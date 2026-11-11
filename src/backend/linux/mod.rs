//! Linux backend: PID/mount/UTS/IPC/network namespaces + `pivot_root` for
//! identity and filesystem isolation (see `rootfs.rs`), pidfd-based process
//! control, and — in later milestones — cgroups v2 resource limits, output
//! capture and seccomp. The building blocks are demonstrated in
//! `examples/linux_*`.

mod rootfs;
mod spawn;

use std::collections::HashMap;
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::unix::io::IntoRawFd as _;
use std::path::{Path, PathBuf};
use std::time::Instant;

use pyo3::exceptions::{PyOSError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use rustix::fd::{AsFd, FromRawFd, OwnedFd};
use rustix::process::{WaitId, WaitidOptions, waitid};

use crate::backend::common::Backend;
use crate::backend::common::copy;
use crate::backend::common::{resolve_cwd, validate_copy_in, validate_copy_out};
use crate::contract::RunSpec;
use crate::contract::status::Status;

use self::spawn::ChildSpec;

/// Where the session workdir lives inside the sandbox.
const CONTAINER_WORKDIR: &str = "/workspace";

/// Placeholder Linux backend; the namespace mechanics land here milestone by
/// milestone (this one: namespaces + pivot_root + basic exec).
pub(crate) struct Linux;

impl Backend for Linux {
    /// `rootfs` (a caller-supplied container root) is planned as a later
    /// milestone: it needs an overlay to keep the caller tree read-only.
    fn validate_new(&self, rootfs: Option<&Path>, _runtimes: &[PathBuf]) -> PyResult<()> {
        if rootfs.is_some() {
            return Err(PyValueError::new_err(
                "rootfs is not supported on Linux yet; use runtimes=[...] to expose \
                 read-only runtime directories instead",
            ));
        }
        Ok(())
    }

    fn exec(
        &self,
        _rootfs: Option<&Path>,
        _runtimes: &[PathBuf],
        mut spec: RunSpec,
        workdir: Option<&Path>,
    ) -> PyResult<Status> {
        validate_copy_in(spec.copy_in.as_ref())?;
        validate_copy_out(spec.copy_out.as_ref())?;
        let copy_out = spec.copy_out.take().filter(|entries| !entries.is_empty());
        let copy_out_limit_bytes = spec.copy_out_limit_bytes;
        let copy_in = spec.copy_in.as_ref().filter(|entries| !entries.is_empty());

        // The sandbox root is a tmpfs built under the session workdir, so a
        // Linux run always needs an active session.
        let Some(workdir) = workdir else {
            return Err(PyRuntimeError::new_err(
                "the Linux sandbox builds its root under the session workdir; run \
                 exec inside `with Sandbox(...)`",
            ));
        };
        if let Some(copy_in) = copy_in {
            copy::provision(workdir, copy_in)
                .map_err(|error| PyOSError::new_err(format!("copy_in failed: {error}")))?;
        }

        let environment = build_environment(spec.envs.as_ref(), workdir)?;
        let cwd = container_cwd(spec.cwd.as_deref(), workdir)?;

        let status = run(&spec, workdir, &environment, &cwd)
            .map_err(|error| os_error("sandbox run failed", error))?;

        // Products are recovered only from a successful run; a collection
        // quota breach outranks the AC verdict.
        let mut status = status;
        if status.status == "AC"
            && let Some(copy_out) = copy_out
        {
            let exceeded = copy::collect(workdir, &copy_out, copy_out_limit_bytes)
                .map_err(|error| PyOSError::new_err(format!("copy_out failed: {error}")))?;
            if exceeded {
                status.status = "OLE".to_string();
                status.signal = 9;
            }
        }
        Ok(status)
    }
}

/// Runs the spec in the sandbox and classifies the outcome.
fn run(
    spec: &RunSpec,
    workdir: &Path,
    environment: &[(String, String)],
    cwd: &str,
) -> io::Result<Status> {
    let stdio = open_stdio(
        spec.stdin_file.as_deref(),
        spec.stdout_file.as_deref(),
        spec.stderr_file.as_deref(),
    )?;

    let child_spec = ChildSpec {
        executable: cstring(&spec.executable)?,
        args: spec
            .args
            .iter()
            .map(|arg| CString::new(arg.as_str()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "argument contains a NUL byte"))?,
        envp: environment
            .iter()
            .map(|(key, value)| CString::new(format!("{key}={value}")))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "environment contains a NUL byte"))?,
        cwd: CString::new(cwd)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "cwd contains a NUL byte"))?,
        workdir: cstring(workdir)?,
        runtimes: vec![], // runtime grants land with the rootfs milestone
        stdio,
    };

    let child = spawn::spawn(child_spec)?;
    let started = Instant::now();

    if let Err(error) = await_handshake(&child.status) {
        reap(&child.pidfd);
        return Err(error);
    }

    let wait = waitid(WaitId::PidFd(child.pidfd.as_fd()), WaitidOptions::EXITED)
        .map_err(|error| io::Error::other(format!("waitid failed: {error}")))?
        .ok_or_else(|| io::Error::other("the sandboxed child never exited"))?;
    let wall_time_used_ms = started.elapsed().as_millis() as u64;

    // Resource accounting (cpu/memory) and the TLE/MLE/OLE verdicts land with
    // the cgroups milestone; this milestone reports AC/RE plus the exit
    // status.
    let (status, exit_code, signal) = if wait.exited() {
        let code = wait.exit_status().unwrap_or(0) as u32;
        (if code == 0 { "AC" } else { "RE" }, code, 0)
    } else {
        let signal = wait.terminating_signal().unwrap_or(0) as i32;
        ("RE", 0, signal)
    };

    Ok(Status {
        cpu_time_used_ms: 0,
        wall_time_used_ms,
        memory_used_bytes: 0,
        status: status.to_string(),
        signal,
        exit_code,
    })
}

/// Opens the redirection files as inheritable fds, in the stdin/stdout/stderr
/// order `ChildSpec::stdio` expects. `None` keeps the parent's stream.
/// Output limits are enforced from the capture milestone on.
fn open_stdio(
    stdin_file: Option<&Path>,
    stdout_file: Option<&Path>,
    stderr_file: Option<&Path>,
) -> io::Result<[Option<OwnedFd>; 3]> {
    let stdin = match stdin_file {
        Some(path) => Some(into_fd(File::open(path)?)),
        None => None,
    };
    let stdout = match stdout_file {
        Some(path) => Some(into_fd(File::create(path)?)),
        None => None,
    };
    let stderr = match stderr_file {
        Some(path) => Some(into_fd(File::create(path)?)),
        None => None,
    };
    Ok([stdin, stdout, stderr])
}

/// Converts a `File` into the plain fd type `ChildSpec` carries.
fn into_fd(file: File) -> OwnedFd {
    // SAFETY: `into_raw_fd` hands over a live fd that `OwnedFd` now owns.
    unsafe { OwnedFd::from_raw_fd(file.into_raw_fd()) }
}

/// Reads the 8-byte handshake (errno + stage): non-zero errno means the run
/// never started. EOF means the child died before reporting; the caller's
/// waitid then observes the death, so treat it as success here.
fn await_handshake(status: &OwnedFd) -> io::Result<()> {
    let mut buf = [0u8; 8];
    let mut read_total = 0;
    while read_total < buf.len() {
        match rustix::io::read(status, &mut buf[read_total..]) {
            Ok(0) => return Ok(()), // child died pre-report; waitid will tell
            Ok(n) => read_total += n,
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
    }
    let errno = i32::from_ne_bytes(buf[..4].try_into().unwrap());
    let stage = u32::from_ne_bytes(buf[4..].try_into().unwrap());
    if errno != 0 {
        let stage = spawn::stage_name(stage);
        return Err(io::Error::other(format!(
            "sandbox init failed at `{stage}`: {} (os error {errno})",
            io::Error::from_raw_os_error(errno)
        )));
    }
    Ok(())
}

fn reap(pidfd: &OwnedFd) {
    let _ = waitid(WaitId::PidFd(pidfd.as_fd()), WaitidOptions::EXITED);
}

fn container_cwd(cwd: Option<&str>, workdir: &Path) -> PyResult<String> {
    let resolved =
        resolve_cwd(cwd, Some(workdir))?.unwrap_or_else(|| workdir.to_path_buf());
    let relative = resolved
        .strip_prefix(workdir)
        .map_err(|_| PyValueError::new_err("cwd escapes the sandbox workdir"))?;
    if relative.as_os_str().is_empty() {
        Ok(CONTAINER_WORKDIR.to_string())
    } else {
        Ok(format!(
            "{}/{}",
            CONTAINER_WORKDIR,
            relative.to_string_lossy()
        ))
    }
}

/// The child environment: the host variables plus `TMPDIR`/`TEMP`/`TMP`
/// pointing into the writable scratch, with caller `envs` last (case
/// sensitive, as POSIX environments are).
fn build_environment(
    overrides: Option<&HashMap<String, String>>,
    workdir: &Path,
) -> PyResult<Vec<(String, String)>> {
    let temp = workdir.join("tmp");
    std::fs::create_dir_all(&temp).map_err(|error| {
        PyOSError::new_err(format!(
            "failed to create the sandbox temp directory {}: {error}",
            temp.display()
        ))
    })?;
    let temp = format!("{CONTAINER_WORKDIR}/tmp");

    let mut variables: Vec<(String, String)> = std::env::vars_os()
        .map(|(key, value)| {
            (
                key.to_string_lossy().into_owned(),
                value.to_string_lossy().into_owned(),
            )
        })
        .collect();
    for name in ["TMPDIR", "TEMP", "TMP"] {
        set_environment(&mut variables, name, temp.clone());
    }

    if let Some(overrides) = overrides {
        for (key, value) in overrides {
            if key.is_empty() || key.contains('=') || key.contains('\0') || value.contains('\0') {
                return Err(PyValueError::new_err(format!(
                    "invalid environment variable {key:?}"
                )));
            }
            set_environment(&mut variables, key, value.clone());
        }
    }
    Ok(variables)
}

fn set_environment(variables: &mut Vec<(String, String)>, key: &str, value: String) {
    if let Some(slot) = variables.iter_mut().find(|(existing, _)| existing == key) {
        *slot = (key.to_string(), value);
    } else {
        variables.push((key.to_string(), value));
    }
}

fn cstring(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))
}

fn os_error(context: &str, error: io::Error) -> PyErr {
    PyOSError::new_err(format!("{context}: {error}"))
}
