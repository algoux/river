//! Linux backend: PID/mount/UTS/IPC/network namespaces + `pivot_root` for
//! identity and filesystem isolation (see `rootfs.rs`), cgroups v2 for
//! resource limits and accounting (see `cgroup.rs`), pidfd-based process
//! control and output capture with kill thresholds (see `capture.rs`).
//! seccomp is a later milestone. The building blocks are demonstrated in
//! `examples/linux_*`.

mod capture;
mod cgroup;
mod rootfs;
mod spawn;

use std::collections::HashMap;
use std::ffi::CString;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use pyo3::exceptions::{PyOSError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use rustix::fd::{AsFd, FromRawFd, OwnedFd};
use rustix::process::{Signal, WaitId, WaitidOptions, pidfd_send_signal, waitid};

use crate::backend::common::Backend;
use crate::backend::common::copy;
use crate::backend::common::{resolve_cwd, validate_copy_in, validate_copy_out};
use crate::contract::RunSpec;
use crate::contract::status::Status;

use self::cgroup::Session;
use self::spawn::ChildSpec;

/// Where the session workdir lives inside the sandbox.
const CONTAINER_WORKDIR: &str = "/workspace";

/// The Linux backend. The cgroup session directory is owned by the sandbox
/// session: `__enter__` creates it, every run gets a child group, `__exit__`
/// kills leftovers and removes the tree.
pub(crate) struct Linux {
    session: Mutex<Option<Session>>,
}

impl Linux {
    pub(crate) fn new() -> Self {
        Linux {
            session: Mutex::new(None),
        }
    }

    /// Best-effort teardown of the current session group.
    fn close_session(&self) {
        let mut guard = self.session.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(session) = guard.take() {
            session.destroy();
        }
    }
}

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

    fn on_enter(
        &self,
        _rootfs: Option<&Path>,
        _runtimes: &[PathBuf],
        _workdir: &Path,
    ) -> PyResult<()> {
        // A new session must not inherit the previous session's limits.
        self.close_session();
        let session = Session::create().map_err(|error| {
            PyOSError::new_err(format!(
                "failed to create the cgroup sandbox session: {error} (the Linux \
                 backend needs root on a cgroups v2 host)"
            ))
        })?;
        let mut guard = self.session.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some(session);
        Ok(())
    }

    fn on_exit(
        &self,
        _rootfs: Option<&Path>,
        _runtimes: &[PathBuf],
        _workdir: &Path,
    ) -> PyResult<()> {
        self.close_session();
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
        let mut session = {
            let mut guard = self.session.lock().unwrap_or_else(|e| e.into_inner());
            guard
                .take()
                .ok_or_else(|| PyRuntimeError::new_err("the sandbox session is not active"))?
        };

        let result = (|| {
            if let Some(copy_in) = copy_in {
                copy::provision(workdir, copy_in)
                    .map_err(|error| PyOSError::new_err(format!("copy_in failed: {error}")))?;
            }

            let environment = build_environment(spec.envs.as_ref(), workdir)?;
            let cwd = container_cwd(spec.cwd.as_deref(), workdir)?;

            run(&spec, workdir, &environment, &cwd, &mut session)
                .map_err(|error| os_error("sandbox run failed", error))
        })();

        // Always put the session back so later runs (and `on_exit`) see it.
        let mut guard = self.session.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some(session);
        drop(guard);

        let mut status = result?;

        // Products are recovered only from a successful run; a collection
        // quota breach outranks the AC verdict.
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
    session: &mut Session,
) -> io::Result<Status> {
    let run_group = session.run_group(spec.cpu_time_limit_ms, spec.memory_limit_bytes)?;
    let raw = match supervise(spec, workdir, environment, cwd, &run_group) {
        Ok(raw) => raw,
        Err(error) => {
            // The group may still hold processes; kill and drop it before
            // propagating.
            run_group.remove();
            return Err(error);
        }
    };
    // The judged process is gone; the PID namespace took its descendants
    // with it, so the group is empty and the counters are final.
    let stats = run_group.stats()?;
    run_group.remove();

    let cpu_time_used_ms = stats.cpu_time_used_us / 1000;
    let memory_used_bytes = stats.memory_used_bytes;
    let (verdict, signal) = classify(
        &raw,
        spec.cpu_time_limit_ms,
        cpu_time_used_ms,
        spec.memory_limit_bytes,
        memory_used_bytes,
        stats.oom_kills,
    );

    Ok(Status {
        cpu_time_used_ms,
        wall_time_used_ms: raw.wall_time_used_ms,
        memory_used_bytes,
        status: verdict.to_string(),
        signal,
        exit_code: raw.exit_code,
    })
}

/// The observed end of the run, before resource-based reclassification.
struct RawOutcome {
    exit_code: u32,
    signal: i32,
    wall_time_used_ms: u64,
    timed_out: bool,
    output_limit_hit: bool,
}

/// Supervises the run: an epoll set holds the pidfd (readable when the
/// child dies) and the limited output pipes, so the loop wakes on real
/// events instead of a timer. The wall clock is the epoll timeout: on
/// expiry the run is killed over the pidfd.
fn supervise(
    spec: &RunSpec,
    workdir: &Path,
    environment: &[(String, String)],
    cwd: &str,
    run_group: &cgroup::RunGroup,
) -> io::Result<RawOutcome> {
    use rustix::event::epoll::{self, CreateFlags, EventData, EventFlags, EventVec};

    const EVENT_PIDFD: u64 = 2;

    let (mut capture, stdio) = capture::Capture::new(
        spec.stdin_file.as_deref(),
        spec.stdout_file.as_deref(),
        spec.stderr_file.as_deref(),
        spec.stdout_limit_bytes,
        spec.stderr_limit_bytes,
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
        cgroup: Some(cgroup_fd(run_group.path())?),
    };

    let child = spawn::spawn(child_spec)?;
    let started = Instant::now();

    if let Err(error) = await_handshake(&child.status) {
        let _ = pidfd_send_signal(child.pidfd.as_fd(), Signal::Kill);
        reap(&child.pidfd);
        return Err(error);
    }

    let poller = epoll::create(CreateFlags::CLOEXEC)?;
    for index in 0..2 {
        if let Some(reader) = capture.reader(index) {
            epoll::add(
                &poller,
                reader,
                EventData::new_u64(index as u64),
                EventFlags::IN,
            )?;
        }
    }
    epoll::add(
        &poller,
        child.pidfd.as_fd(),
        EventData::new_u64(EVENT_PIDFD),
        EventFlags::IN,
    )?;

    let deadline = spec
        .wall_time_limit_ms
        .map(|limit| started + Duration::from_millis(limit));
    let mut killed = false;
    let mut timed_out = false;
    let mut output_limit_hit = false;
    let mut events = EventVec::with_capacity(3);

    let wait = 'run: loop {
        let timeout = match deadline {
            // Block until the wall deadline; the +1ms rounds the sub-ms
            // remainder up so we never wake a hair early and miss the kill.
            Some(deadline) => (deadline.saturating_duration_since(Instant::now())
                + Duration::from_millis(1))
            .as_millis()
            .min(i32::MAX as u128) as i32,
            None => -1,
        };
        epoll::wait(&poller, &mut events, timeout)?;

        for event in &events {
            if event.data.u64() == EVENT_PIDFD {
                if let Ok(Some(wait)) = waitid(
                    WaitId::PidFd(child.pidfd.as_fd()),
                    WaitidOptions::NOHANG | WaitidOptions::EXITED,
                ) {
                    break 'run wait;
                }
                continue;
            }
            let index = event.data.u64() as usize;
            if capture.drain_one(index) && !killed {
                output_limit_hit = true;
                killed = true;
                let _ = pidfd_send_signal(child.pidfd.as_fd(), Signal::Kill);
            }
            if capture.at_eof(index) {
                // Level-triggered EOF would wake the loop forever.
                if let Some(reader) = capture.reader(index) {
                    let _ = epoll::delete(&poller, reader);
                }
            }
        }

        if !killed
            && let Some(deadline) = deadline
            && Instant::now() >= deadline
        {
            timed_out = true;
            killed = true;
            let _ = pidfd_send_signal(child.pidfd.as_fd(), Signal::Kill);
        }
    };
    // Final drain: the last chunk between the exit and this point still
    // counts against the limits.
    if capture.poll() {
        output_limit_hit = true;
    }
    let wall_time_used_ms = started.elapsed().as_millis() as u64;

    let (exit_code, signal) = if wait.exited() {
        (wait.exit_status().unwrap_or(0) as u32, 0)
    } else {
        (0, wait.terminating_signal().unwrap_or(0) as i32)
    };

    Ok(RawOutcome {
        exit_code,
        signal,
        wall_time_used_ms,
        timed_out,
        output_limit_hit: output_limit_hit || capture.exceeded(),
    })
}

/// Maps one finished run onto the frozen `Status` verdicts. Evidence:
/// the wall deadline is a direct observation; a cpu.max throttle makes the
/// run hit the wall clock (or post-run usage pass the limit); a memory.max
/// breach kills via the memory cgroup (`oom_kill` event, SIGKILL); output
/// overflow is a direct observation. Same priority order as the Windows
/// backend: OLE > MLE > TLE > AC/RE.
fn classify(
    raw: &RawOutcome,
    cpu_limit_ms: Option<u64>,
    cpu_used_ms: u64,
    memory_limit_bytes: Option<u64>,
    peak_memory_bytes: u64,
    oom_kills: u64,
) -> (&'static str, i32) {
    let abnormal = raw.timed_out || raw.signal != 0 || raw.exit_code != 0;
    let cpu_over = cpu_limit_ms.is_some_and(|limit| cpu_used_ms > limit);
    let memory_hit = oom_kills > 0
        || memory_limit_bytes.is_some_and(|limit| peak_memory_bytes >= limit);

    if raw.output_limit_hit {
        ("OLE", 9)
    } else if abnormal && memory_hit {
        ("MLE", 9)
    } else if raw.timed_out || cpu_over {
        ("TLE", 9)
    } else if raw.exit_code == 0 && raw.signal == 0 {
        ("AC", 0)
    } else {
        ("RE", raw.signal)
    }
}

/// Opens the run cgroup directory as the O_PATH fd clone3 wants.
fn cgroup_fd(path: &Path) -> io::Result<OwnedFd> {
    let c_path = cstring(path)?;
    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_PATH | libc::O_CLOEXEC | libc::O_DIRECTORY,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fresh fd from open, owned from here on.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
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
    let resolved = resolve_cwd(cwd, Some(workdir))?.unwrap_or_else(|| workdir.to_path_buf());
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
