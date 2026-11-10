//! Windows backend: AppContainer + Job Object (see `examples/windows_*`).
//!
//! A sandbox session with a non-empty `runtimes` list owns an AppContainer
//! profile for the whole `with` block: the profile is created and the runtimes
//! are granted on `__enter__`, the runs reuse it, and `__exit__` revokes the
//! grants and deletes it. Every run is placed in a Job Object that enforces
//! the CPU and memory limits and provides the CPU-time and peak-memory
//! accounting.
//!
//! Scope of this basic implementation:
//! - CPU time limit (native job time limit, user-mode) and measurement
//!   (user + kernel of the whole job);
//! - peak memory limit / measurement (Job Object, whole-tree commit);
//! - wall-clock limit / measurement;
//! - read-only `runtimes` grants to the target AppContainer identity;
//! - `copy_in` provisioning into the session workdir (host files and
//!   directories; read-only for the AppContainer identity);
//! - `copy_out` recovery from the session workdir after a successful run
//!   (host files and directories; links skipped; a total-byte cap that
//!   reports `OLE` when breached);
//! - `stdin_file` / `stdout_file` / `stderr_file` redirection and the
//!   `stdout_limit_bytes` / `stderr_limit_bytes` kill thresholds (`OLE`).
//!
//! Without any redirection the child inherits the caller's standard streams.

mod acl;
mod copy;
mod job;
mod profile;
mod spawn;
mod stdio;

use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use pyo3::exceptions::{PyOSError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use windows_sys::Win32::Foundation::ERROR_NOT_ENOUGH_QUOTA;
use windows_sys::Win32::Security::PSID;

use crate::backend::common::Backend;
use crate::contract::RunSpec;
use crate::contract::status::Status;

use self::job::{Job, JobLimits, KILL_EXIT_CODE};
use self::profile::AppContainer;
use self::spawn::{SpawnConfig, WaitResult, env_block, spawn};
use self::stdio::StdioSet;

/// Environment variables kept for an AppContainer child. Everything else
/// from the host environment is dropped (the AppContainer's visible surface
/// is already restricted to the granted paths).
const SANDBOX_ENV_WHITELIST: &[&str] = &[
    "SystemRoot",
    "SystemDrive",
    "windir",
    "ComSpec",
    "PATH",
    "PATHEXT",
    "LOCALAPPDATA",
    "APPDATA",
    "ProgramData",
    "ProgramFiles",
    "ProgramFiles(x86)",
    "CommonProgramFiles",
    "CommonProgramFiles(x86)",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
    "PROCESSOR_IDENTIFIER",
    "OS",
    "USERPROFILE",
    "PUBLIC",
    "TEMP",
    "TMP",
];

/// Sequence for per-sandbox AppContainer profile names.
static PROFILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// The Windows backend. The AppContainer profile is owned by the session:
/// `__enter__` creates it and grants the runtimes plus the session workdir,
/// `__exit__` revokes the grants and deletes it. A run with a non-empty
/// `runtimes` list therefore has to happen inside the `with` block.
pub(crate) struct Windows {
    container: Mutex<Option<AppContainer>>,
}

impl Windows {
    pub(crate) fn new() -> Self {
        Windows {
            container: Mutex::new(None),
        }
    }

    /// Best-effort teardown: revoke the grants and delete the profile.
    fn close_container(&self) {
        let mut guard = self.container.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(mut container) = guard.take() {
            let _ = container.close();
        }
    }
}

impl Drop for Windows {
    fn drop(&mut self) {
        self.close_container();
    }
}

impl Backend for Windows {
    /// Windows has no pivot-root equivalent, so a private root filesystem
    /// cannot be provided: expose read-only runtime directories instead.
    fn validate_new(&self, rootfs: Option<&Path>, _runtimes: &[PathBuf]) -> PyResult<()> {
        if rootfs.is_some() {
            return Err(PyValueError::new_err(
                "rootfs is not supported on Windows; use runtimes=[...] to expose \
                 read-only runtime directories instead",
            ));
        }
        Ok(())
    }

    fn on_enter(
        &self,
        _rootfs: Option<&Path>,
        runtimes: &[PathBuf],
        workdir: &Path,
    ) -> PyResult<()> {
        // A new session must not inherit the previous session's AppContainer
        // grants or its scratch directory.
        self.close_container();
        if runtimes.is_empty() {
            return Ok(());
        }

        // Profile creation (and therefore the read-only runtimes grants) is
        // part of entering the session, not of the first run: a bad runtime
        // path fails `with Sandbox(...)` instead of the first `exec`, and an
        // `exec` outside the block has no profile to use.
        let container = AppContainer::create(&next_profile_name(), runtimes, Some(workdir))
            .map_err(|error| {
                PyOSError::new_err(format!(
                    "failed to create the AppContainer sandbox: {error}"
                ))
            })?;
        let mut guard = self.container.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some(container);
        Ok(())
    }

    fn on_exit(
        &self,
        _rootfs: Option<&Path>,
        _runtimes: &[PathBuf],
        _workdir: &Path,
    ) -> PyResult<()> {
        self.close_container();
        Ok(())
    }

    fn exec(
        &self,
        _rootfs: Option<&Path>,
        runtimes: &[PathBuf],
        mut spec: RunSpec,
        workdir: Option<&Path>,
    ) -> PyResult<Status> {
        validate_copy_in(spec.copy_in.as_ref())?;
        validate_copy_out(spec.copy_out.as_ref())?;
        let copy_out = spec.copy_out.take().filter(|entries| !entries.is_empty());
        let copy_out_limit_bytes = spec.copy_out_limit_bytes;
        let copy_in = spec.copy_in.as_ref().filter(|entries| !entries.is_empty());
        if copy_in.is_some() && workdir.is_none() {
            return Err(PyRuntimeError::new_err(
                "copy_in requires an active sandbox session; run exec inside \
                 `with Sandbox(...)`",
            ));
        }
        if copy_out.is_some() && workdir.is_none() {
            return Err(PyRuntimeError::new_err(
                "copy_out requires an active sandbox session; run exec inside \
                 `with Sandbox(...)`",
            ));
        }

        let sandboxed = !runtimes.is_empty();

        // The profile belongs to the session, so a run with runtimes must
        // happen inside `with Sandbox(runtimes=[...])`. The guard keeps the
        // SID (and therefore the grants) alive for the whole run.
        let container_guard = if sandboxed {
            let guard = self.container.lock().unwrap_or_else(|e| e.into_inner());
            if guard.is_none() {
                return Err(PyRuntimeError::new_err(
                    "the AppContainer sandbox is not active; run exec inside \
                     `with Sandbox(runtimes=[...])`",
                ));
            }
            Some(guard)
        } else {
            None
        };
        let appcontainer_sid = container_guard
            .as_ref()
            .and_then(|guard| guard.as_ref())
            .map(AppContainer::sid);

        // Provision before resolving `cwd`: a `cwd` may point into the tree
        // that `copy_in` just created.
        if let (Some(workdir), Some(copy_in)) = (workdir, copy_in) {
            copy::provision(workdir, copy_in, appcontainer_sid)
                .map_err(|error| PyOSError::new_err(format!("copy_in failed: {error}")))?;
        }

        let environment = build_environment(spec.envs.as_ref(), workdir, sandboxed)?;
        let cwd = resolve_cwd(spec.cwd.as_deref(), workdir)?;

        let mut status = run(spec, cwd.as_deref(), &environment, appcontainer_sid)
            .map_err(|error| os_error("sandbox run failed", error))?;

        // Products are recovered only from a successful run. A collection
        // quota breach is a direct observation, so it outranks the AC verdict.
        if status.status == "AC"
            && let (Some(workdir), Some(copy_out)) = (workdir, copy_out)
        {
            let exceeded = copy::collect(workdir, &copy_out, copy_out_limit_bytes)
                .map_err(|error| PyOSError::new_err(format!("copy_out failed: {error}")))?;
            if exceeded {
                status.status = "OLE".to_string();
                status.signal = 9;
            }
        }

        drop(container_guard);
        Ok(status)
    }
}

fn run(
    spec: RunSpec,
    cwd: Option<&Path>,
    environment: &[(String, String)],
    appcontainer_sid: Option<PSID>,
) -> io::Result<Status> {
    let environment_block = env_block(environment);

    let job = Job::new(&JobLimits {
        cpu_time_limit_ms: spec.cpu_time_limit_ms,
        memory_limit_bytes: spec.memory_limit_bytes,
    })?;

    let stdio = StdioSet::new(
        spec.stdin_file.as_deref(),
        spec.stdout_file.as_deref(),
        spec.stderr_file.as_deref(),
        spec.stdout_limit_bytes,
        spec.stderr_limit_bytes,
    )?;

    let child = spawn(
        SpawnConfig {
            executable: &spec.executable,
            args: &spec.args,
            cwd,
            env_block: &environment_block,
            appcontainer_sid,
            job: &job,
        },
        &stdio,
    )
    .map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("failed to start {}: {error}", spec.executable.display()),
        )
    })?;

    let started = Instant::now();
    child.resume()?;

    let wait_timeout = spec
        .wall_time_limit_ms
        .map(|limit| limit.min(u32::MAX as u64 - 1) as u32);
    let first_wait = child.wait_with_overflow(stdio.overflow_handle(), wait_timeout)?;

    let mut output_limit_hit = matches!(first_wait, WaitResult::OutputOverflow);
    let timed_out = matches!(first_wait, WaitResult::TimedOut);
    let exit_code = match first_wait {
        WaitResult::Exited(code) => code,
        WaitResult::TimedOut | WaitResult::OutputOverflow => {
            job.terminate(KILL_EXIT_CODE)?;
            child
                .wait(None)?
                .ok_or_else(|| io::Error::other("the terminated child process never exited"))?
        }
    };
    let wall_time_used_ms = started.elapsed().as_millis() as u64;

    // The judged process is gone; no descendant may keep running after it.
    // This also finalizes the job accounting before it is read (the handle
    // is closed at the end of this scope, which would kill them anyway).
    let _ = job.terminate(KILL_EXIT_CODE);

    // Drains the output pipes after the tree is gone. A fast writer can pass
    // the limit between the last wait and this join, so the totals get the
    // last word on the OLE verdict.
    let (stdout_total, stderr_total) = stdio.finish()?;
    output_limit_hit |= spec
        .stdout_limit_bytes
        .is_some_and(|limit| stdout_total > limit)
        || spec
            .stderr_limit_bytes
            .is_some_and(|limit| stderr_total > limit);

    let cpu_time_used_ms = job.cpu_time_ms()?;
    let memory_used_bytes = job.peak_job_memory_used()?;

    let (status, signal) = classify(
        exit_code,
        timed_out,
        spec.cpu_time_limit_ms,
        cpu_time_used_ms,
        spec.memory_limit_bytes,
        memory_used_bytes,
        output_limit_hit,
    );

    Ok(Status {
        cpu_time_used_ms,
        wall_time_used_ms,
        memory_used_bytes,
        status: status.to_string(),
        signal,
        exit_code,
    })
}

/// `STATUS_QUOTA_EXCEEDED`: the NTSTATUS the job-time limit uses when it
/// terminates the tree (observed on current Windows builds).
const STATUS_QUOTA_EXCEEDED: u32 = 0xC000_0044;

/// Maps one finished run onto the frozen `Status` verdicts.
///
/// Native job limits provide the evidence: a job-time kill terminates with
/// `ERROR_NOT_ENOUGH_QUOTA` / `STATUS_QUOTA_EXCEEDED`, the measured total CPU
/// can also exceed the limit before the system's periodic check fires, and a
/// memory cap makes allocations fail (so an abnormal end with the peak at the
/// cap is the memory-limit signature). Output overflow is a direct observation
/// by the reader threads, so it outranks the inferred kill causes.
fn classify(
    exit_code: u32,
    timed_out: bool,
    cpu_limit_ms: Option<u64>,
    cpu_used_ms: u64,
    memory_limit_bytes: Option<u64>,
    peak_memory_bytes: u64,
    output_limit_hit: bool,
) -> (&'static str, i32) {
    let abnormal = timed_out || exit_code != 0;
    let cpu_over = cpu_limit_ms.is_some_and(|limit| cpu_used_ms > limit);
    let cpu_killed = cpu_limit_ms.is_some()
        && matches!(exit_code, ERROR_NOT_ENOUGH_QUOTA | STATUS_QUOTA_EXCEEDED);
    let memory_hit = memory_limit_bytes
        .is_some_and(|limit| peak_memory_bytes.saturating_add(memory_slack(limit)) >= limit);

    if output_limit_hit {
        ("OLE", 9)
    } else if abnormal && memory_hit {
        ("MLE", 9)
    } else if timed_out || cpu_over || cpu_killed {
        ("TLE", 9)
    } else if exit_code == 0 {
        ("AC", 0)
    } else {
        ("RE", 0)
    }
}

/// The memory cap makes oversized allocations fail instead of succeeding, so
/// the observed peak can land below the cap by roughly the refused
/// allocation. One MiB or 1/8 of the cap covers that gap without crediting a
/// run that stayed well clear.
fn memory_slack(limit_bytes: u64) -> u64 {
    (limit_bytes / 8).max(1024 * 1024)
}

/// Validates the `copy_out` sources: relative to the workdir. Destinations
/// are host paths and are not restricted.
fn validate_copy_out(entries: Option<&HashMap<PathBuf, PathBuf>>) -> PyResult<()> {
    let Some(entries) = entries else {
        return Ok(());
    };
    for source in entries.keys() {
        validate_relative_path("copy_out", source)?;
    }
    Ok(())
}

/// Validates the `copy_in` destinations: relative to the workdir, unique, and
/// not nested inside one another.
fn validate_copy_in(entries: Option<&HashMap<PathBuf, PathBuf>>) -> PyResult<()> {
    let Some(entries) = entries else {
        return Ok(());
    };
    let mut destinations: HashSet<&Path> = HashSet::with_capacity(entries.len());
    for destination in entries.values() {
        validate_relative_path("copy_in", destination)?;
        if !destinations.insert(destination.as_path()) {
            return Err(PyValueError::new_err(format!(
                "copy_in maps more than one source to the same destination: {}",
                destination.display()
            )));
        }
    }
    for &destination in &destinations {
        for ancestor in destination.ancestors().skip(1) {
            if ancestor.as_os_str().is_empty() {
                break;
            }
            if destinations.contains(ancestor) {
                return Err(PyValueError::new_err(format!(
                    "copy_in destinations overlap: {} is inside {}",
                    destination.display(),
                    ancestor.display()
                )));
            }
        }
    }
    Ok(())
}

/// `cwd` is relative to the session scratch directory; inside a session the
/// default is that directory itself. Outside a `with` block there is no
/// scratch directory and the child keeps the caller's current directory.
fn resolve_cwd(cwd: Option<&str>, workdir: Option<&Path>) -> PyResult<Option<PathBuf>> {
    let Some(cwd) = cwd else {
        return Ok(workdir.map(Path::to_path_buf));
    };
    validate_relative_path("cwd", Path::new(cwd))?;

    let base = match workdir {
        Some(workdir) => workdir.to_path_buf(),
        None => std::env::current_dir().map_err(|error| {
            PyOSError::new_err(format!("failed to resolve the current directory: {error}"))
        })?,
    };
    let path = base.join(cwd);
    if !path.is_dir() {
        return Err(PyValueError::new_err(format!(
            "cwd {cwd:?} is not a directory inside the sandbox: {}",
            path.display()
        )));
    }
    Ok(Some(path))
}

/// Accepts only plain relative components (no root, drive prefix, `.` or
/// `..`), so `cwd` and `copy_in` destinations cannot escape the workdir.
fn validate_relative_path(kind: &str, path: &Path) -> PyResult<()> {
    if path.as_os_str().is_empty()
        || path.has_root()
        || path.to_string_lossy().contains(':')
        || !path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(PyValueError::new_err(format!(
            "invalid {kind} {}: must be a relative path inside the sandbox workdir",
            path.display()
        )));
    }
    Ok(())
}

/// The child environment: all host variables for a plain run, a whitelist
/// for an AppContainer run. The session `TEMP`/`TMP` point into the writable
/// scratch directory; caller `envs` override either base.
fn build_environment(
    overrides: Option<&HashMap<String, String>>,
    workdir: Option<&Path>,
    sandboxed: bool,
) -> PyResult<Vec<(String, String)>> {
    let mut variables: Vec<(String, String)> = if sandboxed {
        SANDBOX_ENV_WHITELIST
            .iter()
            .filter_map(|name| {
                std::env::var(name)
                    .ok()
                    .map(|value| ((*name).to_string(), value))
            })
            .collect()
    } else {
        std::env::vars_os()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.to_string_lossy().into_owned(),
                )
            })
            .collect()
    };

    // An AppContainer run gets a fixed system PATH; caller `envs` can
    // override it. Copying the host PATH would advertise directories the
    // package cannot actually open.
    if sandboxed && let Ok(root) = std::env::var("SystemRoot") {
        set_environment(&mut variables, "PATH", format!(r"{root}\system32;{root}"));
    }

    if sandboxed && let Some(workdir) = workdir {
        let temp = workdir.join("tmp");
        std::fs::create_dir_all(&temp).map_err(|error| {
            PyOSError::new_err(format!(
                "failed to create the sandbox temp directory {}: {error}",
                temp.display()
            ))
        })?;
        let temp = temp.display().to_string();
        set_environment(&mut variables, "TEMP", temp.clone());
        set_environment(&mut variables, "TMP", temp);
    }

    if let Some(overrides) = overrides {
        for (key, value) in overrides {
            validate_environment_entry(key, value)?;
            set_environment(&mut variables, key, value.clone());
        }
    }

    Ok(variables)
}

fn validate_environment_entry(key: &str, value: &str) -> PyResult<()> {
    if key.is_empty() || key.contains('=') || key.contains('\0') || value.contains('\0') {
        return Err(PyValueError::new_err(format!(
            "invalid environment variable {key:?}"
        )));
    }
    Ok(())
}

fn set_environment(variables: &mut Vec<(String, String)>, key: &str, value: String) {
    if let Some(slot) = variables
        .iter_mut()
        .find(|(existing, _)| existing.eq_ignore_ascii_case(key))
    {
        *slot = (key.to_string(), value);
    } else {
        variables.push((key.to_string(), value));
    }
}

fn next_profile_name() -> String {
    let sequence = PROFILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("river.sandbox.{}.{sequence}", std::process::id())
}

fn os_error(context: &str, error: io::Error) -> PyErr {
    PyOSError::new_err(format!("{context}: {error}"))
}
