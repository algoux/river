use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

use pyo3::prelude::*;
use pyo3::types::PyAny;

use crate::backend::windows::acl;
use crate::backend::windows::job::{Job, JobLimits, physical_memory_bytes};
use crate::backend::windows::monitor::monitor;
use crate::backend::windows::profile;
use crate::backend::windows::spawn::{
    SpawnProfile, env_block, spawn_bare, with_silent_crash_dialog,
};
use crate::backend::windows::stdio::{StdinSource, StdioCeilings, StdioSet};
use crate::backend::windows::workdir::{WorkDir, sweep_stale_workdirs};
use crate::contract::status::Status;
use crate::contract::verdict::{KillOrigin, RunEvidence, classify};
use crate::contract::{RunSpec, SafetyCeilings, parse_copy_in, parse_copy_out, validate};

/// Windows sandbox.
///
/// The sandbox filesystem model on Windows:
/// - a fresh private writable working directory per `run` (auto-created,
///   auto-deleted when the context manager block exits);
/// - each path in `runtimes` exposed read-only (+execute) via ACL grants;
/// - `copy_in` files provisioned into the working directory (read-only for
///   the program by default);
/// - everything else on the host is invisible to the sandboxed process.
///
/// `rootfs` is not supported on Windows (Windows processes always resolve
/// system DLLs from the real `System32`): passing it raises `ValueError`.
/// See `river.capabilities()` for the programmatic capability matrix.
///
/// Concurrency: the class is `frozen` — it holds no mutable state
/// (only the configured `runtimes` and the safety ceilings), and every run
/// keeps all of its state in locals. `run()` may therefore be called
/// concurrently from several Python threads on the same `Sandbox`; per-run
/// resources (job, working directory, stdio) are independent.
#[pyclass(module = "river", frozen)]
pub struct Sandbox {
    pub rootfs: Option<PathBuf>,
    pub runtimes: Vec<PathBuf>,
    /// Internal safety ceilings (mechanism guarantees that stay in place
    /// when the caller passes `None` limits). Configurable so a deployment
    /// can tighten the defaults; never disableable.
    pub(crate) ceilings: SafetyCeilings,
}

#[pymethods]
impl Sandbox {
    #[new]
    #[pyo3(signature = (rootfs=None, runtimes=None, max_wall_secs=None, max_processes=None))]
    #[pyo3(text_signature = "(rootfs=None, runtimes=None, max_wall_secs=None, max_processes=None)")]
    fn new(
        rootfs: Option<PathBuf>,
        runtimes: Option<Vec<PathBuf>>,
        max_wall_secs: Option<u64>,
        max_processes: Option<u32>,
    ) -> PyResult<Self> {
        if rootfs.is_some() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "rootfs is not supported on Windows; use runtimes=[...] to expose \
                 read-only runtime directories instead (check river.capabilities())",
            ));
        }
        let mut ceilings = SafetyCeilings::default();
        // "Tighten only": a caller value can lower a ceiling, never raise it
        // (the mechanism guarantee must not be disableable). Zero is rejected
        // instead of silently becoming 1s/1 process.
        if let Some(secs) = max_wall_secs {
            if secs == 0 {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "max_wall_secs must be >= 1",
                ));
            }
            ceilings.wall_limit = Duration::from_secs(secs.min(ceilings.wall_limit.as_secs()));
        }
        if let Some(n) = max_processes {
            if n == 0 {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "max_processes must be >= 1",
                ));
            }
            ceilings.max_processes = n.min(ceilings.max_processes);
        }
        Ok(Self {
            rootfs: None,
            runtimes: runtimes.unwrap_or_default(),
            ceilings,
        })
    }

    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        // Defensive net: sweep dirs abandoned by a *different*, hard-killed
        // judger process. Cheap after the first call (one atomic load).
        sweep_stale_workdirs();
        slf
    }

    /// Exit protocol: everything a `run` leaves behind is owned by
    /// per-run RAII guards — the `Job` (KILL_ON_JOB_CLOSE kills any still
    /// alive processes), the `WorkDir` (removed on drop, reparse-safe), and
    /// the stdio handles — so a normal block exit has nothing left to do.
    /// Always returns `false` (never suppresses block exceptions).
    fn __exit__(
        &self,
        _exc_type: &Bound<'_, PyAny>,
        _exc_value: &Bound<'_, PyAny>,
        _traceback: &Bound<'_, PyAny>,
    ) -> bool {
        sweep_stale_workdirs();
        false
    }

    /// Run an untrusted executable inside the sandbox and collect its status.
    ///
    /// Coordinate systems: `executable` is a host path; `cwd` and `copy_in`
    /// keys are relative to the per-run private working directory.
    ///
    /// Limits: `None` means no caller-imposed limit (internal safety ceilings
    /// still apply). `wall_time_limit_ms` defaults to `2 * time_limit_ms +
    /// 1000` when only a CPU time limit is given.
    ///
    /// `stdin` / `stdin_file` are mutually exclusive. `*_file` output
    /// parameters receive the full captured stream (host paths); the returned
    /// `Status` still carries truncated copies plus truncation flags.
    #[pyo3(signature = (
        executable,
        args = vec![],
        cwd = None,
        env = None,
        time_limit_ms = None,
        wall_time_limit_ms = None,
        memory_limit_kb = None,
        stdin = None,
        stdin_file = None,
        copy_in = None,
        copy_out = None,
        copy_out_limit_kb = None,
        stdout_limit_kb = None,
        stderr_limit_kb = None,
        stdout_file = None,
        stderr_file = None,
    ))]
    #[pyo3(
        text_signature = "(executable, args=[], cwd=None, env=None, time_limit_ms=None, wall_time_limit_ms=None, memory_limit_kb=None, stdin=None, stdin_file=None, copy_in=None, copy_out=None, copy_out_limit_kb=None, stdout_limit_kb=None, stderr_limit_kb=None, stdout_file=None, stderr_file=None)"
    )]
    // The signature mirrors the frozen Python contract (one parameter per
    // run() keyword); collapsing it into a struct would hide that mapping.
    #[allow(clippy::too_many_arguments)]
    fn run(
        &self,
        executable: PathBuf,
        args: Vec<String>,
        cwd: Option<String>,
        env: Option<HashMap<String, String>>,
        time_limit_ms: Option<u64>,
        wall_time_limit_ms: Option<u64>,
        memory_limit_kb: Option<u64>,
        stdin: Option<Vec<u8>>,
        stdin_file: Option<PathBuf>,
        copy_in: Option<HashMap<String, Py<PyAny>>>,
        copy_out: Option<HashMap<String, PathBuf>>,
        copy_out_limit_kb: Option<u64>,
        stdout_limit_kb: Option<u64>,
        stderr_limit_kb: Option<u64>,
        stdout_file: Option<PathBuf>,
        stderr_file: Option<PathBuf>,
        py: Python<'_>,
    ) -> PyResult<Status> {
        let spec = RunSpec {
            executable,
            args,
            cwd,
            env,
            time_limit_ms,
            wall_time_limit_ms,
            memory_limit_kb,
            stdin,
            stdin_file,
            copy_in: match &copy_in {
                Some(map) => Some(parse_copy_in(map, py)?),
                None => None,
            },
            copy_out: match &copy_out {
                Some(map) => Some(parse_copy_out(map)?),
                None => None,
            },
            copy_out_limit_bytes: copy_out_limit_kb.map(|kb| kb.saturating_mul(1024)),
            stdout_limit_kb,
            stderr_limit_kb,
            stdout_file,
            stderr_file,
        };
        validate(&spec)?;

        // --- translate the frozen contract into backend primitives --------
        let stdin_src = match (&spec.stdin, &spec.stdin_file) {
            (Some(bytes), _) => StdinSource::Bytes(bytes.clone()),
            (None, Some(path)) => StdinSource::File(path.clone()),
            _ => StdinSource::Null,
        };
        let limits = JobLimits {
            memory_limit_bytes: spec.memory_limit_kb.map(|kb| kb.saturating_mul(1024)),
            max_processes: self.ceilings.max_processes,
        };
        // Wall limit: user value, the 2x+1s default for CPU-limited runs, or
        // the configured safety ceiling for "unlimited" runs.
        let wall_limit = spec
            .effective_wall_time_limit_ms()
            .map(Duration::from_millis)
            .unwrap_or(self.ceilings.wall_limit);
        // Effective limits the job enforces (user limit or safety ceiling);
        // the verdict compares measurements against these (contract-layer
        // evidence).
        let memory_limit_bytes = limits
            .memory_limit_bytes
            .unwrap_or_else(physical_memory_bytes);
        let cpu_time_limit_ms = spec.time_limit_ms;
        let stdout_limit = spec.stdout_limit_kb.map(|kb| kb * 1024);
        let stderr_limit = spec.stderr_limit_kb.map(|kb| kb * 1024);
        let exe = spec.executable.clone();
        let args = spec.args.clone();
        let (stdout_file, stderr_file) = (spec.stdout_file.clone(), spec.stderr_file.clone());
        let copy_in = spec.copy_in.clone();
        let copy_out = spec.copy_out.clone();
        let copy_out_limit_bytes = spec.copy_out_limit_bytes;
        let cwd_rel = spec.cwd.clone();
        let env_map = spec.env.clone().unwrap_or_default();
        let runtimes = self.runtimes.clone();
        let stdio_ceilings = StdioCeilings {
            capture_limit_bytes: self.ceilings.capture_limit_bytes,
            sink_limit_bytes: self.ceilings.file_sink_limit_bytes,
        };

        // Blocking pipeline with the GIL released.
        let result = py.detach(move || -> io::Result<_> {
            // Per-run working directory: the only writable place the program
            // sees. `WorkDir` removes itself on drop (also on error paths).
            let workdir = WorkDir::create()?;

            // AppContainer identity + ACL grants. The child adopts the
            // AppContainer at spawn time; its visible filesystem is exactly
            // the granted surface (cwd rw, runtimes ro, system DLLs default).
            //
            // The profile comes from a fixed slot pool: the lease wipes the
            // slot's `%LOCALAPPDATA%\Packages\<profile>\AC` before the run and
            // again on release, so no file survives between runs (that folder
            // is fully writable by the sandboxed identity).
            let slot = profile::acquire()?;
            let appcontainer = slot.app()?;
            let sid = appcontainer.sid();
            acl::grant_rw(workdir.path(), sid)?;
            // `copy_in` first inherits the cwd's read/write ACE, then gets an
            // explicit deny-write ACE: the READONLY attribute alone was
            // bypassable with SetFileAttributes/chmod (verified).
            let provisioned = match &copy_in {
                Some(files) => workdir.provision(files)?,
                None => Vec::new(),
            };
            for entry in &provisioned {
                acl::protect_read_only(&entry.path, sid, entry.is_dir)?;
            }
            for rt in &runtimes {
                acl::grant_ro(rt, sid)?;
            }

            // Whitelisted environment: base + caller overrides (incremental
            // merge). TEMP/TMP point into the private cwd. LOCALAPPDATA is
            // REQUIRED for an AppContainer spawn: without it CreateProcessW
            // fails with ERROR_ENVVAR_NOT_FOUND (203). PATH is a fixed system
            // PATH: without it `cmd /c whoami`, batch wrappers and most
            // runtimes cannot find their own tools (the Linux backend has
            // always provided PATH).
            let tmp_dir = workdir.path().join("tmp");
            std::fs::create_dir(&tmp_dir)?;
            let system_root =
                std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
            let mut env_vars: Vec<(String, String)> = vec![
                ("SystemRoot".to_string(), system_root.clone()),
                (
                    "PATH".to_string(),
                    format!(r"{system_root}\system32;{system_root}"),
                ),
                (
                    "LOCALAPPDATA".to_string(),
                    std::env::var("LOCALAPPDATA").unwrap_or_default(),
                ),
                ("TEMP".to_string(), tmp_dir.display().to_string()),
                ("TMP".to_string(), tmp_dir.display().to_string()),
            ];
            for (k, v) in &env_map {
                env_vars.push((k.clone(), v.clone()));
            }
            let profile = SpawnProfile::sandboxed(sid, env_block(&env_vars));

            // The process starts inside the working directory; an explicit
            // `cwd` (already validated as workdir-relative by the contract)
            // must exist — failing loudly beats silently relocating the run
            // to the workdir root.
            let cwd_path = match &cwd_rel {
                Some(rel) => {
                    let p = workdir.path().join(rel);
                    if p.is_dir() {
                        Some(p)
                    } else {
                        return Err(io::Error::new(
                            io::ErrorKind::NotFound,
                            format!("cwd {rel:?} does not exist in the sandbox working directory"),
                        ));
                    }
                }
                None => Some(workdir.path().to_path_buf()),
            };
            let job = Job::new(&limits)?;
            let mut set = StdioSet::new(
                stdin_src,
                stdout_limit,
                stderr_limit,
                stdout_file,
                stderr_file,
                stdio_ceilings,
            )?;
            // The child inherits the judger's error mode: suppress the
            // Windows "serious problem" crash dialog for sandboxed
            // programs (see `with_silent_crash_dialog`).
            let child = with_silent_crash_dialog(|| {
                spawn_bare(
                    &exe,
                    &args,
                    &job,
                    &mut set,
                    cwd_path.as_deref(),
                    Some(&profile),
                )
            })?;
            // The reader threads fire the overflow event past an output
            // kill threshold; the monitor waits on it alongside the process
            // and reaps the job (verdict OLE) instead of waiting for exit.
            let outcome = monitor(
                &child,
                &job,
                Some(wall_limit),
                Some(set.overflow_event_handle()),
                cpu_time_limit_ms,
            )?;
            let peak_bytes = job
                .peak_process_memory_used()?
                .max(job.peak_job_memory_used()?);
            // copy_out: collect the products while the Job Object has
            // already reaped the tree, before the workdir disappears.
            let collected = match &copy_out {
                Some(entries) => workdir.collect(entries, copy_out_limit_bytes)?,
                None => crate::backend::windows::workdir::Collected::default(),
            };
            let (out, err) = set.finish()?;
            // Post-run output evidence: a fast writer can exit before the
            // monitor observes the reader's flag, so the completed channel
            // totals get the last word (the Linux backend does the same).
            let output_limit_hit = stdout_limit.is_some_and(|limit| out.total > limit)
                || stderr_limit.is_some_and(|limit| err.total > limit);
            Ok((
                outcome,
                peak_bytes,
                out,
                err,
                collected.quota_exceeded,
                output_limit_hit,
            ))
        });

        match result {
            Ok((outcome, peak_bytes, out, err, quota_exceeded, output_limit_hit)) => {
                // Evidence-priority verdict (contract layer): the backend reports what it
                // observed; the contract classifies it — sandbox kills and
                // limit evidence outrank the raw exit code of a killed process.
                let kill = if quota_exceeded {
                    KillOrigin::CopyOutQuota
                } else {
                    outcome.kill
                };
                let evidence = RunEvidence {
                    kill,
                    exit_code: outcome.exit_code,
                    residual_processes: outcome.residual_processes,
                    // Windows memory caps make allocations fail (commit
                    // semantics); there is no kernel OOM-kill counter.
                    oom_killed: false,
                    output_limit_hit,
                    cpu_time_limit_ms,
                    cpu_time_used_ms: outcome.cpu_time_ms,
                    memory_limit_bytes: Some(memory_limit_bytes),
                    peak_memory_bytes: peak_bytes,
                };
                let mut status = Status::from_verdict(classify(&evidence));
                status.time_used_ms = outcome.cpu_time_ms;
                status.wall_time_used_ms = outcome.wall_time_ms;
                status.memory_used_kb = peak_bytes / 1024;
                status.exit_code = outcome.exit_code;
                status.stdout = out.data;
                status.stderr = err.data;
                status.stdout_truncated = out.truncated;
                status.stderr_truncated = err.truncated;
                status.stdout_file_truncated = out.sink_truncated;
                status.stderr_file_truncated = err.sink_truncated;
                Ok(status)
            }
            Err(e) => {
                // Infra failure: report as SE per the frozen contract
                // (validation errors raise; runtime failures surface here).
                Ok(Status::infra_se(e.to_string()))
            }
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "Sandbox(runtimes=[{}], max_wall_secs={}, max_processes={})",
            self.runtimes.len(),
            self.ceilings.wall_limit.as_secs(),
            self.ceilings.max_processes
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sandboxed spawn profile always carries the full mitigation set.
    #[test]
    fn sandboxed_profile_carries_mitigations() {
        let p = SpawnProfile::sandboxed(std::ptr::null_mut(), Vec::new());
        assert_eq!(
            p.mitigation_policy,
            crate::backend::windows::spawn::mitigation_policies()
        );
        assert!(!p.has_appcontainer());
    }
}
