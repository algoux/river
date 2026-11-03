use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

use pyo3::prelude::*;
use pyo3::types::PyAny;

use crate::platform::windows::acl;
use crate::platform::windows::job::{Job, JobLimits};
use crate::platform::windows::monitor::monitor;
use crate::platform::windows::spawn::{SpawnSecurity, env_block, spawn_bare};
use crate::platform::windows::stdio::{StdinSource, StdioSet};
use crate::platform::windows::token::AppContainer;
use crate::platform::windows::verdict::{
    AC, RE, SE, SIG_NONE, SIGKILL, TLE, Verdict, classify_with_residual,
};
use crate::platform::windows::workdir::WorkDir;
use crate::platform::{RunSpec, parse_copy_in, validate};
use crate::status::Status;

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
#[pyclass(module = "river")]
pub struct Sandbox {
    pub rootfs: Option<PathBuf>,
    pub runtimes: Vec<PathBuf>,
}

#[pymethods]
impl Sandbox {
    #[new]
    #[pyo3(signature = (rootfs=None, runtimes=None))]
    #[pyo3(text_signature = "(rootfs=None, runtimes=None)")]
    fn new(rootfs: Option<PathBuf>, runtimes: Option<Vec<PathBuf>>) -> PyResult<Self> {
        if rootfs.is_some() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "rootfs is not supported on Windows; use runtimes=[...] to expose \
                 read-only runtime directories instead",
            ));
        }
        Ok(Self {
            rootfs: None,
            runtimes: runtimes.unwrap_or_default(),
        })
    }

    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    /// Exit protocol: no leftover sandboxed processes, temporary working
    /// directories removed, tokens/handles released. Always returns `false`.
    fn __exit__(
        &self,
        _exc_type: &Bound<'_, PyAny>,
        _exc_value: &Bound<'_, PyAny>,
        _traceback: &Bound<'_, PyAny>,
    ) -> bool {
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
        stdout_limit_kb = None,
        stderr_limit_kb = None,
        stdout_file = None,
        stderr_file = None,
    ))]
    #[pyo3(
        text_signature = "(executable, args=[], cwd=None, env=None, time_limit_ms=None, wall_time_limit_ms=None, memory_limit_kb=None, stdin=None, stdin_file=None, copy_in=None, stdout_limit_kb=None, stderr_limit_kb=None, stdout_file=None, stderr_file=None)"
    )]
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
            stdout_limit_kb,
            stderr_limit_kb,
            stdout_file,
            stderr_file,
        };
        validate(&spec)?;

        // --- translate the frozen contract into P1/P2 primitives ----------
        let stdin_src = match (&spec.stdin, &spec.stdin_file) {
            (Some(bytes), _) => StdinSource::Bytes(bytes.clone()),
            (None, Some(path)) => StdinSource::File(path.clone()),
            _ => StdinSource::Null,
        };
        let limits = JobLimits {
            memory_limit_bytes: spec.memory_limit_kb.map(|kb| kb.saturating_mul(1024)),
            cpu_time_limit_ms: spec.time_limit_ms,
            max_processes: crate::platform::windows::job::DEFAULT_MAX_PROCESSES,
        };
        let wall_limit = spec
            .effective_wall_time_limit_ms()
            .map(Duration::from_millis);
        let stdout_limit = spec.stdout_limit_kb.map(|kb| kb * 1024);
        let stderr_limit = spec.stderr_limit_kb.map(|kb| kb * 1024);
        let exe = spec.executable.clone();
        let args = spec.args.clone();
        let (stdout_file, stderr_file) = (spec.stdout_file.clone(), spec.stderr_file.clone());
        let copy_in = spec.copy_in.clone();
        let cwd_rel = spec.cwd.clone();
        let env_map = spec.env.clone().unwrap_or_default();
        let runtimes = self.runtimes.clone();

        // Blocking pipeline with the GIL released.
        let result = py.detach(move || -> io::Result<_> {
            // Per-run working directory: the only writable place the program
            // sees. `WorkDir` removes itself on drop (also on error paths).
            let workdir = WorkDir::create()?;
            if let Some(files) = &copy_in {
                workdir.provision(files)?;
            }

            // S7: AppContainer identity + ACL grants. The child adopts the
            // AppContainer at spawn time; its visible filesystem is exactly
            // the granted surface (cwd rw, runtimes ro, system DLLs default).
            let appcontainer = AppContainer::create_or_open()?;
            let sid = appcontainer.sid();
            acl::grant_rw(workdir.path(), sid)?;
            for rt in &runtimes {
                acl::grant_ro(rt, sid)?;
            }

            // Whitelisted environment: base + caller overrides (incremental
            // merge). TEMP/TMP point into the private cwd. LOCALAPPDATA is
            // REQUIRED for an AppContainer spawn: without it CreateProcessW
            // fails with ERROR_ENVVAR_NOT_FOUND (203) — see S7 踩坑记录.
            let tmp_dir = workdir.path().join("tmp");
            std::fs::create_dir(&tmp_dir)?;
            let mut env_vars: Vec<(String, String)> = vec![
                (
                    "SystemRoot".to_string(),
                    std::env::var("SystemRoot")
                        .unwrap_or_else(|_| r"C:\Windows".to_string()),
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
            let security = SpawnSecurity {
                appcontainer_sid: sid,
                env_block: env_block(&env_vars),
            };

            // The process starts inside the working directory; an explicit
            // `cwd` (relative to it) is applied below when supported.
            let cwd_path = match &cwd_rel {
                Some(rel) => {
                    let p = workdir.path().join(rel);
                    if p.is_dir() { Some(p) } else { None }
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
            )?;
            let child = spawn_bare(
                &exe,
                &args,
                &job,
                &mut set,
                cwd_path.as_deref(),
                Some(&security),
            )?;
            let outcome = monitor(&child, &job, wall_limit)?;
            let peak_bytes = job.peak_process_memory_used()?;
            let (out, err) = set.finish()?;
            Ok((outcome, peak_bytes, out, err))
        });

        match result {
            Ok((outcome, peak_bytes, out, err)) => {
                let mut verdict: Verdict = classify_with_residual(
                    &outcome.kill_reason,
                    outcome.exit_code,
                    outcome.residual_processes,
                );
                // CPU-limit evidence: the job kills the process on CPU
                // overrun; classify via the measured time (S9 moves this
                // into the monitor with evidence priority).
                if (verdict.status == AC || verdict.status == RE)
                    && let Some(limit) = spec.time_limit_ms
                    && outcome.cpu_time_ms > limit
                {
                    verdict = Verdict {
                        status: TLE,
                        signal: SIGKILL,
                    };
                }
                Ok(Status {
                    time_used_ms: outcome.cpu_time_ms,
                    wall_time_used_ms: outcome.wall_time_ms,
                    memory_used_kb: peak_bytes / 1024,
                    status: verdict.status.to_string(),
                    signal: verdict.signal,
                    exit_code: outcome.exit_code as i32,
                    stdout: out.data,
                    stderr: err.data,
                    stdout_truncated: out.truncated,
                    stderr_truncated: err.truncated,
                })
            }
            Err(e) => {
                // Infra failure: report as SE per the frozen contract
                // (validation errors raise; runtime failures surface here).
                Ok(Status {
                    status: SE.to_string(),
                    signal: SIG_NONE,
                    exit_code: -1,
                    stderr: e.to_string().into_bytes(),
                    ..Default::default()
                })
            }
        }
    }

    fn __repr__(&self) -> String {
        format!("Sandbox(runtimes=[{}])", self.runtimes.len())
    }
}
