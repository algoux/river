use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

use pyo3::prelude::*;
use pyo3::types::PyAny;

use crate::platform::windows::job::{Job, JobLimits};
use crate::platform::windows::monitor::monitor;
use crate::platform::windows::spawn::spawn_bare;
use crate::platform::windows::stdio::{StdinSource, StdioSet};
use crate::platform::windows::verdict::{
    AC, RE, SE, SIG_NONE, SIGKILL, TLE, Verdict, classify_with_residual,
};
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

        // --- translate the frozen contract into P1 primitives -------------
        // P1 scope: measurement core without sandboxing. cwd/env/copy_in are
        // honored from S5/S7 (workdir + ACL layer); runtimes from S7.
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

        // Blocking pipeline with the GIL released.
        let result = py.detach(move || -> io::Result<_> {
            let job = Job::new(&limits)?;
            let mut set = StdioSet::new(
                stdin_src,
                stdout_limit,
                stderr_limit,
                stdout_file,
                stderr_file,
            )?;
            let child = spawn_bare(&exe, &args, &job, &mut set)?;
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
