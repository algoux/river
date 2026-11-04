use pyo3::prelude::*;

use super::verdict::Verdict;

/// Result of `Sandbox.run`.
///
/// Field units (part of the frozen API contract, mirrored in field names):
/// - `time_used_ms` / `wall_time_used_ms`: milliseconds (CPU time / wall
///   clock time)
/// - `memory_used_kb`: kilobytes (peak committed memory of the process tree)
/// - `status`: one of `"AC" | "TLE" | "MLE" | "OLE" | "RE" | "SE"`
///   - `AC`  : exited normally (exit code 0)
///   - `TLE` : CPU time or wall clock time limit exceeded
///   - `MLE` : memory limit exceeded
///   - `OLE` : stdout/stderr limit exceeded
///   - `RE`  : non-zero exit code / abnormal termination
///   - `SE`  : sandbox internal error (spawn failure, cleanup failure, ...)
/// - `signal`: synthesized value; `0` for normal exit, `9` when the sandbox
///   killed the process (TLE / MLE / OLE / residual-SE). Windows has no
///   signals; this field mimics the Linux convention for caller
///   portability. (An infrastructure `SE` — spawn/cleanup failure — reports
///   `0`: nothing was killed.)
/// - `exit_code`: raw process exit code. Abnormal terminations surface as
///   NTSTATUS values on Windows (e.g. `0xC0000005` access violation).
/// - `stdout` / `stderr`: captured output, truncated to the respective limit.
///   Check `stdout_truncated` / `stderr_truncated` to know whether bytes were
///   dropped.
#[pyclass(module = "river")]
#[derive(Default)]
pub struct Status {
    pub time_used_ms: u64,
    pub wall_time_used_ms: u64,
    pub memory_used_kb: u64,
    pub status: String,
    pub signal: i32,
    pub exit_code: i32,
    /// The kernel OOM killer reaped a task in the sandbox cgroup during the
    /// run (`memory.events` `oom_kill` > 0). Linux-only; always false on
    /// Windows (where the memory cap makes allocations fail instead).
    pub oom_killed: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

impl Status {
    /// Build a Status from a classified verdict (the normal path).
    pub(crate) fn from_verdict(verdict: Verdict) -> Self {
        Status {
            status: verdict.as_str().to_string(),
            signal: verdict.synthesized_signal(),
            ..Default::default()
        }
    }

    /// Build an infrastructure-failure `SE` (spawn/cleanup error): the
    /// sandbox's own machinery failed, nothing was killed, `signal` stays 0.
    pub(crate) fn infra_se(stderr: String) -> Self {
        Status {
            status: Verdict::Se.as_str().to_string(),
            exit_code: -1,
            stderr: stderr.into_bytes(),
            ..Default::default()
        }
    }
}

#[pymethods]
impl Status {
    /// CPU time used, in milliseconds.
    #[getter]
    fn time_used_ms(&self) -> u64 {
        self.time_used_ms
    }

    /// Wall clock time used, in milliseconds.
    #[getter]
    fn wall_time_used_ms(&self) -> u64 {
        self.wall_time_used_ms
    }

    /// Peak memory usage, in kilobytes.
    #[getter]
    fn memory_used_kb(&self) -> u64 {
        self.memory_used_kb
    }

    /// Verdict string: `"AC" | "TLE" | "MLE" | "OLE" | "RE" | "SE"`.
    #[getter]
    fn status(&self) -> String {
        self.status.clone()
    }

    /// Synthesized signal: `0` normally, `9` when killed by the sandbox.
    #[getter]
    fn signal(&self) -> i32 {
        self.signal
    }

    /// Raw process exit code (NTSTATUS on abnormal Windows terminations).
    #[getter]
    fn exit_code(&self) -> i32 {
        self.exit_code
    }

    /// Whether the kernel OOM killer reaped a sandbox task during the run.
    /// Linux-only (`memory.events` `oom_kill` > 0); always false on Windows.
    #[getter]
    fn oom_killed(&self) -> bool {
        self.oom_killed
    }

    /// Captured stdout, truncated to `stdout_limit_kb`.
    #[getter]
    fn stdout(&self) -> Vec<u8> {
        self.stdout.clone()
    }

    /// Captured stderr, truncated to `stderr_limit_kb`.
    #[getter]
    fn stderr(&self) -> Vec<u8> {
        self.stderr.clone()
    }

    /// Whether stdout exceeded its limit and bytes were dropped.
    #[getter]
    fn stdout_truncated(&self) -> bool {
        self.stdout_truncated
    }

    /// Whether stderr exceeded its limit and bytes were dropped.
    #[getter]
    fn stderr_truncated(&self) -> bool {
        self.stderr_truncated
    }

    fn __repr__(&self) -> String {
        format!(
            "Status(status={:?}, exit_code={:?}, signal={:?}, time_used_ms={}, wall_time_used_ms={}, memory_used_kb={})",
            self.status,
            self.exit_code,
            self.signal,
            self.time_used_ms,
            self.wall_time_used_ms,
            self.memory_used_kb
        )
    }
}
