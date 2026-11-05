use std::sync::OnceLock;

use pyo3::prelude::*;
use pyo3::types::PyBytes;

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
/// - `exit_code`: raw process exit code, **unsigned** (Windows NTSTATUS
///   values such as `0xC0000005` are the full 32-bit value, e.g.
///   `3221225477`). `u32::MAX` means "no exit code": the sandbox's own
///   machinery failed before/while spawning (infrastructure `SE`).
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
    pub exit_code: u32,
    /// The kernel OOM killer reaped a task in the sandbox cgroup during the
    /// run (`memory.events` `oom_kill` > 0). Linux-only; always false on
    /// Windows (where the memory cap makes allocations fail instead).
    pub oom_killed: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    /// The `stdout_file` / `stderr_file` archive stopped early (the internal
    /// file-sink safety ceiling was reached and bytes were dropped).
    pub stdout_file_truncated: bool,
    pub stderr_file_truncated: bool,
    /// Materialized Python `bytes` objects, created on first attribute
    /// access. Reading `r.stdout` more than once (a very common judge
    /// pattern) must not copy the sample — up to 64 MiB per channel — on
    /// every access.
    ///
    /// Invariant: `stdout`/`stderr` are populated by the backend *before*
    /// the object is returned to Python; nothing mutates them afterwards.
    stdout_py: OnceLock<Py<PyBytes>>,
    stderr_py: OnceLock<Py<PyBytes>>,
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
    /// sandbox's own machinery failed, nothing was killed, `signal` stays 0
    /// and `exit_code` is `u32::MAX` ("no exit code").
    pub(crate) fn infra_se(stderr: String) -> Self {
        Status {
            status: Verdict::Se.as_str().to_string(),
            exit_code: u32::MAX,
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

    /// Raw process exit code (unsigned; NTSTATUS on abnormal Windows
    /// terminations, `u32::MAX` for an infrastructure `SE`).
    #[getter]
    fn exit_code(&self) -> u32 {
        self.exit_code
    }

    /// Whether the kernel OOM killer reaped a sandbox task during the run.
    /// Linux-only (`memory.events` `oom_kill` > 0); always false on Windows.
    #[getter]
    fn oom_killed(&self) -> bool {
        self.oom_killed
    }

    /// Captured stdout, truncated to `stdout_limit_kb`.
    ///
    /// The returned object is cached: repeated reads return the same
    /// immutable `bytes` (no re-copy of the sample).
    #[getter]
    fn stdout(&self, py: Python<'_>) -> Py<PyBytes> {
        bytes_cached(py, &self.stdout_py, &self.stdout)
    }

    /// Captured stderr, truncated to `stderr_limit_kb`.
    #[getter]
    fn stderr(&self, py: Python<'_>) -> Py<PyBytes> {
        bytes_cached(py, &self.stderr_py, &self.stderr)
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

    /// Whether the `stdout_file` archive stopped early (sink ceiling).
    #[getter]
    fn stdout_file_truncated(&self) -> bool {
        self.stdout_file_truncated
    }

    /// Whether the `stderr_file` archive stopped early (sink ceiling).
    #[getter]
    fn stderr_file_truncated(&self) -> bool {
        self.stderr_file_truncated
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

/// Return the cached `bytes` object for `data`, creating it on first access.
/// The `OnceLock` makes repeated attribute reads O(1) (a refcount bump)
/// instead of re-copying the (up to 64 MiB) sample; concurrent first reads
/// are safe — both may build a `PyBytes`, one wins the `set` and both
/// return an equivalent object.
fn bytes_cached(py: Python<'_>, cache: &OnceLock<Py<PyBytes>>, data: &[u8]) -> Py<PyBytes> {
    if let Some(cached) = cache.get() {
        return cached.clone_ref(py);
    }
    let fresh = PyBytes::new(py, data).unbind();
    match cache.set(fresh.clone_ref(py)) {
        Ok(()) => fresh,
        // Another thread materialized it first: hand out that object.
        Err(_) => cache.get().map_or(fresh, |c| c.clone_ref(py)),
    }
}
