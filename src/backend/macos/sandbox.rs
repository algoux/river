use std::collections::HashMap;
use std::path::PathBuf;

use pyo3::prelude::*;
use pyo3::types::PyAny;

use crate::contract::{RunSpec, parse_copy_in, validate};
use crate::contract::status::Status;

/// macOS sandbox — **not implemented yet**.
///
/// The Windows backend is the current target; this module exists so the crate
/// keeps the platform split, and `run()` raises `NotImplementedError` rather
/// than pretending to sandbox anything.
///
/// The intended design (see DESIGN.md §1): with `rootfs` the sandbox would
/// execute inside a sandbox-exec profile restricted to it, and paths in
/// `runtimes` would be exposed read-only on top of it.
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
    fn new(rootfs: Option<PathBuf>, runtimes: Option<Vec<PathBuf>>) -> Self {
        Self {
            rootfs,
            runtimes: runtimes.unwrap_or_default(),
        }
    }

    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    /// Exit protocol: no leftover sandboxed processes, temporary working
    /// directories removed, profiles/tokens released. Always returns `false`.
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
    /// Coordinate systems: `executable` is a host path when no `rootfs` is
    /// set, else a path inside the rootfs; `cwd` and `copy_in` keys are
    /// relative to the per-run private working directory.
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
        let _ = spec.effective_wall_time_limit_ms();
        // The macOS backend is not implemented yet (see DESIGN.md §1). Fail
        // loudly instead of returning an empty Status that would look like a
        // silent no-op run.
        Err(pyo3::exceptions::PyNotImplementedError::new_err(
            "river currently supports Windows only; the macOS backend is not implemented yet",
        ))
    }

    fn __repr__(&self) -> String {
        match &self.rootfs {
            Some(rootfs) => format!(
                "Sandbox(rootfs={:?}, runtimes=[{}])",
                rootfs.display().to_string(),
                self.runtimes.len()
            ),
            None => format!("Sandbox(runtimes=[{}])", self.runtimes.len()),
        }
    }
}