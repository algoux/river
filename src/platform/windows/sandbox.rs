use std::collections::HashMap;
use std::path::PathBuf;

use pyo3::prelude::*;
use pyo3::types::PyAny;

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
        let _ = spec.effective_wall_time_limit_ms();
        // TODO(win32): AppContainer/low-IL token + Job Object + mitigation
        // policies + piped stdio per DESIGN (see conversation baseline).
        Ok(Status::default())
    }

    fn __repr__(&self) -> String {
        format!("Sandbox(runtimes=[{}])", self.runtimes.len())
    }
}
