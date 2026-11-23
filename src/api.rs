//! Python-facing API: `River`, `ExecResult` and the exception hierarchy
//! (design.md §4).

use std::collections::HashMap;
use std::path::PathBuf;

use pyo3::exceptions::{PyNotImplementedError, PyRuntimeError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyTuple};

use crate::preflight;

pyo3::create_exception!(
    river,
    RiverError,
    PyRuntimeError,
    "Base class of every exception river raises on the host side."
);
pyo3::create_exception!(
    river,
    KernelTooOldError,
    RiverError,
    "The running kernel is older than 6.8."
);
pyo3::create_exception!(
    river,
    UserNamespaceDeniedError,
    RiverError,
    "Unprivileged user namespaces are not available."
);
pyo3::create_exception!(
    river,
    CgroupNotDelegatedError,
    RiverError,
    "The process does not run inside a delegated cgroup v2 subtree."
);
pyo3::create_exception!(river, RootfsError, RiverError, "The rootfs directory cannot be used.");
pyo3::create_exception!(
    river,
    ExecSetupError,
    RiverError,
    "The sandbox could not be established before execve."
);
pyo3::create_exception!(
    river,
    CopyOutError,
    RiverError,
    "A copy_out entry could not be retrieved."
);

/// Runs programs inside a rootfs. Construction performs every preflight check
/// (design.md §8) and raises on the first failure; instances are immutable and
/// safe to share between threads.
#[pyclass(frozen, module = "river")]
pub struct River {
    rootfs: PathBuf,
    /// `envs` from `<rootfs>/meta.json`, consumed by `exec()`.
    #[allow(dead_code)]
    envs: Option<HashMap<String, String>>,
}

#[pymethods]
impl River {
    #[new]
    #[pyo3(signature = (rootfs))]
    fn new(py: Python<'_>, rootfs: PathBuf) -> PyResult<Self> {
        preflight::check_all()?;
        let info = preflight::check_rootfs(py, &rootfs)?;
        Ok(River {
            rootfs: info.path,
            envs: info.envs,
        })
    }

    /// Absolute path of the rootfs.
    #[getter]
    fn rootfs(&self) -> String {
        self.rootfs.display().to_string()
    }

    fn __repr__(&self) -> String {
        format!("River('{}')", self.rootfs.display())
    }

    fn __enter__(slf: Bound<'_, Self>) -> Bound<'_, Self> {
        slf
    }

    fn __exit__(&self, _exc_type: Py<PyAny>, _exc_value: Py<PyAny>, _traceback: Py<PyAny>) -> bool {
        false
    }

    /// Not implemented yet; the signature is documented in `river/_river.pyi`
    /// and `docs/example.py`.
    #[pyo3(signature = (*args, **kwargs))]
    #[allow(unused_variables)]
    fn exec(&self, args: &Bound<'_, PyTuple>, kwargs: Option<&Bound<'_, PyAny>>) -> PyResult<ExecResult> {
        Err(PyNotImplementedError::new_err(
            "River.exec() is not implemented yet",
        ))
    }
}

/// Immutable outcome of one `River.exec()` (design.md §4).
#[pyclass(frozen, module = "river", get_all)]
pub struct ExecResult {
    pub status: String,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub cpu_time_used_ms: u64,
    pub wall_time_used_ms: u64,
    pub memory_used_bytes: u64,
    pub stdout: Option<Py<PyBytes>>,
    pub stderr: Option<Py<PyBytes>>,
    pub files: Py<PyDict>,
    pub error: Option<String>,
}

#[pymethods]
impl ExecResult {
    #[new]
    #[pyo3(signature = (
        status,
        exit_code,
        signal,
        cpu_time_used_ms,
        wall_time_used_ms,
        memory_used_bytes,
        *,
        stdout = None,
        stderr = None,
        files = None,
        error = None,
    ))]
    fn new(
        py: Python<'_>,
        status: String,
        exit_code: Option<i32>,
        signal: Option<i32>,
        cpu_time_used_ms: u64,
        wall_time_used_ms: u64,
        memory_used_bytes: u64,
        stdout: Option<Bound<'_, PyBytes>>,
        stderr: Option<Bound<'_, PyBytes>>,
        files: Option<Bound<'_, PyDict>>,
        error: Option<String>,
    ) -> Self {
        ExecResult {
            status,
            exit_code,
            signal,
            cpu_time_used_ms,
            wall_time_used_ms,
            memory_used_bytes,
            stdout: stdout.map(|b| b.unbind()),
            stderr: stderr.map(|b| b.unbind()),
            files: files.map_or_else(|| PyDict::new(py).unbind(), |d| d.unbind()),
            error,
        }
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        let blob = |b: &Option<Py<PyBytes>>| -> PyResult<String> {
            Ok(match b {
                Some(b) => format!("{} bytes", b.bind(py).len()?),
                None => "None".to_string(),
            })
        };
        let opt = |v: &Option<i32>| v.map(|v| v.to_string()).unwrap_or_else(|| "None".to_string());
        let quoted = |s: &Option<String>| {
            s.as_deref()
                .map(|s| format!("'{s}'"))
                .unwrap_or_else(|| "None".to_string())
        };
        Ok(format!(
            "ExecResult(status='{}', exit_code={}, signal={}, cpu_time_used_ms={}, \
             wall_time_used_ms={}, memory_used_bytes={}, stdout={}, stderr={}, files={}, error={})",
            self.status,
            opt(&self.exit_code),
            opt(&self.signal),
            self.cpu_time_used_ms,
            self.wall_time_used_ms,
            self.memory_used_bytes,
            blob(&self.stdout)?,
            blob(&self.stderr)?,
            self.files.bind(py).repr()?,
            quoted(&self.error)
        ))
    }
}
