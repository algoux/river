//! Python-facing API: `River`, `ExecResult` and the exception hierarchy
//! (design.md §4).

use std::collections::HashMap;
use std::path::PathBuf;

use pyo3::exceptions::{PyKeyboardInterrupt, PyRuntimeError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

use crate::exec::{self, CopyInValue, ExecFailure, ExecParams};
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
    "A copy_out entry could not be retrieved; .result holds the ExecResult of the finished run."
);

/// Runs programs inside a rootfs. Construction performs every preflight check
/// (design.md §8) and raises on the first failure; instances are immutable and
/// safe to share between threads.
#[pyclass(frozen, module = "river")]
pub struct River {
    rootfs: PathBuf,
    /// `envs` from `<rootfs>/meta.json`, consumed by `exec()` (design.md §4.1).
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

    /// Executes `executable` inside the sandbox (design.md §4). The sandbox
    /// child is pid 1 of a fresh pid namespace; every end state lands in the
    /// returned `ExecResult`, only setup failures raise.
    #[pyo3(signature = (
        executable,
        args = None,
        *,
        cwd = None,
        envs = None,
        cpu_time_limit_ms = None,
        wall_time_limit_ms = None,
        memory_limit_bytes = None,
        stdout_limit_bytes = None,
        stderr_limit_bytes = None,
        copy_in = None,
        copy_out = None,
        copy_out_limit_bytes = None,
        stdin_file = None,
        stdin = None,
        stdout_file = None,
        stderr_file = None,
        proc_limit = None,
        open_file_limit = None,
        stack_limit_bytes = None,
        address_space_limit_bytes = None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn exec(
        &self,
        py: Python<'_>,
        executable: Py<PyAny>,
        args: Option<Vec<String>>,
        cwd: Option<String>,
        envs: Option<Py<PyAny>>,
        cpu_time_limit_ms: Option<u64>,
        wall_time_limit_ms: Option<u64>,
        memory_limit_bytes: Option<u64>,
        stdout_limit_bytes: Option<u64>,
        stderr_limit_bytes: Option<u64>,
        copy_in: Option<Py<PyAny>>,
        copy_out: Option<Py<PyAny>>,
        copy_out_limit_bytes: Option<u64>,
        stdin_file: Option<String>,
        stdin: Option<Py<PyBytes>>,
        stdout_file: Option<String>,
        stderr_file: Option<String>,
        proc_limit: Option<u64>,
        open_file_limit: Option<u64>,
        stack_limit_bytes: Option<u64>,
        address_space_limit_bytes: Option<u64>,
    ) -> PyResult<ExecResult> {
        // ------------------------------------------------- extract & validate
        let executable = str_or_path(py, executable)?;
        let args = args.unwrap_or_default();
        let cwd = cwd.unwrap_or_else(|| "/work".to_string());
        let envs = match envs {
            Some(value) => extract_envs(py, value)?,
            None => self.envs.clone().ok_or_else(|| {
                RootfsError::new_err(format!(
                    "envs is None but the rootfs {} has no meta.json providing envs",
                    self.rootfs.display()
                ))
            })?,
        };
        let stdin_data = stdin.map(|b| b.bind(py).as_bytes().to_vec());
        if stdin_data.is_some() && stdin_file.is_some() {
            return Err(PyValueError::new_err(
                "stdin and stdin_file are mutually exclusive",
            ));
        }
        if !cwd.starts_with('/') {
            return Err(PyValueError::new_err(format!(
                "cwd {cwd:?} must be an absolute sandbox path"
            )));
        }
        if executable.is_empty() {
            return Err(PyValueError::new_err("executable must not be empty"));
        }
        if !executable.contains('/') && !envs.contains_key("PATH") {
            return Err(PyValueError::new_err(
                "executable without '/' requires envs['PATH'] so the sandbox can find it",
            ));
        }
        let copy_in = match copy_in {
            None => Vec::new(),
            Some(value) => extract_copy_in(py, value)?,
        };
        let copy_out = match copy_out {
            None => Vec::new(),
            Some(value) => extract_copy_out(py, value)?,
        };
        // design.md §10: keys normalize strictly below /work.
        for (key, _) in &copy_in {
            exec::io::sandbox_path(key, &cwd).map_err(RootfsError::new_err)?;
        }
        for (key, _) in &copy_out {
            exec::io::sandbox_path(key, &cwd).map_err(RootfsError::new_err)?;
        }

        // design.md §6: from here the limits reach the run cgroup
        // (`memory.max`, `pids.max`), the rlimits (`RLIMIT_*`) or the
        // supervisor (wall clock, output caps).

        let params = ExecParams {
            executable,
            args,
            cwd,
            envs,
            stdin: stdin_data,
            stdin_file,
            stdout_file,
            stderr_file,
            stdout_limit_bytes,
            stderr_limit_bytes,
            cpu_time_limit_ms,
            wall_time_limit_ms,
            memory_limit_bytes,
            proc_limit,
            open_file_limit,
            stack_limit_bytes,
            address_space_limit_bytes,
            copy_in,
            copy_out,
            copy_out_limit_bytes,
        };

        // ------------------------------------------------------- run, GIL-free
        let outcome = py
            .detach(|| exec::run(&self.rootfs, &params))
            .map(|outcome| build_result(py, outcome))
            .map_err(|failure| failure_to_err(py, failure))?;
        Ok(outcome)
    }
}

/// `str | os.PathLike` → `String` (design.md §4).
fn str_or_path(py: Python<'_>, value: Py<PyAny>) -> PyResult<String> {
    let bound = value.bind(py);
    if let Ok(text) = bound.extract::<String>() {
        return Ok(text);
    }
    if is_pathlike(py, bound)? {
        fspath(py, bound)
    } else {
        Err(PyTypeError::new_err(format!(
            "expected str or os.PathLike, got {}",
            bound.get_type().name()?
        )))
    }
}

fn is_pathlike(py: Python<'_>, value: &Bound<'_, PyAny>) -> PyResult<bool> {
    let os = py.import("os")?;
    let pathlike = os.getattr("PathLike")?;
    let builtins = py.import("builtins")?;
    let isinstance = builtins.getattr("isinstance")?;
    isinstance.call1((value, pathlike))?.extract()
}

fn fspath(py: Python<'_>, value: &Bound<'_, PyAny>) -> PyResult<String> {
    let os = py.import("os")?;
    let resolved = os.getattr("fspath")?.call1((value,))?;
    resolved.extract::<String>().map_err(|_| {
        PyTypeError::new_err("paths must be str, not bytes")
    })
}

/// `Mapping[str, str]` → `HashMap<String, String>` (passed `envs`).
fn extract_envs(py: Python<'_>, value: Py<PyAny>) -> PyResult<HashMap<String, String>> {
    let bound = value.bind(py);
    let items = bound.call_method0("items")?;
    let mut out = HashMap::new();
    for pair in items.try_iter()? {
        let (key, value): (String, String) = pair?.extract()?;
        out.insert(key, value);
    }
    Ok(out)
}

/// `Mapping[str, bytes | str | os.PathLike]` → copy_in entries (design.md §10).
fn extract_copy_in(py: Python<'_>, value: Py<PyAny>) -> PyResult<Vec<(String, CopyInValue)>> {
    let bound = value.bind(py);
    let items = bound.call_method0("items")?;
    let mut out = Vec::new();
    for pair in items.try_iter()? {
        let (key, item): (String, Py<PyAny>) = pair?.extract()?;
        let item = item.bind(py);
        let entry = if let Ok(bytes) = item.cast::<PyBytes>() {
            CopyInValue::Bytes(bytes.as_bytes().to_vec())
        } else if let Ok(text) = item.extract::<String>() {
            CopyInValue::Bytes(text.into_bytes())
        } else if is_pathlike(py, item)? {
            CopyInValue::HostFile(PathBuf::from(fspath(py, item)?))
        } else {
            return Err(PyTypeError::new_err(format!(
                "copy_in values must be bytes, str or os.PathLike, got {}",
                item.get_type().name()?
            )));
        };
        out.push((key, entry));
    }
    Ok(out)
}

/// `Mapping[str, None | str | os.PathLike]` → copy_out entries (design.md
/// §4, §10): a host path as `str` or `os.PathLike` gets the content written
/// over it, `None` keeps the content in `ExecResult.files`.
fn extract_copy_out(py: Python<'_>, value: Py<PyAny>) -> PyResult<Vec<(String, Option<String>)>> {
    let bound = value.bind(py);
    let items = bound.call_method0("items")?;
    let mut out = Vec::new();
    for pair in items.try_iter()? {
        let (key, item): (String, Py<PyAny>) = pair?.extract()?;
        let item = item.bind(py);
        let dest = if item.is_none() {
            None
        } else if let Ok(text) = item.extract::<String>() {
            Some(text)
        } else if is_pathlike(py, item)? {
            Some(fspath(py, item)?)
        } else {
            return Err(PyTypeError::new_err(format!(
                "copy_out values must be None or os.PathLike, got {}",
                item.get_type().name()?
            )));
        };
        out.push((key, dest));
    }
    Ok(out)
}

/// `ExecFailure` → the Python exception it represents (design.md §4).
fn failure_to_err(py: Python<'_>, failure: ExecFailure) -> PyErr {
    match failure {
        ExecFailure::BadParams(msg) => PyValueError::new_err(msg),
        ExecFailure::Rootfs(msg) => RootfsError::new_err(msg),
        ExecFailure::Host(msg) => RiverError::new_err(msg),
        ExecFailure::Setup { step, errno, context } => {
            // ExecSetupError carries the step name and the errno text
            // (design.md §4).
            let errno_text = if errno == 0 {
                String::new()
            } else {
                format!(": {}", std::io::Error::from_raw_os_error(errno))
            };
            let msg = if context.is_empty() {
                format!("{step}{errno_text}")
            } else {
                format!("{step}: {context}{errno_text}")
            };
            ExecSetupError::new_err(msg)
        }
        ExecFailure::CopyOut { key, reason, result } => {
            // design.md §4: `.result` carries the run that finished before
            // copy_out failed, so the caller keeps the verdict and metrics.
            // (This function returns PyErr, not PyResult, so the ? operator
            // is unavailable here.)
            let err = CopyOutError::new_err(format!("copy_out {key:?}: {reason}"));
            if let Err(setattr_err) = err.value(py).setattr("result", build_result(py, *result)) {
                return setattr_err;
            }
            err
        }
        ExecFailure::Interrupted => {
            // The child is already killed and reaped; surface the pending
            // signal now that the GIL is back (design.md §4).
            match py.check_signals() {
                Err(err) => err,
                Ok(()) => PyKeyboardInterrupt::new_err("river.exec() was interrupted"),
            }
        }
    }
}

/// `Outcome` (plain Rust) → `ExecResult`.
fn build_result(py: Python<'_>, outcome: exec::Outcome) -> ExecResult {
    let files = PyDict::new(py);
    for (key, data) in outcome.files {
        let _ = files.set_item(key, PyBytes::new(py, &data));
    }
    ExecResult {
        status: outcome.status,
        exit_code: outcome.exit_code,
        signal: outcome.signal,
        cpu_time_used_ms: outcome.cpu_time_used_ms,
        wall_time_used_ms: outcome.wall_time_used_ms,
        memory_used_bytes: outcome.memory_used_bytes,
        stdout: outcome.stdout.map(|data| PyBytes::new(py, &data).unbind()),
        stderr: outcome.stderr.map(|data| PyBytes::new(py, &data).unbind()),
        files: files.unbind(),
        error: outcome.error,
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
