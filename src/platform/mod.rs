#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "windows")]
pub mod windows;

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

/// Source of a `copy_in` entry: inline bytes or a host-side file path.
#[derive(Clone)]
pub(crate) enum CopyInSource {
    Bytes(Vec<u8>),
    Path(PathBuf),
}

/// Frozen `run()` argument set shared by all platform backends.
///
/// Coordinate system contract:
/// - `executable`, `stdin_file`, `stdout_file`, `stderr_file`: host paths
/// - `cwd`: path relative to the sandbox private working directory
/// - `copy_in` keys: paths relative to the sandbox working directory
///
/// Limit semantics: `None` means *no caller-imposed limit*. Backends must
/// still enforce internal safety ceilings (configurable at Sandbox
/// construction) so that unlimited runs cannot take down the host.
pub(crate) struct RunSpec {
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub cwd: Option<String>,
    pub env: Option<HashMap<String, String>>,
    pub time_limit_ms: Option<u64>,
    pub wall_time_limit_ms: Option<u64>,
    pub memory_limit_kb: Option<u64>,
    pub stdin: Option<Vec<u8>>,
    pub stdin_file: Option<PathBuf>,
    pub copy_in: Option<HashMap<String, CopyInSource>>,
    pub stdout_limit_kb: Option<u64>,
    pub stderr_limit_kb: Option<u64>,
    pub stdout_file: Option<PathBuf>,
    pub stderr_file: Option<PathBuf>,
}

impl RunSpec {
    /// Effective wall clock limit: explicit value, else `2 * time_limit + 1000ms`
    /// when a CPU time limit is set, else `None` (unlimited).
    pub(crate) fn effective_wall_time_limit_ms(&self) -> Option<u64> {
        self.wall_time_limit_ms.or_else(|| {
            self.time_limit_ms
                .map(|t| t.saturating_mul(2).saturating_add(1000))
        })
    }
}

/// Parse the raw `copy_in` mapping (`sandbox-relative path -> bytes | host path`).
pub(crate) fn parse_copy_in(
    map: &HashMap<String, pyo3::Py<pyo3::PyAny>>,
    py: Python<'_>,
) -> PyResult<HashMap<String, CopyInSource>> {
    let mut out = HashMap::with_capacity(map.len());
    for (key, value) in map {
        let bound = value.bind(py);
        if let Ok(bytes) = bound.extract::<Vec<u8>>() {
            out.insert(key.clone(), CopyInSource::Bytes(bytes));
        } else if let Ok(path) = bound.extract::<PathBuf>() {
            out.insert(key.clone(), CopyInSource::Path(path));
        } else {
            return Err(PyValueError::new_err(format!(
                "copy_in[{key:?}]: value must be bytes or a host file path"
            )));
        }
    }
    Ok(out)
}

/// Cross-platform argument validation, run before any backend work.
pub(crate) fn validate(spec: &RunSpec) -> PyResult<()> {
    if spec.stdin.is_some() && spec.stdin_file.is_some() {
        return Err(PyValueError::new_err(
            "stdin and stdin_file are mutually exclusive",
        ));
    }
    for key in spec.copy_in.iter().flat_map(|m| m.keys()) {
        let path = Path::new(key);
        if path.is_absolute()
            || key.contains(':')
            || path.components().any(|c| matches!(c, Component::ParentDir))
        {
            return Err(PyValueError::new_err(format!(
                "invalid copy_in key {key:?}: must be a relative path inside the sandbox working directory"
            )));
        }
    }
    Ok(())
}
