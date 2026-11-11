//! Path and copy-map validation shared by every backend.
//!
//! `cwd`, `copy_in` destinations and `copy_out` sources are caller-supplied
//! relative paths interpreted inside the session scratch directory; these
//! helpers are the single choke point that keeps them from escaping it.

use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};

use pyo3::exceptions::{PyOSError, PyValueError};
use pyo3::prelude::*;

/// Validates the `copy_out` sources: relative to the workdir. Destinations
/// are host paths and are not restricted.
pub(crate) fn validate_copy_out(entries: Option<&HashMap<PathBuf, PathBuf>>) -> PyResult<()> {
    let Some(entries) = entries else {
        return Ok(());
    };
    for source in entries.keys() {
        validate_relative_path("copy_out", source)?;
    }
    Ok(())
}

/// Validates the `copy_in` destinations: relative to the workdir, unique, and
/// not nested inside one another.
pub(crate) fn validate_copy_in(entries: Option<&HashMap<PathBuf, PathBuf>>) -> PyResult<()> {
    let Some(entries) = entries else {
        return Ok(());
    };
    let mut destinations: HashSet<&Path> = HashSet::with_capacity(entries.len());
    for destination in entries.values() {
        validate_relative_path("copy_in", destination)?;
        if !destinations.insert(destination.as_path()) {
            return Err(PyValueError::new_err(format!(
                "copy_in maps more than one source to the same destination: {}",
                destination.display()
            )));
        }
    }
    for &destination in &destinations {
        for ancestor in destination.ancestors().skip(1) {
            if ancestor.as_os_str().is_empty() {
                break;
            }
            if destinations.contains(ancestor) {
                return Err(PyValueError::new_err(format!(
                    "copy_in destinations overlap: {} is inside {}",
                    destination.display(),
                    ancestor.display()
                )));
            }
        }
    }
    Ok(())
}

/// `cwd` is relative to the session scratch directory; inside a session the
/// default is that directory itself. Outside a `with` block there is no
/// scratch directory and the child keeps the caller's current directory.
pub(crate) fn resolve_cwd(cwd: Option<&str>, workdir: Option<&Path>) -> PyResult<Option<PathBuf>> {
    let Some(cwd) = cwd else {
        return Ok(workdir.map(Path::to_path_buf));
    };
    validate_relative_path("cwd", Path::new(cwd))?;

    let base = match workdir {
        Some(workdir) => workdir.to_path_buf(),
        None => std::env::current_dir().map_err(|error| {
            PyOSError::new_err(format!("failed to resolve the current directory: {error}"))
        })?,
    };
    let path = base.join(cwd);
    if !path.is_dir() {
        return Err(PyValueError::new_err(format!(
            "cwd {cwd:?} is not a directory inside the sandbox: {}",
            path.display()
        )));
    }
    Ok(Some(path))
}

/// Accepts only plain relative components (no root, `.` or `..`), so `cwd`
/// and `copy_in` destinations cannot escape the workdir.
pub(crate) fn validate_relative_path(kind: &str, path: &Path) -> PyResult<()> {
    if path.as_os_str().is_empty()
        || path.has_root()
        // shortcut: `:` is only special in Windows paths, but a Unix name
        // containing one is exotic enough to reject for cross-platform parity
        || path.to_string_lossy().contains(':')
        || !path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(PyValueError::new_err(format!(
            "invalid {kind} {}: must be a relative path inside the sandbox workdir",
            path.display()
        )));
    }
    Ok(())
}
