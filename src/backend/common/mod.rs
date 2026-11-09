//! The platform-independent half of every backend.
//!
//! [`Sandbox`] owns the Python surface and the session scratch directory;
//! the platform modules implement the [`Backend`] seam and are selected by
//! [`platform_backend`]. Everything identical across Linux, macOS and
//! Windows lives in this module exactly once.

mod sandbox;

pub use sandbox::Sandbox;

use std::path::{Path, PathBuf};

use pyo3::prelude::*;

use crate::contract::RunSpec;
use crate::contract::status::Status;

/// The platform seam: everything that differs between Linux, macOS and
/// Windows hangs off this trait so the shared `Sandbox` can be written once.
///
/// `rootfs` and `runtimes` are the construction-time configuration, passed
/// by reference on every call; `workdir` is `None` outside a session.
pub(crate) trait Backend: Send + Sync + 'static {
    /// Reject platform-unsupported construction parameters. The default
    /// accepts everything.
    fn validate_new(&self, _rootfs: Option<&Path>, _runtimes: &[PathBuf]) -> PyResult<()> {
        Ok(())
    }

    /// Session-establishment hook: called by `__enter__` once the scratch
    /// directory exists but before the session becomes visible. The default
    /// does nothing.
    fn on_enter(
        &self,
        _rootfs: Option<&Path>,
        _runtimes: &[PathBuf],
        _workdir: &Path,
    ) -> PyResult<()> {
        Ok(())
    }

    /// Session-teardown hook: called by `__exit__` before the scratch
    /// directory is removed. The default does nothing.
    fn on_exit(
        &self,
        _rootfs: Option<&Path>,
        _runtimes: &[PathBuf],
        _workdir: &Path,
    ) -> PyResult<()> {
        Ok(())
    }

    /// Run `spec` inside the sandbox.
    ///
    /// The default body is the placeholder shared by the backends whose
    /// real mechanics have not landed yet; each platform replaces it by
    /// overriding (see `examples/` for the building blocks).
    fn exec(
        &self,
        _rootfs: Option<&Path>,
        _runtimes: &[PathBuf],
        spec: RunSpec,
        _workdir: Option<&Path>,
    ) -> PyResult<Status> {
        println!("Sandbox.exec called with spec: {:#?}", spec);
        Ok(Status {
            cpu_time_used_ms: spec.cpu_time_limit_ms.unwrap_or(0),
            wall_time_used_ms: spec.wall_time_limit_ms.unwrap_or(0),
            memory_used_bytes: spec.memory_limit_bytes.unwrap_or(0),
            status: "AC".to_string(),
            signal: 0,
            exit_code: 0,
        })
    }
}

/// Build the backend matching the platform this extension was compiled for.
#[cfg(target_os = "linux")]
pub(crate) fn platform_backend() -> Box<dyn Backend> {
    Box::new(super::linux::Linux)
}

#[cfg(target_os = "macos")]
pub(crate) fn platform_backend() -> Box<dyn Backend> {
    Box::new(super::macos::Macos)
}

#[cfg(target_os = "windows")]
pub(crate) fn platform_backend() -> Box<dyn Backend> {
    Box::new(super::windows::Windows)
}
