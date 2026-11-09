//! Windows backend: AppContainer + Job Object (see `examples/windows_*`).

use std::path::{Path, PathBuf};

use pyo3::prelude::*;

use crate::backend::common::Backend;

/// Placeholder Windows backend; the AppContainer + Job Object mechanics
/// land here when implemented.
pub(crate) struct Windows;

impl Backend for Windows {
    /// Windows has no pivot-root equivalent, so a private root filesystem
    /// cannot be provided: expose read-only runtime directories instead.
    fn validate_new(&self, rootfs: Option<&Path>, _runtimes: &[PathBuf]) -> PyResult<()> {
        if rootfs.is_some() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "rootfs is not supported on Windows; use runtimes=[...] to expose \
                 read-only runtime directories instead",
            ));
        }
        Ok(())
    }

    fn exec(
        &self,
        _rootfs: Option<&Path>,
        _runtimes: &[PathBuf],
        _spec: crate::contract::RunSpec,
        _workdir: Option<&Path>,
    ) -> PyResult<crate::contract::status::Status> {
        println!("Sandbox.exec called with workdir: {:#?}", _workdir);
        Ok(Default::default())
    }
}
