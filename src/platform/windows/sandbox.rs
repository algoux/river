use std::path::PathBuf;

use pyo3::prelude::*;
use pyo3::types::PyAny;

use crate::status::Status;

#[pyclass(module = "river")]
pub struct Sandbox {
    pub rootfs: Option<PathBuf>,
}

#[pymethods]
impl Sandbox {
    #[new]
    #[pyo3(signature = (rootfs=None))]
    fn new(rootfs: Option<PathBuf>) -> Self {
        Self { rootfs }
    }

    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __exit__(
        &self,
        _exc_type: &Bound<'_, PyAny>,
        _exc_value: &Bound<'_, PyAny>,
        _traceback: &Bound<'_, PyAny>,
    ) -> bool {
        false
    }

    fn run(&self, _executable: PathBuf) -> PyResult<Status> {
        Ok(Status::default())
    }

    fn __repr__(&self) -> String {
        match &self.rootfs {
            Some(rootfs) => {
                format!("Sandbox(rootfs={:?})", rootfs.display().to_string())
            }
            None => "Sandbox()".to_owned(),
        }
    }
}
