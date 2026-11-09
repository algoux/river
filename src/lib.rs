mod backend;
mod contract;

use pyo3::prelude::*;

#[pymodule]
mod river {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[pymodule_export]
    use super::backend::common::Sandbox;

    #[pymodule_export]
    use super::contract::status::Status;
}
