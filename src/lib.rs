mod backend;
mod contract;

use pyo3::prelude::*;

#[pymodule]
mod river {
    #[cfg(target_os = "linux")]
    #[pymodule_export]
    use super::backend::linux::Sandbox;
    #[cfg(target_os = "macos")]
    #[pymodule_export]
    use super::backend::macos::Sandbox;
    #[cfg(target_os = "windows")]
    #[pymodule_export]
    use super::backend::windows::Sandbox;

    #[pymodule_export]
    use super::contract::status::Status;
}
