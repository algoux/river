mod platform;
mod status;

#[pyo3::pymodule]
mod river {
    #[cfg(target_os = "linux")]
    #[pymodule_export]
    use super::platform::linux::Sandbox;
    #[cfg(target_os = "macos")]
    #[pymodule_export]
    use super::platform::macos::Sandbox;
    #[cfg(target_os = "windows")]
    #[pymodule_export]
    use super::platform::windows::Sandbox;

    #[pymodule_export]
    use super::status::Status;
}
