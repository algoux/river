//! river — sandbox for untrusted executables, as a Python extension in Rust.
//!
//! Layout (design §architecture):
//! - [`contract`] — the frozen, platform-neutral API contract: `RunSpec`
//!   validation, `RunEvidence` → `Verdict` classification (a pure function),
//!   and the `Status` pyclass. No platform code may leak in here; platform
//!   backends *translate their mechanisms into evidence*.
//! - [`backend`] — platform backends. Each backend implements the mechanisms
//!   (process isolation, resource limits, stdio) and reports its findings as
//!   [`contract::verdict::RunEvidence`]; the verdict itself is always
//!   synthesized by the shared contract so the "evidence beats exit code"
//!   rule is written and tested exactly once.

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
