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
use pyo3::types::PyDict;

/// Platform capability matrix for the running interpreter (introspection for
/// the caller / OJ scheduler layer, so it never needs try/except probing).
///
/// Keys (frozen contract):
/// - `platform`: `"windows" | "linux" | "macos"`
/// - `rootfs`: whether `Sandbox(rootfs=...)` is supported
/// - `default_max_processes`: default live-process cap per run
/// - `internal_wall_limit_secs`: the safety wall-clock ceiling for
///   caller-unlimited runs
/// - `max_concurrent_runs`: hard ceiling on simultaneously running `run()`
///   calls per session (`4294967295` = no fixed ceiling; Windows reports
///   its AppContainer profile slot pool size here)
#[pyfunction]
fn capabilities(py: Python<'_>) -> PyResult<Py<PyDict>> {
    let caps = backend::capabilities();
    let dict = PyDict::new(py);
    dict.set_item("platform", caps.platform)?;
    dict.set_item("rootfs", caps.rootfs)?;
    dict.set_item("default_max_processes", caps.default_max_processes)?;
    dict.set_item("internal_wall_limit_secs", caps.internal_wall_limit_secs)?;
    dict.set_item("max_concurrent_runs", caps.max_concurrent_runs)?;
    Ok(dict.unbind())
}

/// Kernel / cgroup / seccomp / filesystem facts for deployment diagnosis.
///
/// Returns a dict with `platform`, `ok`, `errors` (list of blocking
/// problems), `warnings` (list of non-blocking caveats) and
/// platform-specific keys (Linux: `kernel`, `cgroup_root`, `cgroups_v2`,
/// `controllers`, `memory_peak`, `memory_swap_max`, `cgroup_kill`, `seccomp`,
/// `seccomp_actions`, `userns_allowed`, `workdir_root`; Windows:
/// `app_container`, `job_object`, `workdir_root`).
///
/// `Sandbox(...)` runs the same checks and fails closed when `ok` is false.
#[pyfunction]
fn doctor(py: Python<'_>) -> PyResult<Py<PyDict>> {
    let dict = PyDict::new(py);
    for (name, value) in backend::doctor() {
        match value {
            backend::DoctorValue::Bool(v) => dict.set_item(name, v)?,
            backend::DoctorValue::Str(v) => dict.set_item(name, v)?,
            backend::DoctorValue::List(v) => dict.set_item(name, v)?,
        }
    }
    Ok(dict.unbind())
}

#[pymodule]
mod river {
    #[pymodule_export]
    use super::capabilities;
    #[pymodule_export]
    use super::doctor;

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
