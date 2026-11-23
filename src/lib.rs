//! Native half of river (`river._river`). The public API is assembled in
//! `python/river/__init__.py`; import `river` instead of this module.

mod api;
mod cgroup;
mod preflight;

use pyo3::prelude::*;

/// Native half of river; import `river` instead.
#[pymodule]
mod _river {
    #[pymodule_export]
    use super::api::{
        CgroupNotDelegatedError, CopyOutError, ExecResult, ExecSetupError, KernelTooOldError, River,
        RiverError, RootfsError, UserNamespaceDeniedError,
    };

    #[pymodule_export]
    use super::preflight::run_doctor_checks;
}
