//! macOS backend — **not implemented yet**.
//!
//! Kept so `river.capabilities()` and `river.doctor()` report a coherent
//! platform matrix instead of the generic "unsupported" fallback. `run()`
//! raises `NotImplementedError` rather than pretending to sandbox anything.

pub mod sandbox;

use crate::backend::{Capabilities, DoctorValue};
use crate::contract::SafetyCeilings;

pub use sandbox::Sandbox;

/// Capability matrix of the (unimplemented) macOS backend.
pub(crate) fn capabilities() -> Capabilities {
    let ceilings = SafetyCeilings::default();
    Capabilities {
        platform: "macos",
        rootfs: false,
        default_max_processes: ceilings.max_processes,
        internal_wall_limit_secs: ceilings.wall_limit.as_secs(),
        // Placeholder: no implementation, so no meaningful ceiling to report.
        max_concurrent_runs: u32::MAX,
    }
}

/// macOS has no backend mechanisms to probe; report the missing backend as a
/// blocking problem.
pub(crate) fn doctor() -> Vec<(&'static str, DoctorValue)> {
    vec![
        ("platform", DoctorValue::Str("macos".into())),
        ("ok", DoctorValue::Bool(false)),
        (
            "errors",
            DoctorValue::List(vec!["macOS backend not implemented".into()]),
        ),
        ("warnings", DoctorValue::List(Vec::new())),
    ]
}
