//! Windows backend: AppContainer (identity & filesystem) + Job Object
//! (resources & process tree) + mitigation policies (kernel attack surface).
//! See docs/windows-backend.md for the decision log and measured pitfalls.

pub mod acl;
pub mod job;
pub mod monitor;
pub mod ntstatus;
pub mod sandbox;
pub mod spawn;
pub mod stdio;
pub mod token;
pub mod workdir;

use crate::backend::{Capabilities, DoctorValue};
use crate::contract::SafetyCeilings;

pub use sandbox::Sandbox;

/// Environment facts. The doctor is primarily a Linux deployment tool; the
/// Windows backend reports the basics so `river.doctor()` stays callable.
pub(crate) fn doctor() -> Vec<(&'static str, DoctorValue)> {
    vec![
        ("platform", DoctorValue::Str("windows".into())),
        ("ok", DoctorValue::Bool(true)),
        ("errors", DoctorValue::List(Vec::new())),
        (
            "note",
            DoctorValue::Str(
                "doctor() reports Linux backend facts; the Windows backend is not instrumented"
                    .into(),
            ),
        ),
    ]
}

/// Capability matrix of the Windows backend.
pub(crate) fn capabilities() -> Capabilities {
    let ceilings = SafetyCeilings::default();
    Capabilities {
        platform: "windows",
        rootfs: false, // Windows processes always load system DLLs from the real System32
        network_isolation: true, // AppContainer: no capability => no network
        concurrent_runs: true, // Sandbox is frozen; every run keeps its state in locals
        default_max_processes: ceilings.max_processes,
        internal_wall_limit_secs: ceilings.wall_limit.as_secs(),
    }
}
