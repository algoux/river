//! Windows backend: AppContainer (identity & filesystem) + Job Object
//! (resources & process tree) + mitigation policies (kernel attack surface).
//! See docs/windows-backend.md for the decision log and measured pitfalls.

pub mod acl;
pub mod job;
pub mod monitor;
pub mod ntstatus;
pub mod profile;
pub mod sandbox;
pub mod spawn;
pub mod stdio;
pub mod token;
pub mod workdir;

use crate::backend::{Capabilities, DoctorValue};
use crate::contract::SafetyCeilings;

pub use sandbox::Sandbox;

/// Environment facts and a real self-check.
///
/// Unlike the Linux backend this cannot probe for "missing mechanisms" (the
/// AppContainer / Job Object APIs are part of Windows), but it does exercise
/// the machinery the sandbox depends on: a throwaway AppContainer profile
/// (created and deleted), a Job Object with limits, and a writable workdir.
pub(crate) fn doctor() -> Vec<(&'static str, DoctorValue)> {
    let mut errors: Vec<String> = Vec::new();

    let profile_ok = match token::profile_check() {
        Ok(()) => true,
        Err(e) => {
            errors.push(format!("AppContainer profile check failed: {e}"));
            false
        }
    };
    let job_ok = match job::Job::new(&job::JobLimits {
        memory_limit_bytes: Some(64 * 1024 * 1024),
        max_processes: 8,
    }) {
        Ok(_) => true,
        Err(e) => {
            errors.push(format!("Job Object check failed: {e}"));
            false
        }
    };
    let workdir_root = std::env::temp_dir();
    let workdir_ok = probe_workdir(&workdir_root).is_ok();
    if !workdir_ok {
        errors.push(format!(
            "workdir root {} is not writable",
            workdir_root.display()
        ));
    }

    vec![
        ("platform", DoctorValue::Str("windows".into())),
        ("app_container", DoctorValue::Bool(profile_ok)),
        ("job_object", DoctorValue::Bool(job_ok)),
        (
            "workdir_root",
            DoctorValue::Str(workdir_root.display().to_string()),
        ),
        ("ok", DoctorValue::Bool(errors.is_empty())),
        ("errors", DoctorValue::List(errors)),
    ]
}

fn probe_workdir(root: &std::path::Path) -> std::io::Result<()> {
    let dir = root.join(format!("river-doctor-{}", std::process::id()));
    std::fs::create_dir(&dir)?;
    std::fs::remove_dir(&dir)
}

/// Capability matrix of the Windows backend.
pub(crate) fn capabilities() -> Capabilities {
    let ceilings = SafetyCeilings::default();
    Capabilities {
        platform: "windows",
        rootfs: false, // Windows processes always load system DLLs from the real System32
        default_max_processes: ceilings.max_processes,
        internal_wall_limit_secs: ceilings.wall_limit.as_secs(),
    }
}
