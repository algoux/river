//! Linux backend: mount/pid/net/ipc/uts/cgroup namespaces (identity &
//! filesystem, unconditional network denial) + cgroups v2 (resources &
//! process tree) + seccomp allowlist + a judger-death watchdog. See
//! docs/linux-backend.md for the mechanism details and decision log.

pub mod cgroup;
pub mod monitor;
pub mod mount;
pub mod ns;
pub mod sandbox;
pub mod seccomp;
pub mod stdio;
pub mod workdir;

use crate::backend::{Capabilities, DoctorValue};
use crate::contract::SafetyCeilings;

pub use sandbox::Sandbox;

/// Capability matrix of the Linux backend.
pub(crate) fn capabilities() -> Capabilities {
    let ceilings = SafetyCeilings::default();
    Capabilities {
        platform: "linux",
        // A caller-supplied rootfs directory replaces the tmpfs root: it is
        // bind-mounted read-only and the program is pivoted into it.
        rootfs: true,
        default_max_processes: ceilings.max_processes,
        internal_wall_limit_secs: ceilings.wall_limit.as_secs(),
    }
}

/// Facts `doctor()` reports, plus the list of blocking problems (`ok` is
/// true only when `errors` is empty).
pub(crate) fn facts() -> Vec<(&'static str, DoctorValue)> {
    let root = cgroup::cgroup_root();
    let controllers = std::fs::read_to_string(root.join("cgroup.controllers"))
        .map(|s| s.split_whitespace().map(str::to_string).collect::<Vec<_>>())
        .unwrap_or_default();
    let seccomp_actions = std::fs::read_to_string("/proc/sys/kernel/seccomp/actions_avail")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let seccomp_ok = seccomp::program().is_ok() && !seccomp_actions.is_empty();

    // The cgroup probe runs inside the `river` subtree: controller files
    // like `memory.peak` are absent at the systemd root even when the kernel
    // supports them.
    let probe_errors = cgroup::probe();
    let has_cgroup_file = |errors: &[String], name: &str| !errors.iter().any(|e| e.contains(name));
    let cgroup_errors = probe_errors.clone();

    let mut errors = probe_errors;
    if !seccomp_ok {
        errors.push(format!(
            "seccomp filter unavailable (actions_avail={seccomp_actions:?})"
        ));
    }

    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    // User namespaces: `clone` is filtered (no CLONE_NEW* flags), but
    // `clone3` cannot be argument-inspected without breaking glibc's
    // pthread_create (EPERM is not an ENOSYS fallback). Warn unless the
    // host explicitly disables unprivileged creation. The AppArmor sysctl is
    // reported as a fact but is *not* treated as a guarantee: on Ubuntu
    // 24.04 with apparmor_restrict_unprivileged_userns=1 the sandboxed
    // process still created a userns (verified), so only the kernel knob
    // being 0 is trusted.
    let userns_sysctl = std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
        .ok()
        .map(|s| s.trim() == "1");
    let apparmor_restrict =
        std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
            .ok()
            .map(|s| s.trim() == "1");
    let userns_allowed = userns_sysctl != Some(false);
    let mut warnings = Vec::new();
    if userns_allowed {
        warnings.push(
            "clone3 can still create an unprivileged user namespace (glibc pthread_create \
             needs clone3); set kernel.unprivileged_userns_clone=0 if this matters"
                .to_string(),
        );
    }

    let mut out: Vec<(&'static str, DoctorValue)> = vec![
        ("platform", DoctorValue::Str("linux".into())),
        ("kernel", DoctorValue::Str(kernel)),
        ("cgroup_root", DoctorValue::Str(root.display().to_string())),
        (
            "cgroups_v2",
            DoctorValue::Bool(root.join("cgroup.controllers").exists()),
        ),
        ("controllers", DoctorValue::List(controllers)),
        (
            "memory_peak",
            DoctorValue::Bool(has_cgroup_file(&cgroup_errors, "memory.peak")),
        ),
        (
            "memory_swap_max",
            DoctorValue::Bool(has_cgroup_file(&cgroup_errors, "memory.swap.max")),
        ),
        (
            "cgroup_kill",
            DoctorValue::Bool(has_cgroup_file(&cgroup_errors, "cgroup.kill")),
        ),
        ("seccomp", DoctorValue::Bool(seccomp_ok)),
        ("seccomp_actions", DoctorValue::Str(seccomp_actions)),
        ("userns_allowed", DoctorValue::Bool(userns_allowed)),
        (
            "apparmor_userns_restrict",
            DoctorValue::Bool(apparmor_restrict.unwrap_or(false)),
        ),
        ("warnings", DoctorValue::List(warnings)),
        (
            "workdir_root",
            DoctorValue::Str(std::env::temp_dir().display().to_string()),
        ),
    ];
    out.push(("ok", DoctorValue::Bool(errors.is_empty())));
    out.push(("errors", DoctorValue::List(errors)));
    out
}

pub(crate) fn doctor() -> Vec<(&'static str, DoctorValue)> {
    facts()
}

/// Construction-time fail-closed check: every mechanism the limit contract
/// relies on must exist, otherwise `Sandbox(...)` fails instead of silently
/// degrading on the first `run()`.
pub(crate) fn preflight() -> Result<(), String> {
    let errors = doctor()
        .into_iter()
        .find_map(|(name, value)| match (name, value) {
            ("errors", DoctorValue::List(errors)) => Some(errors),
            _ => None,
        })
        .unwrap_or_default();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "river Linux backend cannot start on this host:\n  - {}",
            errors.join("\n  - ")
        ))
    }
}
