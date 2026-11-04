//! Platform backends. Each backend implements the sandbox *mechanisms*
//! (process isolation, resource limits, stdio plumbing) and reports what it
//! observed as a [`crate::contract::verdict::RunEvidence`]; the verdict is
//! always synthesized by the shared contract.

/// Platform capability matrix (the frozen `river.capabilities()` contract).
#[derive(Clone, Copy)]
pub(crate) struct Capabilities {
    pub platform: &'static str,
    pub rootfs: bool,
    pub network_isolation: bool,
    pub concurrent_runs: bool,
    pub default_max_processes: u32,
    pub internal_wall_limit_secs: u64,
}

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "windows")]
pub mod windows;

/// Capability matrix of the backend compiled into this build.
pub(crate) fn capabilities() -> Capabilities {
    #[cfg(target_os = "windows")]
    {
        windows::capabilities()
    }
    #[cfg(not(target_os = "windows"))]
    {
        Capabilities {
            platform: "unsupported",
            rootfs: false,
            network_isolation: false,
            concurrent_runs: false,
            default_max_processes: 0,
            internal_wall_limit_secs: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The compiled-in backend must advertise itself with a usable matrix.
    #[test]
    fn capabilities_describe_the_built_backend() {
        let caps = capabilities();
        assert!(!caps.platform.is_empty());
        assert!(caps.default_max_processes > 0);
        assert!(caps.internal_wall_limit_secs > 0);
    }
}
