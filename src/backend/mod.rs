//! Platform backends. Each backend implements the sandbox *mechanisms*
//! (process isolation, resource limits, stdio plumbing) and reports what it
//! observed as a [`crate::contract::verdict::RunEvidence`]; the verdict is
//! always synthesized by the shared contract.

/// Platform capability matrix (the frozen `river.capabilities()` contract).
#[derive(Clone, Copy)]
pub(crate) struct Capabilities {
    pub platform: &'static str,
    pub rootfs: bool,
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
    #[cfg(target_os = "linux")]
    {
        linux::capabilities()
    }
    #[cfg(target_os = "macos")]
    {
        macos::capabilities()
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        Capabilities {
            platform: "unsupported",
            rootfs: false,
            default_max_processes: 0,
            internal_wall_limit_secs: 0,
        }
    }
}

/// A value in a `river.doctor()` report.
pub(crate) enum DoctorValue {
    Bool(bool),
    Str(String),
    List(Vec<String>),
}

/// Environment facts / self-check for the compiled-in backend.
pub(crate) fn doctor() -> Vec<(&'static str, DoctorValue)> {
    #[cfg(target_os = "linux")]
    {
        linux::doctor()
    }
    #[cfg(target_os = "windows")]
    {
        windows::doctor()
    }
    #[cfg(target_os = "macos")]
    {
        macos::doctor()
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        vec![
            ("platform", DoctorValue::Str("unsupported".into())),
            ("ok", DoctorValue::Bool(false)),
            (
                "errors",
                DoctorValue::List(vec!["backend not implemented".into()]),
            ),
            ("warnings", DoctorValue::List(Vec::new())),
        ]
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
