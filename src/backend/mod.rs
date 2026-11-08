//! Platform backends. Each backend implements the sandbox *mechanisms*
//! (process isolation, resource limits, stdio plumbing) and reports what it
//! observed as a [`crate::contract::verdict::RunEvidence`]; the verdict is
//! always synthesized by the shared contract.

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "windows")]
pub mod windows;
