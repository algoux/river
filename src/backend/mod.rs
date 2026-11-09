#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub mod common;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "windows")]
pub mod windows;
