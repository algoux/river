#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use crate::sys::macos::*;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use crate::sys::linux::*;

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub use crate::sys::windows::*;
