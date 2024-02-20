#[cfg(target_os = "macos")]
use sys::macos::S;
#[cfg(target_os = "linux")]
use sys::linux::S;
#[cfg(target_os = "windows")]
use sys::windows::S;

use crate::sys::Sys;

mod sys;

fn main() {
    S::run();
}
