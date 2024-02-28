use crate::Opts;
use crate::status::Status;

use super::error::Result;

#[cfg(target_os = "linux")]
pub(crate) mod linux;
#[cfg(target_os = "macos")]
pub(crate) mod macos;
#[cfg(target_os = "windows")]
pub(crate) mod windows;

pub trait SandboxImpl {
    fn with_opts(opts: Opts) -> Self;

    /**
     * run
     */
    unsafe fn run(&mut self) -> Result<Status>;
}
