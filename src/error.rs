use std::fmt::Formatter;
use std::{fmt, result};

#[cfg(target_os = "windows")]
use windows::Win32::Foundation::WIN32_ERROR;

#[allow(dead_code)]
#[derive(Debug)]
pub enum Error {
    /// Windows 平台下的 LastError
    #[cfg(target_os = "windows")]
    WinError(WIN32_ERROR),
}

pub type Result<T> = result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Error::WinError(ref e) => {
                write!(
                    f,
                    "Windows API Error: {}",
                    WIN32_ERROR(e.0).to_hresult().message()
                )
            }
        }
    }
}
