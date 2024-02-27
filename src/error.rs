use std::fmt::Formatter;
use std::{fmt, result};

#[cfg(target_os = "windows")]
use windows::core::Error as WIN_ERROR;

#[derive(Debug)]
pub enum Error {
    E(String, u32, String),
    /// Windows 平台下的 LastError
    #[cfg(target_os = "windows")]
    WinError(String, u32, WIN_ERROR),
}

pub type Result<T> = result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Error::E(ref filename, ref line, ref e) => {
                write!(
                    f,
                    "{}:{}: Error: {}",
                    filename,
                    line,
                    e
                )
            }
            #[cfg(target_os = "windows")]
            Error::WinError(ref filename, ref line, ref e) => {
                write!(
                    f,
                    "{}:{}: Windows API Error: {}",
                    filename,
                    line,
                    e.message()
                )
            }
        }
    }
}
