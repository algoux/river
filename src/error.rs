use serde_json::Error as SerdeJsonError;
use std::fmt::Formatter;
use std::io::Error as IOError;
use std::{fmt, result};

#[cfg(target_os = "windows")]
use windows::core::Error as WIN_ERROR;

#[derive(Debug)]
pub enum Error {
    E(String, u32, String),
    IOError(IOError),
    SerdeJsonError(SerdeJsonError),
    /// Windows 平台下的 LastError
    #[cfg(target_os = "windows")]
    WinError(String, u32, WIN_ERROR),
}

pub type Result<T> = result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Error::E(ref filename, ref line, ref e) => {
                write!(f, "{}:{}: Error: {}", filename, line, e)
            }
            Error::IOError(ref e) => {
                write!(f, "{}", e)
            }
            Error::SerdeJsonError(ref e) => {
                write!(f, "{}", e)
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
