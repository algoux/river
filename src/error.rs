use libc::strerror;
use serde_json::Error as SerdeJsonError;
use std::ffi::{CStr, NulError};
use std::fmt::Formatter;
use std::io::Error as IOError;
use std::{fmt, result};

#[cfg(target_os = "windows")]
use windows::core::Error as WIN_ERROR;

#[derive(Debug)]
pub enum Error {
    S(String),
    E(String, u32, String),
    IOError(IOError),
    SerdeJsonError(SerdeJsonError),
    /// Windows 平台下的 LastError
    #[cfg(target_os = "windows")]
    WinError(String, u32, WIN_ERROR),
    #[cfg(target_os = "linux")]
    LinuxError(String, u32, Option<i32>),
    #[cfg(target_os = "linux")]
    StringToCStringError(NulError),
}

pub type Result<T> = result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Error::E(ref filename, ref line, ref e) => {
                write!(f, "{}:{}: Error: {}", filename, line, e)
            }
            Error::S(ref e) => {
                write!(f, "{}", e)
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
            #[cfg(target_os = "linux")]
            Error::LinuxError(ref filename, ref line, errno) => {
                write!(f, "{}:{}: Error: {}", filename, line, errno_str(errno))
            }
            _ => {
                write!(f, "{}", self)
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub fn errno_str(errno: Option<i32>) -> String {
    match errno {
        Some(no) => {
            let stre = unsafe { strerror(no) };
            let c_str: &CStr = unsafe { CStr::from_ptr(stre) };
            c_str.to_str().unwrap().to_string()
        }
        _ => String::from("Unknown Error!"),
    }
}
