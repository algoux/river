use libc::strerror;
use std::ffi::CStr;

pub fn errno_str(errno: Option<i32>) -> String {
    match errno {
        Some(no) => {
            let str_e = unsafe { strerror(no) };
            let c_str: &CStr = unsafe { CStr::from_ptr(str_e) };
            if let Ok(s) = c_str.to_str() {
                s
            } else {
                "cstr to str Error!"
            }
            .to_string()
        }
        _ => String::from("Unknown Error!"),
    }
}

pub fn last_err() -> String {
    errno_str(std::io::Error::last_os_error().raw_os_error())
}
