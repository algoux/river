//! Child stdio inheritance.
//!
//! The sandbox does not capture output in this basic implementation: the
//! child inherits the caller's standard streams. The three handles are
//! duplicated as inheritable so the child still receives them when the
//! Python process itself was started with redirected (pipe/file) handles.
//! A missing stream falls back to the `NUL` device so `CreateProcessW` always
//! has three valid inheritable handles for `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`.

use std::io;
use std::os::windows::io::{FromRawHandle, OwnedHandle, RawHandle};

use windows_sys::Win32::Foundation::{
    DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

/// The three inheritable handles handed to the child, in the
/// stdin/stdout/stderr order used by `STARTUPINFOW`.
pub(crate) struct StdioSet {
    handles: [OwnedHandle; 3],
}

impl StdioSet {
    pub(crate) fn new() -> io::Result<Self> {
        Ok(StdioSet {
            handles: [
                duplicate_or_nul(STD_INPUT_HANDLE, false)?,
                duplicate_or_nul(STD_OUTPUT_HANDLE, true)?,
                duplicate_or_nul(STD_ERROR_HANDLE, true)?,
            ],
        })
    }

    pub(crate) fn into_handles(self) -> [OwnedHandle; 3] {
        self.handles
    }
}

fn duplicate_or_nul(std_handle: u32, write: bool) -> io::Result<OwnedHandle> {
    // SAFETY: GetStdHandle only reads the per-process std handle table.
    let source = unsafe { GetStdHandle(std_handle) };
    if source.is_null() || source == INVALID_HANDLE_VALUE {
        return open_nul(write);
    }

    let mut duplicate: HANDLE = std::ptr::null_mut();
    // SAFETY: both process pseudo-handles are valid, `source` is an open
    // handle, and `duplicate` is a valid out-pointer.
    let ok = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            source,
            GetCurrentProcess(),
            &mut duplicate,
            0,
            1, // bInheritHandle
            DUPLICATE_SAME_ACCESS,
        )
    };
    if ok == 0 || duplicate.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `duplicate` is a fresh, owned handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(duplicate as RawHandle) })
}

fn open_nul(write: bool) -> io::Result<OwnedHandle> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    let name: [u16; 4] = ['N' as u16, 'U' as u16, 'L' as u16, 0];
    let access = if write {
        FILE_GENERIC_WRITE
    } else {
        FILE_GENERIC_READ
    };
    // SAFETY: the name is NUL-terminated, `attributes` is valid, and the
    // returned handle is owned.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &attributes,
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `handle` is a fresh, owned handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) })
}
