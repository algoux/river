//! Read-only (and scratch-directory) access for the AppContainer identity.
//!
//! The sandboxed child can only open a path when the path's DACL contains an
//! ACE for its AppContainer SID. [`grant_read_execute`] merges that ACE into
//! the existing DACL; [`revoke`] removes it again when the session ends, so a
//! sandbox does not leave its package SID behind on the host filesystem.
//!
//! Directory grants are inheritable (`CONTAINER | OBJECT`), which covers both
//! files that already exist below the directory and files created there
//! later. File grants use `NO_INHERITANCE`.
//!
//! DACL updates are read-modify-write and therefore serialized process-wide.

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::sync::Mutex;

use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ACCESS_MODE, BuildTrusteeWithSidW, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW,
    REVOKE_ACCESS, SE_FILE_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACE_FLAGS, ACL, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, NO_INHERITANCE,
    OBJECT_INHERIT_ACE, PSECURITY_DESCRIPTOR, PSID,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
};

/// Serializes the DACL read-modify-write cycles of this process.
static DACL_LOCK: Mutex<()> = Mutex::new(());

const READ_EXECUTE: u32 = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
const READ_WRITE_EXECUTE: u32 = FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE;
const DIRECTORY_INHERIT: ACE_FLAGS = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;

/// Grants `sid` read and execute access to `path`.
pub(crate) fn grant_read_execute(path: &Path, sid: PSID) -> io::Result<()> {
    grant(path, sid, READ_EXECUTE)
}

/// Grants `sid` read and execute access to `path` **without inheritance**.
/// Used on the parent directory of a file entry: the target can reach and
/// list that one directory, but the grant does not flow to sibling files
/// (their contents stay inaccessible without their own ACE).
pub(crate) fn grant_read_execute_no_inherit(path: &Path, sid: PSID) -> io::Result<()> {
    let _guard = DACL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    apply(path, sid, READ_EXECUTE, GRANT_ACCESS, NO_INHERITANCE)
}

/// Grants `sid` read, write and execute access to `path`.
pub(crate) fn grant_read_write_execute(path: &Path, sid: PSID) -> io::Result<()> {
    grant(path, sid, READ_WRITE_EXECUTE)
}

/// Removes every ACE that belongs to `sid` from `path`'s DACL.
pub(crate) fn revoke(path: &Path, sid: PSID) -> io::Result<()> {
    let _guard = DACL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    apply(path, sid, 0, REVOKE_ACCESS, NO_INHERITANCE)
}

fn grant(path: &Path, sid: PSID, rights: u32) -> io::Result<()> {
    let _guard = DACL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let inheritance = if path.is_dir() {
        DIRECTORY_INHERIT
    } else {
        NO_INHERITANCE
    };
    apply(path, sid, rights, GRANT_ACCESS, inheritance)
}

fn apply(
    path: &Path,
    sid: PSID,
    rights: u32,
    mode: ACCESS_MODE,
    inheritance: ACE_FLAGS,
) -> io::Result<()> {
    let wide = wide_of(path);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `wide` is NUL-terminated and every out-pointer is valid.
    let error = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if error != 0 {
        return Err(win32_error(error));
    }

    if dacl.is_null() {
        // A NULL DACL grants everyone full access. Replacing it with an ACL
        // that only contains our ACE would lock the owner out, so refuse to
        // touch it (revoking from it is a no-op by definition).
        // SAFETY: `descriptor` was allocated by GetNamedSecurityInfoW.
        unsafe { LocalFree(descriptor as HLOCAL) };
        return if mode == REVOKE_ACCESS {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "refusing to replace the NULL DACL of {}",
                path.display()
            )))
        };
    }

    let mut trustee: TRUSTEE_W = unsafe { std::mem::zeroed() };
    // SAFETY: `trustee` is zeroed; `BuildTrusteeWithSidW` points it at `sid`,
    // which stays valid for this call.
    unsafe { BuildTrusteeWithSidW(&mut trustee, sid) };
    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: rights,
        grfAccessMode: mode,
        grfInheritance: inheritance,
        Trustee: trustee,
    };

    let mut new_dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: `entry` and `dacl` are valid; `new_dacl` is an out-pointer.
    let error = unsafe { SetEntriesInAclW(1, &entry, dacl, &mut new_dacl) };
    let result = if error != 0 {
        Err(win32_error(error))
    } else {
        // SAFETY: `wide` is NUL-terminated and `new_dacl` is a valid ACL.
        let error = unsafe {
            SetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                new_dacl,
                std::ptr::null(),
            )
        };
        if error != 0 {
            Err(win32_error(error))
        } else {
            Ok(())
        }
    };

    // SAFETY: both blocks were allocated by the APIs above and must be freed
    // with LocalFree.
    unsafe {
        if !new_dacl.is_null() {
            LocalFree(new_dacl as HLOCAL);
        }
        LocalFree(descriptor as HLOCAL);
    }
    result
}

fn wide_of(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn win32_error(code: u32) -> io::Error {
    io::Error::from_raw_os_error(code as i32)
}
