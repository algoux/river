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
//! [`protect_read_only`] is the exception to "merge": a `copy_in` entry must
//! not inherit the workdir's read/write ACE, so its DACL is **replaced** by a
//! protected read-only one (the sandboxed identity reads, the judger keeps
//! enough to clean the entry up).
//!
//! DACL updates are read-modify-write and therefore serialized process-wide.

use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use windows_sys::Win32::Foundation::{HANDLE, HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ACCESS_MODE, BuildTrusteeWithSidW, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW,
    REVOKE_ACCESS, SE_FILE_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACE_FLAGS, ACL, CONTAINER_INHERIT_ACE, CopySid, DACL_SECURITY_INFORMATION, GetLengthSid,
    GetTokenInformation, NO_INHERITANCE, OBJECT_INHERIT_ACE, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_DELETE_CHILD, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

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

/// Replaces `path`'s DACL with a **protected**, read-only one.
///
/// `copy_in` copies are created below the workdir and would inherit its
/// read/write grant for the sandboxed identity. Merging a read-only ACE does
/// not remove that inherited grant, so the whole DACL is replaced instead:
/// the AppContainer SID gets read/execute only, and the judger's own SID gets
/// read/execute plus `FILE_DELETE_CHILD` on directories so the session
/// cleanup can remove the protected entries. No write and no
/// `WRITE_ATTRIBUTES` means the program cannot modify, chmod or delete its
/// own input.
///
/// A directory's ACE is inheritable, so the whole provisioned tree is
/// protected with one DACL write.
pub(crate) fn protect_read_only(path: &Path, app_sid: PSID, inheritable: bool) -> io::Result<()> {
    let _guard = DACL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let user_sid = current_user_sid()?;
    let inheritance = if inheritable {
        DIRECTORY_INHERIT
    } else {
        NO_INHERITANCE
    };
    let user_rights = if inheritable {
        READ_EXECUTE | FILE_DELETE_CHILD
    } else {
        READ_EXECUTE
    };
    let entries = [
        explicit_access(app_sid, READ_EXECUTE, GRANT_ACCESS, inheritance),
        explicit_access(
            user_sid.as_ptr() as PSID,
            user_rights,
            GRANT_ACCESS,
            inheritance,
        ),
    ];

    let mut new_dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: the entries are valid; a null old ACL asks for a fresh one; the
    // out-pointer is valid.
    let error = unsafe {
        SetEntriesInAclW(
            entries.len() as u32,
            entries.as_ptr(),
            std::ptr::null(),
            &mut new_dacl,
        )
    };
    if error != 0 {
        return Err(win32_error(error));
    }

    let wide = wide_of(path);
    // SAFETY: `wide` is NUL-terminated and `new_dacl` is a valid ACL.
    let error = unsafe {
        SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            new_dacl,
            std::ptr::null(),
        )
    };
    // SAFETY: allocated by SetEntriesInAclW above and must be freed with
    // LocalFree.
    unsafe { LocalFree(new_dacl as HLOCAL) };
    if error != 0 {
        Err(win32_error(error))
    } else {
        Ok(())
    }
}

/// The judger's own user SID, copied out of the process token and cached.
///
/// The protected `copy_in` DACL needs an explicit ACE for it: the AppContainer
/// token carries the user SID too, but the lowbox access check is driven by
/// the package SID, so this ACE is what lets the judger clean the entry up.
fn current_user_sid() -> io::Result<&'static [u8]> {
    static CACHE: OnceLock<Vec<u8>> = OnceLock::new();
    if let Some(sid) = CACHE.get() {
        return Ok(sid.as_slice());
    }
    let sid = query_current_user_sid()?;
    let _ = CACHE.set(sid);
    Ok(CACHE
        .get()
        .expect("the user SID was just cached")
        .as_slice())
}

fn query_current_user_sid() -> io::Result<Vec<u8>> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: the process pseudo-handle is valid and `token` is an out-pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `token` is a fresh, owned handle.
    let token = unsafe { OwnedHandle::from_raw_handle(token as RawHandle) };

    let mut needed = 0u32;
    // SAFETY: the first call only queries the required buffer size.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle() as HANDLE,
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut needed,
        );
    };
    if needed == 0 {
        return Err(io::Error::last_os_error());
    }

    // `u64` keeps the buffer aligned for `TOKEN_USER` (it starts with a
    // pointer).
    let mut buffer = vec![0u64; (needed as usize).div_ceil(std::mem::size_of::<u64>())];
    let mut returned = 0u32;
    // SAFETY: the buffer is large enough for `needed` bytes and the token is
    // open for `TOKEN_QUERY`.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle() as HANDLE,
            TokenUser,
            buffer.as_mut_ptr() as *mut c_void,
            needed,
            &mut returned,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: the buffer holds a TOKEN_USER written by the API above.
    let user: TOKEN_USER =
        unsafe { std::ptr::read_unaligned(buffer.as_ptr() as *const TOKEN_USER) };
    // SAFETY: `user.User.Sid` points into the still-alive buffer.
    let length = unsafe { GetLengthSid(user.User.Sid) };
    if length == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut sid = vec![0u8; length as usize];
    // SAFETY: `sid` has room for `length` bytes and both SIDs are valid.
    if unsafe { CopySid(length, sid.as_mut_ptr() as PSID, user.User.Sid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(sid)
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

    let entry = explicit_access(sid, rights, mode, inheritance);

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

fn explicit_access(
    sid: PSID,
    rights: u32,
    mode: ACCESS_MODE,
    inheritance: ACE_FLAGS,
) -> EXPLICIT_ACCESS_W {
    let mut trustee: TRUSTEE_W = unsafe { std::mem::zeroed() };
    // SAFETY: `trustee` is zeroed; `BuildTrusteeWithSidW` points it at `sid`,
    // which stays valid for this call.
    unsafe { BuildTrusteeWithSidW(&mut trustee, sid) };
    EXPLICIT_ACCESS_W {
        grfAccessPermissions: rights,
        grfAccessMode: mode,
        grfInheritance: inheritance,
        Trustee: trustee,
    }
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
