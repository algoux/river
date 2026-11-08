//! ACL grant primitives: expose host directories to the AppContainer.
//!
//! Granting is a **merge**: the explicit ACE for the AppContainer SID is
//! added to the existing DACL (nothing else is touched), and it is marked
//! inheritable so files created by the sandboxed program inside the granted
//! directory are covered automatically.
//!
//! Two grant levels exist, matching the frozen filesystem model (DESIGN.md):
//! - `grant_rw` — the per-run working directory: read/write/execute, with
//!   **no** DELETE / WRITE_DAC / WRITE_OWNER bits;
//! - `grant_ro` — runtime directories: read/execute only.
//!
//! Grants are idempotent: an identical ACE (same SID, same mask) is detected
//! and not duplicated, so re-granting a `runtimes` directory on every run
//! never grows its DACL.
//!
//! Concurrency: the DACL update is a **read-modify-write** and is not
//! atomic — two threads granting the same directory concurrently can lose
//! one of the ACEs (last writer wins). All grants are therefore serialized
//! through a process-global lock: the operation is a couple of microseconds,
//! and correctness beats parallelism here.

use std::io;
use std::path::Path;
use std::sync::Mutex;

use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    BuildTrusteeWithSidW, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, EqualSid, GetAce, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_DELETE_CHILD, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
};

/// Serializes DACL read-modify-write cycles (see module docs).
static GRANT_LOCK: Mutex<()> = Mutex::new(());

/// Windows SDK `ACCESS_ALLOWED_ACE` (header, then mask, then the SID bytes).
#[repr(C)]
struct AccessAllowedAce {
    ace_type: u8,
    ace_flags: u8,
    ace_size: u16,
    mask: u32,
    sid_start: u32, // SID bytes follow inline
}

/// Read + write + execute over the directory and its children.
///
/// Deliberately excludes DELETE (the program must not delete the working
/// directory itself out from under cleanup), WRITE_DAC and WRITE_OWNER.
const CWD_GRANT_RIGHTS: u32 = FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE;

/// Read + execute only: no write, no delete.
const RUNTIMES_GRANT_RIGHTS: u32 = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;

/// Rights granted on a protected `copy_in` entry: read + execute only.
const INPUT_READ_RIGHTS: u32 = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;

const CONTAINER_AND_OBJECT_INHERIT: u32 = 0x3; // CONTAINER|OBJECT INHERIT_ACE
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;

fn win32_error(code: u32) -> io::Error {
    io::Error::from_raw_os_error(code as i32)
}

/// Merge an explicit grant ACE for `sid` into the DACL of `path`.
///
/// The existing DACL is read first (`GetNamedSecurityInfoW`), the explicit
/// entry is merged in (`SetEntriesInAclW`) and written back
/// (`SetNamedSecurityInfoW`). Requires WRITE_DAC on `path` — true for
/// directories the judger itself created, and for `runtimes` directories
/// owned by the same user. No elevation needed.
pub(crate) fn grant(path: &Path, sid: PSID, rights: u32) -> io::Result<()> {
    // Serialize the whole check-then-modify cycle: concurrent grants on the
    // same path would otherwise race on the DACL (lost ACE).
    let _guard = GRANT_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    if ace_present(path, sid, rights, ACCESS_ALLOWED_ACE_TYPE)? {
        return Ok(());
    }
    apply_entry(
        path,
        sid,
        rights,
        GRANT_ACCESS,
        CONTAINER_AND_OBJECT_INHERIT,
    )
}

/// Replace a `copy_in` entry's DACL with a **protected**, read-only one.
///
/// The sandboxed token carries the judger's user SID *and* the AppContainer
/// package SID, and the AppContainer access check accepts either. An
/// inherited user ACE granting write therefore still allowed modifying the
/// input — a package-SID deny ACE alone did **not** stop `chmod`+write
/// (verified). The fix is to drop inheritance and grant exactly read/execute
/// to both identities: no write, no `WRITE_ATTRIBUTES` (the chmod vector),
/// no `WRITE_DAC`.
///
/// Deletion/rename are already impossible: the program has no DELETE on the
/// entry and `CWD_GRANT_RIGHTS` deliberately excludes `FILE_DELETE_CHILD`.
pub(crate) fn protect_read_only(path: &Path, app_sid: PSID, inheritable: bool) -> io::Result<()> {
    let _guard = GRANT_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let user_sid = crate::backend::windows::token::current_user_sid()?;
    // Directories pass their read-only ACL down to the whole provisioned
    // tree (one DACL write instead of one per file: a 200-file input cost
    // ~100 ms with per-file writes).
    let inheritance = if inheritable {
        CONTAINER_AND_OBJECT_INHERIT
    } else {
        0
    };
    // A protected directory needs `FILE_DELETE_CHILD` for the judger,
    // otherwise its own cleanup cannot remove the (read-only) entries inside
    // it and every run leaks a workdir. The sandboxed identity is the same
    // user SID, so the program may also delete entries inside the input
    // tree — accepted semantics: the *content* stays immutable, deletion of
    // its own input leaks nothing (same rule as the Linux backend).
    let user_rights = if inheritable {
        INPUT_READ_RIGHTS | FILE_DELETE_CHILD
    } else {
        INPUT_READ_RIGHTS
    };
    let entries = [
        grant_entry(app_sid, INPUT_READ_RIGHTS, inheritance),
        grant_entry(user_sid.as_ptr() as PSID, user_rights, inheritance),
    ];

    let wide = crate::backend::windows::token::wide_of(path);
    let mut new_dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: entries are valid; a null old ACL asks for a fresh one;
    // out-pointer is valid.
    let err = unsafe {
        SetEntriesInAclW(
            entries.len() as u32,
            entries.as_ptr(),
            std::ptr::null(),
            &mut new_dacl,
        )
    };
    if err != 0 {
        return Err(win32_error(err));
    }
    // SAFETY: wide string is NUL-terminated; new_dacl is valid.
    let err = unsafe {
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
    // SAFETY: allocated by SetEntriesInAclW above.
    unsafe { LocalFree(new_dacl as HLOCAL) };
    if err != 0 {
        return Err(win32_error(err));
    }
    Ok(())
}

fn grant_entry(sid: PSID, rights: u32, inheritance: u32) -> EXPLICIT_ACCESS_W {
    let mut trustee: TRUSTEE_W = unsafe { std::mem::zeroed() };
    // SAFETY: trustee is zeroed; sid is valid for the duration of the call.
    unsafe { BuildTrusteeWithSidW(&mut trustee, sid as _) };
    EXPLICIT_ACCESS_W {
        grfAccessPermissions: rights,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: inheritance,
        Trustee: trustee,
    }
}

/// Merge one explicit ACE into `path`'s DACL. The caller holds `GRANT_LOCK`.
fn apply_entry(path: &Path, sid: PSID, rights: u32, mode: i32, inheritance: u32) -> io::Result<()> {
    let wide = crate::backend::windows::token::wide_of(path);
    let (dacl, sd) = read_dacl(&wide)?;

    let mut trustee: TRUSTEE_W = unsafe { std::mem::zeroed() };
    // SAFETY: trustee is zeroed and valid; sid is owned by the caller and
    // valid for the duration of the call below.
    unsafe { BuildTrusteeWithSidW(&mut trustee, sid as _) };

    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: rights,
        grfAccessMode: mode,
        grfInheritance: inheritance,
        Trustee: trustee,
    };
    let mut new_dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: entry and old DACL are valid; out-pointer is valid.
    let err = unsafe { SetEntriesInAclW(1, &entry, dacl, &mut new_dacl) };
    let merge_err = if err != 0 {
        Some(win32_error(err))
    } else {
        None
    };

    let err = if merge_err.is_none() {
        // SAFETY: wide string is NUL-terminated; new_dacl is valid.
        unsafe {
            SetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                new_dacl,
                std::ptr::null(),
            )
        }
    } else {
        0
    };
    let write_err = if err != 0 {
        Some(win32_error(err))
    } else {
        None
    };

    // SAFETY: both were allocated by the calls above (new_dacl by
    // SetEntriesInAclW, sd by GetNamedSecurityInfoW) and freed with LocalFree.
    unsafe {
        if !new_dacl.is_null() {
            LocalFree(new_dacl as HLOCAL);
        }
        if !sd.is_null() {
            LocalFree(sd as HLOCAL);
        }
    }

    merge_err.or(write_err).map_or(Ok(()), Err)
}

/// Grant the per-run working directory (read/write/execute).
pub(crate) fn grant_rw(path: &Path, sid: PSID) -> io::Result<()> {
    grant(path, sid, CWD_GRANT_RIGHTS)
}

/// Grant a runtime directory (read/execute only).
pub(crate) fn grant_ro(path: &Path, sid: PSID) -> io::Result<()> {
    grant(path, sid, RUNTIMES_GRANT_RIGHTS)
}

/// Read the DACL of `path`; returns `(dacl, security_descriptor)` where the
/// descriptor backs the DACL's memory and must be `LocalFree`d by the caller.
fn read_dacl(wide: &[u16]) -> io::Result<(*mut ACL, PSECURITY_DESCRIPTOR)> {
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: wide string is NUL-terminated; out-pointers are valid.
    let err = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if err != 0 {
        return Err(win32_error(err));
    }
    Ok((dacl, sd))
}

/// True when `path`'s DACL already carries an ACE of `ace_type` with exactly
/// `rights` for `sid` (the idempotency check, for allow and deny entries).
fn ace_present(path: &Path, sid: PSID, rights: u32, ace_type: u8) -> io::Result<bool> {
    let wide = crate::backend::windows::token::wide_of(path);
    let (dacl, sd) = read_dacl(&wide)?;

    let mut found = false;
    if !dacl.is_null() {
        // SAFETY: dacl is valid; ace walks its own AceCount entries.
        let count = unsafe { (*dacl).AceCount } as u32;
        for i in 0..count {
            let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
            let ok = unsafe { GetAce(dacl, i, &mut ace) };
            if ok == 0 || ace.is_null() {
                continue;
            }
            // SAFETY: GetAce returned a pointer to an ACE with this layout.
            let (entry_type, mask, ace_sid) = unsafe {
                let body = ace as *const AccessAllowedAce;
                (
                    (*body).ace_type,
                    (*body).mask,
                    &(*body).sid_start as *const u32 as PSID,
                )
            };
            if entry_type == ace_type && mask == rights {
                // SAFETY: both SIDs are valid and well-formed.
                if unsafe { EqualSid(ace_sid, sid as _) } != 0 {
                    found = true;
                    break;
                }
            }
        }
    }
    // SAFETY: sd was allocated by GetNamedSecurityInfoW.
    unsafe { LocalFree(sd as HLOCAL) };
    Ok(found)
}
