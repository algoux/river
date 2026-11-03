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
//! Concurrency (S12): the DACL update is a **read-modify-write** and is not
//! atomic — two threads granting the same directory concurrently can lose
//! one of the ACEs (last writer wins). All grants are therefore serialized
//! through a process-global lock: the operation is a couple of microseconds,
//! and correctness beats parallelism here.

use std::io;
use std::path::Path;
use std::sync::Mutex;

use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    BuildTrusteeWithSidW, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW,
    SE_FILE_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, EqualSid, GetAce, PSECURITY_DESCRIPTOR, PSID,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
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

    if ace_already_present(path, sid, rights)? {
        return Ok(());
    }

    let wide = crate::platform::windows::token::wide_of(path);
    let (dacl, sd) = read_dacl(&wide)?;

    let mut trustee: TRUSTEE_W = unsafe { std::mem::zeroed() };
    // SAFETY: trustee is zeroed and valid; sid is owned by the caller and
    // valid for the duration of the call below.
    unsafe { BuildTrusteeWithSidW(&mut trustee, sid as _) };

    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: rights,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: CONTAINER_AND_OBJECT_INHERIT,
        Trustee: trustee,
    };
    let mut new_dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: entry and old DACL are valid; out-pointer is valid.
    let err = unsafe { SetEntriesInAclW(1, &entry, dacl, &mut new_dacl) };
    let merge_err = if err != 0 { Some(win32_error(err)) } else { None };

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
    let write_err = if err != 0 { Some(win32_error(err)) } else { None };

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

/// True when `path`'s DACL already carries an ACCESS_ALLOWED ACE with exactly
/// `rights` for `sid` (the idempotency check).
fn ace_already_present(path: &Path, sid: PSID, rights: u32) -> io::Result<bool> {
    let wide = crate::platform::windows::token::wide_of(path);
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
            // SAFETY: GetAce returned a pointer to an ACCESS_ALLOWED_ACE.
            let (ace_type, mask, ace_sid) = unsafe {
                let body = ace as *const AccessAllowedAce;
                ((*body).ace_type, (*body).mask, &(*body).sid_start as *const u32 as PSID)
            };
            if ace_type == ACCESS_ALLOWED_ACE_TYPE && mask == rights {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::windows::token::AppContainer;

    #[test]
    fn grant_is_idempotent_and_precise() {
        let ac = AppContainer::create_or_open().unwrap();
        let dir = std::env::temp_dir().join(format!("river-acl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        grant_rw(&dir, ac.sid()).unwrap();
        let count_after_first = ace_count(&dir).unwrap();
        assert!(
            count_after_first >= 1,
            "no ACE after grant: {count_after_first}"
        );

        // Re-granting must not add a duplicate ACE.
        grant_rw(&dir, ac.sid()).unwrap();
        assert_eq!(ace_count(&dir).unwrap(), count_after_first);

        // The granted mask must be exact (no extra bits, e.g. DELETE).
        assert!(has_exactly(&dir, ac.sid(), CWD_GRANT_RIGHTS).unwrap());
        assert!(!has_exactly(&dir, ac.sid(), CWD_GRANT_RIGHTS | 0x0001_0000).unwrap());

        // Read-only grant on the same dir: SetEntriesInAclW merges per
        // trustee, so rw ∪ ro collapses into the single rw ACE — same count,
        // and the effective (union) rights stay rw. A standalone ro grant is
        // verified on a fresh directory.
        grant_ro(&dir, ac.sid()).unwrap();
        assert_eq!(ace_count(&dir).unwrap(), count_after_first);
        assert!(has_exactly(&dir, ac.sid(), CWD_GRANT_RIGHTS).unwrap());

        let ro_dir = std::env::temp_dir().join(format!("river-acl-ro-{}", std::process::id()));
        std::fs::create_dir_all(&ro_dir).unwrap();
        grant_ro(&ro_dir, ac.sid()).unwrap();
        assert!(has_exactly(&ro_dir, ac.sid(), RUNTIMES_GRANT_RIGHTS).unwrap());
        assert!(!has_exactly(&ro_dir, ac.sid(), CWD_GRANT_RIGHTS).unwrap());

        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::remove_dir_all(&ro_dir).unwrap();
    }

    fn ace_count(path: &Path) -> io::Result<u16> {
        let wide = crate::platform::windows::token::wide_of(path);
        let (dacl, sd) = read_dacl(&wide)?;
        let count = if dacl.is_null() { 0 } else { unsafe { (*dacl).AceCount } };
        // SAFETY: allocated by GetNamedSecurityInfoW.
        unsafe { LocalFree(sd as HLOCAL) };
        Ok(count)
    }

    fn has_exactly(path: &Path, sid: PSID, rights: u32) -> io::Result<bool> {
        ace_already_present(path, sid, rights)
    }

    /// S12: the DACL update is a read-modify-write; concurrent grants on the
    /// same directory must not lose the ACE (the old unsynchronized version
    /// raced and could drop the grant entirely).
    #[test]
    fn concurrent_grants_keep_the_ace() {
        let ac = AppContainer::create_or_open().unwrap();
        let dir = std::env::temp_dir().join(format!("river-acl-cc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let threads: Vec<_> = (0..8)
            .map(|_| {
                let dir = dir.clone();
                // The SID pointer must outlive the thread: leak a copy of the
                // profile SID by deriving it again inside the thread.
                std::thread::spawn(move || {
                    let ac = AppContainer::create_or_open().unwrap();
                    grant_ro(&dir, ac.sid()).unwrap();
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }

        // The ACE must be present (not lost to the race). The absolute ACE
        // count is not 1: the directory inherits ACEs from its parent, and
        // `SetEntriesInAclW` merges per trustee — what matters is that the
        // grant survived and was not duplicated by the concurrent writers.
        assert!(
            has_exactly(&dir, ac.sid(), RUNTIMES_GRANT_RIGHTS).unwrap(),
            "concurrent grants lost the ACE"
        );
        // Re-granting after the storm must not add anything.
        let count = ace_count(&dir).unwrap();
        grant_ro(&dir, ac.sid()).unwrap();
        assert_eq!(ace_count(&dir).unwrap(), count, "concurrent grants duplicated ACEs");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
