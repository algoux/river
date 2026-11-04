//! AppContainer identity for sandboxed children.
//!
//! A child becomes an AppContainer at process creation time via the
//! `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` attribute (the Chromium
//! approach) — no separate restricted token is needed. This module owns the
//! AppContainer *profile*: it is created once, reused across runs, and its
//! SID is what the ACL layer (acl.rs) grants file access to.
//!
//! An AppContainer without capabilities has no network access: the firewall
//! blocks it by default. Network denial is therefore unconditional (it is
//! not a configurable capability).
//!
//! Concurrency: `CreateAppContainerProfile` **mutates system state**
//! (it writes the AppContainer mapping registry key and the profile
//! folder); concurrent callers corrupt each other — observed under 8-way
//! concurrency as `ERROR_KEY_DELETED`, `ERROR_INVALIDARG`,
//! `ERROR_FILE_NOT_FOUND` and `RPC_E_SERVERCALL_RETRYLATER`. Chromium's
//! sandbox library hit the same race and serializes profile creation behind
//! a lock; so do we. Afterwards the profile is known to exist and only the
//! pure-read `DeriveAppContainerSidFromAppContainerName` is used.
//!
//! NOTE: deriving the SID alone is *not* enough — a derived-but-never-created
//! profile has no registry mapping, and a child adopting that SID fails to
//! start with `ERROR_FILE_NOT_FOUND`. The profile must have been created at
//! least once, which is exactly what the cached "created" flag tracks.

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};

// windows-sys does not expose the userenv profile APIs; declare the three
// functions we need directly (kernel32's LocalFree comes from windows-sys).
type HRESULT = i32;
type PCWSTR = *const u16;
type PSID = *mut core::ffi::c_void;

const ERROR_ALREADY_EXISTS: u32 = 183;
/// HRESULT form of ERROR_ALREADY_EXISTS (0x8007 | win32 code).
const HRESULT_ALREADY_EXISTS: i32 = 0x8007_00B7u32 as i32;
/// HRESULT form of ERROR_NOT_FOUND (profile does not exist yet).
const HRESULT_PROFILE_NOT_FOUND: i32 = 0x8007_0490u32 as i32;

#[link(name = "userenv")]
unsafe extern "system" {
    fn CreateAppContainerProfile(
        appcontainername: PCWSTR,
        displayname: PCWSTR,
        description: PCWSTR,
        capabilitiessid: *const PSID,
        capabilitycount: u32,
        appcontainersid: *mut PSID,
    ) -> HRESULT;
    fn DeriveAppContainerSidFromAppContainerName(
        appcontainername: PCWSTR,
        appcontainersid: *mut PSID,
    ) -> HRESULT;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn ConvertSidToStringSidW(sid: PSID, stringsid: *mut *mut u16) -> i32;
}

/// Profile name reused across runs (must be stable for SID derivation).
const PROFILE_NAME: &str = "river.sandbox";

/// Serializes profile *creation* (the only mutating profile API).
///
/// `CreateAppContainerProfile` writes a registry key and a profile
/// directory; concurrent calls race and leave the profile in a broken state
/// (observed: `ERROR_KEY_DELETED`, `ERROR_INVALIDARG`,
/// `ERROR_FILE_NOT_FOUND`). Chromium's sandbox library takes the same lock
/// around profile creation.
static PROFILE_CREATE_LOCK: Mutex<()> = Mutex::new(());

/// Owned AppContainer SID (freed with `LocalFree`).
pub(crate) struct AppContainer {
    sid: PSID,
    name: String,
}

impl AppContainer {
    /// Open the sandbox profile, creating it on first use.
    pub(crate) fn create_or_open() -> io::Result<Self> {
        Self::create_or_open_named(PROFILE_NAME)
    }

    pub(crate) fn create_or_open_named(name: &str) -> io::Result<Self> {
        // Fast path: this process already created the profile in an earlier
        // run. `CreateAppContainerProfile` is the *mutating* API (it writes
        // the AppContainer mapping registry key and the profile folder);
        // calling it concurrently corrupts the profile (observed:
        // ERROR_KEY_DELETED / ERROR_INVALIDARG / ERROR_FILE_NOT_FOUND), so
        // it runs exactly once per process, under a lock.
        if profile_known_created(name) {
            if let Some(sid) = derive_sid(name)? {
                return Ok(AppContainer {
                    sid,
                    name: name.to_string(),
                });
            }
            // The mapping vanished (profile deleted behind our back): fall
            // through and re-create it.
        }
        create_profile(name)
    }

    /// The AppContainer SID as an opaque handle for ACL / spawn calls.
    pub(crate) fn sid(&self) -> PSID {
        self.sid
    }

    /// SID in the textual `S-1-...` form (used by tests and debugging).
    pub(crate) fn sid_string(&self) -> io::Result<String> {
        let mut wide: *mut u16 = std::ptr::null_mut();
        // SAFETY: SID is owned and valid; out-pointer valid.
        let ok = unsafe { ConvertSidToStringSidW(self.sid as _, &mut wide) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `wide` is NUL-terminated by ConvertSidToStringSidW.
        let s = unsafe { wide_ptr_to_string(wide) };
        // SAFETY: allocated by ConvertSidToStringSidW, freed with LocalFree.
        unsafe { LocalFree(wide as HLOCAL) };
        Ok(s)
    }

    /// Path of the profile's private storage (AppContainer data directory).
    /// Useful to verify the profile exists.
    pub(crate) fn profile_path(&self) -> Option<PathBuf> {
        profile_path_for(&self.name)
    }
}

impl Drop for AppContainer {
    fn drop(&mut self) {
        if !self.sid.is_null() {
            // SAFETY: SID was allocated by CreateAppContainerProfile /
            // DeriveAppContainerSidFromAppContainerName, freed with LocalFree.
            unsafe { LocalFree(self.sid as HLOCAL) };
        }
    }
}

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Derive the SID of an existing profile (pure read; `None` when the profile
/// does not exist yet).
///
/// A failed derive is treated as "does not exist" rather than a hard error:
/// the profile may genuinely be absent (first run) or the registry key may
/// be in a transient state. The authoritative answer comes from
/// `create_profile` under the lock.
fn derive_sid(name: &str) -> io::Result<Option<PSID>> {
    let wide_name = to_wide(name);
    let mut sid: PSID = std::ptr::null_mut();
    // SAFETY: wide string valid; out-pointer valid.
    let hr = unsafe {
        DeriveAppContainerSidFromAppContainerName(wide_name.as_ptr(), &mut sid as *mut PSID)
    };
    if hr == 0 && !sid.is_null() {
        return Ok(Some(sid));
    }
    Ok(None)
}

/// Create the profile (mutating API — serialized by
/// `PROFILE_CREATE_LOCK`), then remember that this process owns it.
fn create_profile(name: &str) -> io::Result<AppContainer> {
    let _guard = PROFILE_CREATE_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let wide_name = to_wide(name);
    let mut sid: PSID = std::ptr::null_mut();
    // SAFETY: wide string is NUL-terminated; out-pointer valid.
    let hr = unsafe {
        CreateAppContainerProfile(
            wide_name.as_ptr(),
            wide_name.as_ptr(), // display name (same moniker is fine)
            wide_name.as_ptr(), // description
            std::ptr::null(),   // no capabilities: network denied by default
            0,
            &mut sid as *mut PSID,
        )
    };
    if hr != 0 && hr != HRESULT_ALREADY_EXISTS {
        return Err(io::Error::from_raw_os_error(hr as i32));
    }
    if sid.is_null() {
        // The profile already existed (ERROR_ALREADY_EXISTS): derive the
        // stable SID. This is the path Chromium takes as well.
        let sid = match derive_sid(name)? {
            Some(sid) => sid,
            None => {
                return Err(io::Error::from_raw_os_error(HRESULT_PROFILE_NOT_FOUND));
            }
        };
        mark_profile_created(name);
        return Ok(AppContainer {
            sid,
            name: name.to_string(),
        });
    }
    mark_profile_created(name);
    Ok(AppContainer {
        sid,
        name: name.to_string(),
    })
}

/// Names of profiles this process has already created.
fn created_profiles() -> &'static Mutex<Vec<String>> {
    static CREATED: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    CREATED.get_or_init(|| Mutex::new(Vec::new()))
}

/// True when this process already created `name` (so the mutating API can be
/// skipped).
fn profile_known_created(name: &str) -> bool {
    created_profiles()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .any(|n| n == name)
}

fn mark_profile_created(name: &str) {
    let mut guard = created_profiles().lock().unwrap_or_else(|e| e.into_inner());
    if !guard.iter().any(|n| n == name) {
        guard.push(name.to_string());
    }
}

// Re-exported for sibling modules (acl.rs / spawn.rs build wide strings too).
pub(crate) fn wide_of(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Read a NUL-terminated wide string into `String`.
///
/// # Safety
/// `ptr` must point to a NUL-terminated UTF-16 string.
unsafe fn wide_ptr_to_string(ptr: *const u16) -> String {
    unsafe {
        let mut len = 0usize;
        // SAFETY: caller guarantees NUL termination.
        while *ptr.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
    }
}

fn profile_path_for(name: &str) -> Option<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")?;
    Some(Path::new(&base).join("Packages").join(name).join("AC"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_is_stable_across_opens() {
        let a = AppContainer::create_or_open().unwrap();
        let sid_a = a.sid_string().unwrap();
        assert!(sid_a.starts_with("S-1-"), "sid: {sid_a}");

        // Reopening derives the same SID.
        let b = AppContainer::create_or_open().unwrap();
        let sid_b = b.sid_string().unwrap();
        assert_eq!(sid_a, sid_b);

        // Named variant is stable too.
        let c = AppContainer::create_or_open_named("river.sandbox").unwrap();
        assert_eq!(sid_a, c.sid_string().unwrap());
    }

    #[test]
    fn distinct_profiles_get_distinct_sids() {
        let base = AppContainer::create_or_open_named("river.sandbox").unwrap();
        let other = AppContainer::create_or_open_named("river.sandbox.t2").unwrap();
        assert_ne!(base.sid_string().unwrap(), other.sid_string().unwrap());
    }

    /// Profile creation is the one *mutating* profile API — concurrent
    /// callers must not corrupt it. This is the regression test for the
    /// 8-way concurrency failure (`ERROR_KEY_DELETED` / `ERROR_INVALIDARG` /
    /// `ERROR_FILE_NOT_FOUND`): every thread must get the same SID.
    #[test]
    fn concurrent_profile_opens_agree_on_one_sid() {
        let threads: Vec<_> = (0..8)
            .map(|_| {
                std::thread::spawn(|| {
                    let ac = AppContainer::create_or_open().unwrap();
                    ac.sid_string().unwrap()
                })
            })
            .collect();
        let sids: Vec<String> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        let first = &sids[0];
        assert!(first.starts_with("S-1-"), "sid: {first}");
        for s in &sids {
            assert_eq!(s, first, "concurrent opens disagreed on the SID");
        }
    }

    /// A *fresh* profile name created concurrently by many threads must
    /// end up with exactly one profile (and one SID).
    #[test]
    fn concurrent_creation_of_a_fresh_profile_is_serialized() {
        let name = "river.sandbox.cctest";
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let name = name.to_string();
                std::thread::spawn(move || {
                    let ac = AppContainer::create_or_open_named(&name).unwrap();
                    ac.sid_string().unwrap()
                })
            })
            .collect();
        let sids: Vec<String> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        for s in &sids {
            assert_eq!(s, &sids[0], "fresh profile got inconsistent SIDs");
        }
    }
}
