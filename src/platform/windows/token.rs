//! AppContainer identity for sandboxed children.
//!
//! A child becomes an AppContainer at process creation time via the
//! `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` attribute (the Chromium
//! approach) — no separate restricted token is needed. This module owns the
//! AppContainer *profile*: it is created once, reused across runs, and its
//! SID is what the ACL layer (acl.rs) grants file access to.
//!
//! An AppContainer without capabilities has no network access: the firewall
//! blocks it by default, which is our network isolation (agreed policy).

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};

// windows-sys does not expose the userenv profile APIs; declare the three
// functions we need directly (kernel32's LocalFree comes from windows-sys).
type HRESULT = i32;
type PCWSTR = *const u16;
type PSID = *mut core::ffi::c_void;

const ERROR_ALREADY_EXISTS: u32 = 183;
/// HRESULT form of ERROR_ALREADY_EXISTS (0x8007 | win32 code).
const HRESULT_ALREADY_EXISTS: i32 = 0x8007_00B7u32 as i32;

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
            // Profile already existed: derive the stable SID.
            // SAFETY: wide string valid; out-pointer valid.
            let hr = unsafe {
                DeriveAppContainerSidFromAppContainerName(wide_name.as_ptr(), &mut sid as *mut PSID)
            };
            if hr != 0 {
                return Err(io::Error::from_raw_os_error(hr as i32));
            }
        }
        Ok(AppContainer {
            sid,
            name: name.to_string(),
        })
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
unsafe fn wide_ptr_to_string(ptr: *const u16) -> String { unsafe {
    let mut len = 0usize;
    // SAFETY: caller guarantees NUL termination.
    while *ptr.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
}}

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
}
