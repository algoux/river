//! AppContainer identity for sandboxed children.
//!
//! A child becomes an AppContainer at process creation time via the
//! `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` attribute (the Chromium
//! approach) — no separate restricted token is needed. This module owns the
//! profile *primitives*: creation (serialized), SID derivation and SID
//! lifetime. The run path does not use a single global profile: it leases a
//! slot from the fixed pool in `profile.rs`, which wipes that slot's package
//! folder before and after every run.
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
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows_sys::Win32::Security::{
    CopySid, GetLengthSid, GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

// windows-sys does not expose the userenv profile APIs; declare the two
// functions we need directly (kernel32's LocalFree comes from windows-sys).
#[allow(clippy::upper_case_acronyms)] // Windows API naming convention
type HRESULT = i32;
#[allow(clippy::upper_case_acronyms)] // Windows API naming convention
type PCWSTR = *const u16;
#[allow(clippy::upper_case_acronyms)] // Windows API naming convention
type PSID = *mut core::ffi::c_void;

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
}

// SAFETY: the SID is immutable after creation and only read (ACL grants,
// spawn attributes) from other threads; it is freed exactly once, on drop of
// the owning `Arc`/value. The profile pool shares one `Arc<AppContainer>` per
// slot across runs.
unsafe impl Send for AppContainer {}
unsafe impl Sync for AppContainer {}

impl AppContainer {
    pub(crate) fn create_or_open_named(name: &str) -> io::Result<Self> {
        // Fast path: this process already created the profile in an earlier
        // run. `CreateAppContainerProfile` is the *mutating* API (it writes
        // the AppContainer mapping registry key and the profile folder);
        // calling it concurrently corrupts the profile (observed:
        // ERROR_KEY_DELETED / ERROR_INVALIDARG / ERROR_FILE_NOT_FOUND), so
        // it runs exactly once per process, under a lock.
        if profile_known_created(name)
            && let Some(sid) = derive_sid(name)?
        {
            return Ok(AppContainer { sid });
            // The mapping vanished (profile deleted behind our back): fall
            // through and re-create it.
        }
        create_profile(name)
    }

    /// The AppContainer SID as an opaque handle for ACL / spawn calls.
    pub(crate) fn sid(&self) -> PSID {
        self.sid
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
        return Ok(AppContainer { sid });
    }
    mark_profile_created(name);
    Ok(AppContainer { sid })
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

/// NUL-terminated UTF-16 for a plain string (named mutexes, etc.).
pub(crate) fn wide_of_text(text: &str) -> Vec<u16> {
    OsStr::new(text)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// The judger's own user SID, as owned bytes.
///
/// Used to build a **protected** DACL for `copy_in` inputs: the sandboxed
/// process runs with the same user SID *and* the AppContainer package SID,
/// so a deny ACE for the package SID alone is not enough — the inherited
/// user ACE would still grant write (the AppContainer access check accepts
/// both). Granting both identities read-only and protecting the DACL from
/// inheritance is what actually makes the input immutable.
pub(crate) fn current_user_sid() -> io::Result<Vec<u8>> {
    // Cached: the SID is per-process stable and the copy_in path asks once
    // per provisioned entry (a 200-file input would otherwise query the
    // token 200 times).
    static CACHE: OnceLock<Vec<u8>> = OnceLock::new();
    if let Some(sid) = CACHE.get() {
        return Ok(sid.clone());
    }
    let sid = query_user_sid()?;
    let _ = CACHE.set(sid.clone());
    Ok(sid)
}

fn query_user_sid() -> io::Result<Vec<u8>> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: the handle is closed below; GetCurrentProcess is pseudo.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let result = (|| {
        let mut len: u32 = 0;
        // First call sizes the buffer (fails with INSUFFICIENT_BUFFER).
        unsafe {
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len);
        };
        if len == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buf = vec![0u8; len as usize];
        // SAFETY: buffer is `len` bytes; the call writes at most `len`.
        if unsafe {
            GetTokenInformation(token, TokenUser, buf.as_mut_ptr() as *mut _, len, &mut len)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the call succeeded and filled a TOKEN_USER.
        let user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
        // SAFETY: User.Sid points into `buf`, still alive.
        let sid_len = unsafe { GetLengthSid(user.User.Sid) } as usize;
        if sid_len == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut sid = vec![0u8; sid_len];
        // SAFETY: destination is `sid_len` bytes; source SID is valid.
        if unsafe { CopySid(sid_len as u32, sid.as_mut_ptr() as *mut _, user.User.Sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(sid)
    })();
    // SAFETY: handle was opened above and is closed exactly once.
    unsafe { CloseHandle(token) };
    result
}
