//! AppContainer profile (identity) and its read-only host surface.
//!
//! A profile is created lazily the first time a sandbox with `runtimes` runs.
//! Its SID is the identity the child adopts at process creation; every
//! `runtimes` entry gets a read/execute ACE for that SID (see [`super::acl`]).
//! A file entry also needs its parent directory to be readable/traversable,
//! so that one directory gets a non-inheritable read/execute ACE. The scratch
//! `workdir` gets read/write/execute because it is the sandbox's writable
//! area.
//!
//! When the profile is closed the granted ACEs are revoked and the profile is
//! deleted, so repeated sandbox sessions neither accumulate ACL entries nor
//! leave a usable AppContainer identity behind.

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
use windows_sys::Win32::Security::PSID;

use super::acl;

#[allow(clippy::upper_case_acronyms)]
type HRESULT = i32;
#[allow(clippy::upper_case_acronyms)]
type PCWSTR = *const u16;

/// `HRESULT_FROM_WIN32(ERROR_NOT_FOUND)` (the profile is already gone).
const HRESULT_PROFILE_NOT_FOUND: HRESULT = 0x8007_0490u32 as HRESULT;

// windows-sys does not expose the userenv profile APIs.
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
    fn DeleteAppContainerProfile(appcontainername: PCWSTR) -> HRESULT;
}

/// `CreateAppContainerProfile` mutates system state (registry + profile
/// folder) and corrupts concurrent callers, so creation is serialized.
static PROFILE_CREATE_LOCK: Mutex<()> = Mutex::new(());

pub(crate) struct AppContainer {
    name: String,
    sid: PSID,
    /// Paths whose DACL currently contains a grant for `sid`.
    grants: Vec<PathBuf>,
    closed: bool,
}

// SAFETY: the SID is immutable after creation and is only read from other
// threads; it is freed exactly once, in `Drop`, after the last user is gone.
unsafe impl Send for AppContainer {}
unsafe impl Sync for AppContainer {}

impl AppContainer {
    /// Creates a profile and grants the sandbox surface.
    ///
    /// If any grant fails, the partially built container is dropped, which
    /// revokes the grants already applied and deletes the profile.
    pub(crate) fn create(
        name: &str,
        runtimes: &[PathBuf],
        workdir: Option<&Path>,
    ) -> io::Result<Self> {
        let sid = create_profile(name)?;
        let mut app = AppContainer {
            name: name.to_string(),
            sid,
            grants: Vec::new(),
            closed: false,
        };
        for runtime in runtimes {
            if !runtime.exists() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("runtimes path does not exist: {}", runtime.display()),
                ));
            }
            if !runtime.is_dir() && !runtime.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "runtimes path is neither a file nor a directory: {}",
                        runtime.display()
                    ),
                ));
            }
        }
        // The scratch directory is granted before the runtime entries: it is
        // the one writable area, and a runtime path below it should inherit
        // that grant rather than downgrade it.
        if let Some(workdir) = workdir {
            app.grant_read_write_execute(workdir)?;
        }
        // Directories first: a file entry's parent grant must not demote an
        // existing directory grant's inheritance flags.
        for runtime in runtimes.iter().filter(|path| path.is_dir()) {
            app.grant_read_execute(runtime)?;
        }
        for runtime in runtimes.iter().filter(|path| path.is_file()) {
            app.grant_read_execute(runtime)?;
            app.grant_parent_access(runtime)?;
        }
        Ok(app)
    }

    pub(crate) fn sid(&self) -> PSID {
        self.sid
    }

    /// Revokes every grant and deletes the profile. Idempotent.
    pub(crate) fn close(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }

        let mut first_error = None;
        for path in &self.grants {
            if let Err(error) = acl::revoke(path, self.sid) {
                first_error.get_or_insert(error);
            }
        }
        if let Err(error) = delete_profile(&self.name) {
            first_error.get_or_insert(error);
        }
        if first_error.is_none() {
            self.closed = true;
        }
        first_error.map_or(Ok(()), Err)
    }

    fn grant_read_execute(&mut self, path: &Path) -> io::Result<()> {
        self.grant(path, acl::grant_read_execute)
    }

    fn grant_read_write_execute(&mut self, path: &Path) -> io::Result<()> {
        self.grant(path, acl::grant_read_write_execute)
    }

    /// A file entry is reachable only when the target may read/traverse its
    /// parent directory. The parent gets a **non-inheritable** read/execute
    /// ACE: sibling files are not granted anything, and the parent stays
    /// read-only. If the parent is itself a runtime entry it already has a
    /// grant and this is skipped.
    fn grant_parent_access(&mut self, path: &Path) -> io::Result<()> {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        if self.grants.iter().any(|granted| granted == parent) {
            return Ok(());
        }
        acl::grant_read_execute_no_inherit(parent, self.sid)?;
        self.grants.push(parent.to_path_buf());
        Ok(())
    }

    fn grant(&mut self, path: &Path, grant: fn(&Path, PSID) -> io::Result<()>) -> io::Result<()> {
        if !path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("runtimes path does not exist: {}", path.display()),
            ));
        }
        // Re-granting the same path is harmless (SetEntriesInAcl merges by
        // trustee); the path is only recorded once for the cleanup pass.
        grant(path, self.sid)?;
        if !self.grants.iter().any(|granted| granted == path) {
            self.grants.push(path.to_path_buf());
        }
        Ok(())
    }
}

impl Drop for AppContainer {
    fn drop(&mut self) {
        let _ = self.close();
        if !self.sid.is_null() {
            // SAFETY: allocated by CreateAppContainerProfile or
            // DeriveAppContainerSidFromAppContainerName (LocalAlloc).
            unsafe { LocalFree(self.sid as HLOCAL) };
            self.sid = std::ptr::null_mut();
        }
    }
}

fn create_profile(name: &str) -> io::Result<PSID> {
    let _guard = PROFILE_CREATE_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let wide = wide_of(name);
    let mut sid: PSID = std::ptr::null_mut();

    // SAFETY: `wide` is NUL-terminated; `sid` is a valid out-pointer.
    let hr = unsafe {
        CreateAppContainerProfile(
            wide.as_ptr(),
            wide.as_ptr(),
            wide.as_ptr(),
            std::ptr::null(),
            0,
            &mut sid,
        )
    };
    if hr == 0 && !sid.is_null() {
        return Ok(sid);
    }

    // The profile may already exist (for example after a hard-killed
    // judger); its SID is the same stable identity either way. A profile that
    // was never created cannot be derived, so creation is attempted first.
    let mut derived: PSID = std::ptr::null_mut();
    // SAFETY: `wide` is NUL-terminated; `derived` is a valid out-pointer.
    let derive_hr =
        unsafe { DeriveAppContainerSidFromAppContainerName(wide.as_ptr(), &mut derived) };
    if derive_hr == 0 && !derived.is_null() {
        return Ok(derived);
    }
    Err(hresult_to_io(if hr != 0 { hr } else { derive_hr }))
}

fn delete_profile(name: &str) -> io::Result<()> {
    let wide = wide_of(name);
    // SAFETY: `wide` is NUL-terminated.
    let hr = unsafe { DeleteAppContainerProfile(wide.as_ptr()) };
    if hr == 0 || hr == HRESULT_PROFILE_NOT_FOUND {
        Ok(())
    } else {
        Err(hresult_to_io(hr))
    }
}

fn wide_of(text: &str) -> Vec<u16> {
    OsStr::new(text)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn hresult_to_io(hr: HRESULT) -> io::Error {
    let raw = hr as u32;
    if raw & 0xFFFF_0000 == 0x8007_0000 {
        // FACILITY_WIN32: the low word is the underlying Win32 error code.
        io::Error::from_raw_os_error((raw & 0xFFFF) as i32)
    } else {
        io::Error::other(format!("HRESULT 0x{raw:08X}"))
    }
}
