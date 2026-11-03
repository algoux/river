//! Per-run working directory: creation, `copy_in` provisioning and
//! reparse-point-safe cleanup.
//!
//! The working directory is the only writable place the sandboxed program
//! sees. It is created per run and destroyed afterwards, including on error
//! paths (the `Drop` implementation is the safety net).
//!
//! Cleanup deliberately does **not** follow reparse points (junctions /
//! symlinks): a program that plants a junction inside its working
//! directory must not be able to make the cleanup walk into (and delete)
//! host directories.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use windows_sys::Win32::Storage::FileSystem::{
    DeleteFileW, FILE_ATTRIBUTE_REPARSE_POINT, GetFileAttributesW,
    INVALID_FILE_ATTRIBUTES, RemoveDirectoryW,
};

use crate::platform::CopyInSource;

/// Root for per-run working directories.
fn workdir_root() -> PathBuf {
    std::env::temp_dir()
}

fn unique_suffix() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64 + d.as_secs())
        .unwrap_or(0);
    format!("{}-{}-{}", std::process::id(), nanos, n)
}

/// A per-run working directory. Removed on drop.
pub(crate) struct WorkDir {
    path: PathBuf,
}

impl WorkDir {
    /// Create a fresh working directory under the system temp dir.
    pub(crate) fn create() -> io::Result<Self> {
        let path = workdir_root().join(format!("river-{}", unique_suffix()));
        fs::create_dir(&path)?;
        Ok(WorkDir { path })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Materialise the `copy_in` files inside the working directory.
    ///
    /// - bytes are written directly;
    /// - host paths are **copied** (never moved: a move would carry the
    ///   source ACL along, while a copy inherits the destination's);
    /// - the copies are marked read-only, so the program cannot modify its
    ///   own input (see DESIGN.md §3.3).
    pub(crate) fn provision(&self, files: &HashMap<String, CopyInSource>) -> io::Result<()> {
        for (rel, source) in files {
            let target = self.path.join(rel);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            match source {
                CopyInSource::Bytes(bytes) => {
                    fs::write(&target, bytes)?;
                }
                CopyInSource::Path(src) => {
                    fs::copy(src, &target)?;
                }
            }
            mark_read_only(&target)?;
        }
        Ok(())
    }

    /// Remove the working directory (best effort; used by `Drop`).
    pub(crate) fn remove(&self) {
        remove_dir_no_follow(&self.path);
    }

    /// Remove the working directory and report the first failure (tests).
    #[cfg(test)]
    pub(crate) fn remove_checked(&self) -> io::Result<()> {
        remove_dir_no_follow_checked(&self.path)
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        self.remove();
    }
}

/// Mark a file read-only for the sandboxed program.
fn mark_read_only(path: &Path) -> io::Result<()> {
    let mut attrs = get_attributes(path)?;
    attrs |= windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_READONLY;
    set_attributes(path, attrs)
}

fn get_attributes(path: &Path) -> io::Result<u32> {
    let wide = to_wide(path);
    // SAFETY: `wide` is a NUL-terminated wide string.
    let attrs = unsafe { GetFileAttributesW(wide.as_ptr()) };
    if attrs == INVALID_FILE_ATTRIBUTES {
        return Err(io::Error::last_os_error());
    }
    Ok(attrs)
}

fn set_attributes(path: &Path, attrs: u32) -> io::Result<()> {
    let wide = to_wide(path);
    // SAFETY: `wide` is a NUL-terminated wide string; `attrs` is a file
    // attribute mask.
    if unsafe { windows_sys::Win32::Storage::FileSystem::SetFileAttributesW(wide.as_ptr(), attrs) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn to_wide(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Recursively delete a directory **without following reparse points**.
///
/// A junction inside the working directory is removed as a link (its
/// target is left untouched); only real directories are descended into.
fn remove_dir_no_follow(dir: &Path) {
    let _ = remove_dir_no_follow_checked(dir);
}

/// Recursively delete a directory **without following reparse points**.
///
/// A junction inside the working directory is removed as a link (its
/// target is left untouched); only real directories are descended into.
fn remove_dir_no_follow_checked(dir: &Path) -> io::Result<()> {
    let mut first_err = None;
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_e) => {
            // Nothing readable: try to remove the directory itself.
            return match remove_dir_entry(dir) {
                Ok(()) => Ok(()),
                Err(e2) => Err(e2),
            };
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let file_type = entry.file_type();
        let is_dir = file_type.as_ref().map(|t| t.is_dir()).unwrap_or(false);
        let is_reparse = file_type.as_ref().map(|t| t.is_symlink()).unwrap_or(false)
            || get_attributes(&path)
                .map(|a| a & FILE_ATTRIBUTE_REPARSE_POINT != 0)
                .unwrap_or(false);

        let result = if is_reparse {
            // Remove the link itself, never its target. `RemoveDirectoryW`
            // refuses junctions, so delete the reparse point by handle:
            // open it with OPEN_REPARSE_POINT (do not follow) and mark it
            // for deletion.
            delete_reparse_point(&path)
        } else if is_dir {
            remove_dir_no_follow_checked(&path)
        } else {
            delete_file(&path)
        };
        if let Err(e) = result
            && first_err.is_none()
        {
            first_err = Some(e);
        }
    }
    match remove_dir_entry(dir) {
        Ok(()) => Ok(()),
        Err(e) => Err(first_err.unwrap_or(e)),
    }
}

/// Delete a reparse point (junction / symlink) by opening it **without
/// following the link** and marking the handle for deletion. This never
/// touches the link target.
fn delete_reparse_point(path: &Path) -> io::Result<()> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, DELETE, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FileDispositionInfo, OPEN_EXISTING,
        SetFileInformationByHandle,
    };

    let wide = to_wide(path);
    // SAFETY: `wide` is a NUL-terminated wide string; the flags ask for
    // backup semantics (needed for directories) and explicitly forbid
    // following the reparse point.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: handle is valid; the structure is a single BOOLEAN.
    let delete = 1u8;
    let ok = unsafe {
        SetFileInformationByHandle(
            handle,
            FileDispositionInfo,
            &delete as *const _ as *const _,
            std::mem::size_of::<u8>() as u32,
        )
    };
    let err = if ok == 0 {
        Some(io::Error::last_os_error())
    } else {
        None
    };
    // SAFETY: handle is valid and closed exactly once.
    unsafe { CloseHandle(handle) };
    match err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Remove a file, clearing the read-only attribute first (a read-only file
/// cannot be deleted otherwise).
fn delete_file(path: &Path) -> io::Result<()> {
    if let Ok(attrs) = get_attributes(path)
        && attrs & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_READONLY != 0
    {
        let _ = set_attributes(
            path,
            attrs & !windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_READONLY,
        );
    }
    let wide = to_wide(path);
    // SAFETY: `wide` is a NUL-terminated wide string.
    if unsafe { DeleteFileW(wide.as_ptr()) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn remove_dir_entry(path: &Path) -> io::Result<()> {
    let wide = to_wide(path);
    // SAFETY: `wide` is a NUL-terminated wide string.
    if unsafe { RemoveDirectoryW(wide.as_ptr()) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_file(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("river-wd-test-{}-{name}", std::process::id()));
        p
    }

    #[test]
    fn creates_and_removes_working_dir() {
        let dir = WorkDir::create().unwrap();
        let path = dir.path().to_path_buf();
        assert!(path.is_dir());
        let file = path.join("hello.txt");
        fs::write(&file, b"hi").unwrap();
        dir.remove();
        assert!(!path.exists());
    }

    #[test]
    fn provisions_bytes_and_host_files() {
        let host = tmp_file("host.txt");
        fs::write(&host, b"from-host").unwrap();

        let dir = WorkDir::create().unwrap();
        let mut files = HashMap::new();
        files.insert(
            "inline.txt".to_string(),
            CopyInSource::Bytes(b"inline".to_vec()),
        );
        files.insert(
            "nested/host.txt".to_string(),
            CopyInSource::Path(host.clone()),
        );
        dir.provision(&files).unwrap();

        assert_eq!(fs::read(dir.path().join("inline.txt")).unwrap(), b"inline");
        assert_eq!(
            fs::read(dir.path().join("nested/host.txt")).unwrap(),
            b"from-host"
        );
        // Provisioned files are marked read-only for the program.
        let attrs = get_attributes(&dir.path().join("inline.txt")).unwrap();
        assert_eq!(
            attrs & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_READONLY,
            windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_READONLY
        );
        fs::remove_file(&host).ok();
    }

    #[test]
    fn cleanup_does_not_follow_junctions() {
        // Plant a junction inside the working directory pointing at a
        // directory that must survive the cleanup.
        let victim = std::env::temp_dir().join(format!("river-wd-victim-{}", std::process::id()));
        fs::create_dir_all(&victim).unwrap();
        fs::write(victim.join("keep.txt"), b"keep").unwrap();

        let dir = WorkDir::create().unwrap();
        let junction = dir.path().join("escape");
        // mklink /J requires cmd; use it via Command.
        let status = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&junction)
            .arg(&victim)
            .status()
            .unwrap();
        if !status.success() {
            // No permission to create junctions: nothing to verify here.
            fs::remove_dir_all(&victim).ok();
            return;
        }

        let path = dir.path().to_path_buf();
        dir.remove_checked()
            .unwrap_or_else(|e| panic!("cleanup failed: {e}"));
        assert!(!path.exists(), "working dir should be gone");
        assert!(
            victim.join("keep.txt").exists(),
            "cleanup must not delete through a junction"
        );
        fs::remove_dir_all(&victim).ok();
    }
}
