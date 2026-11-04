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
    DeleteFileW, FILE_ATTRIBUTE_REPARSE_POINT, GetFileAttributesW, INVALID_FILE_ATTRIBUTES,
    RemoveDirectoryW,
};

use crate::contract::{CopyInSource, CopyOutEntry};

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

/// One top-level `copy_in` entry. `is_dir` selects an inheritable ACL (one
/// DACL write protects the whole tree) over a per-file one.
pub(crate) struct Provisioned {
    pub path: PathBuf,
    pub is_dir: bool,
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
    ///   a host *directory* is provisioned recursively;
    /// - the copies receive a protected, read-only DACL from the caller
    ///   (`sandbox.rs`), so the program cannot modify its own input (see
    ///   DESIGN.md §3.3). No `FILE_ATTRIBUTE_READONLY` is set: the attribute
    ///   is bypassable with `chmod`, and a read-only file also blocks the
    ///   judger's own workdir cleanup (it cannot be deleted without clearing
    ///   the attribute first, which the protected ACL forbids).
    ///
    /// Symlinks / junctions inside a directory source are skipped (a
    /// trusted-source convenience must never become a link farm).
    ///
    /// Returns one entry per top-level key. A directory entry is protected
    /// with an **inheritable** read-only ACE (its whole tree inherits it in
    /// one DACL write); a file entry is protected individually.
    pub(crate) fn provision(
        &self,
        files: &HashMap<String, CopyInSource>,
    ) -> io::Result<Vec<Provisioned>> {
        let mut created = Vec::new();
        for (rel, source) in files {
            let target = self.path.join(rel);
            match source {
                CopyInSource::Bytes(bytes) => {
                    if let Some(parent) = target.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    fs::write(&target, bytes)?;
                    created.push(Provisioned {
                        path: target,
                        is_dir: false,
                    });
                }
                CopyInSource::Path(src) => {
                    let md = fs::metadata(src)?;
                    if md.is_dir() {
                        provision_dir(src, &target)?;
                        created.push(Provisioned {
                            path: target,
                            is_dir: true,
                        });
                    } else {
                        if let Some(parent) = target.parent() {
                            fs::create_dir_all(parent)?;
                        }
                        fs::copy(src, &target)?;
                        created.push(Provisioned {
                            path: target,
                            is_dir: false,
                        });
                    }
                }
            }
        }
        Ok(created)
    }

    /// Collect `copy_out` products from the working directory into their
    /// host destinations (called after the Job Object reaped the tree,
    /// before the `Drop`).
    ///
    /// **Never follows reparse points** (junctions / symlinks): the program
    /// could plant one pointing at any host path, and the judger may run
    /// privileged — following it would be an arbitrary-host-file
    /// exfiltration channel. Reparse-point entries are skipped entirely;
    /// missing sources are skipped (optional products). Collection stops at
    /// the first file that would push the total past `quota_bytes` (that
    /// file is *not* collected — no partial files).
    pub(crate) fn collect(
        &self,
        entries: &[CopyOutEntry],
        quota_bytes: Option<u64>,
    ) -> io::Result<Collected> {
        let mut out = Collected::default();
        for entry in entries {
            if out.quota_exceeded {
                break;
            }
            let src = self.path.join(&entry.src_rel);
            let md = match fs::symlink_metadata(&src) {
                Ok(md) => md,
                Err(_) => continue, // missing source: optional product
            };
            if is_reparse(&md) {
                continue;
            }
            if md.is_dir() {
                collect_dir(&src, &entry.dst_host, quota_bytes, &mut out)?;
            } else {
                copy_one(&src, &entry.dst_host, quota_bytes, &mut out)?;
            }
        }
        Ok(out)
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

/// Outcome of a `copy_out` collection.
#[derive(Default)]
pub(crate) struct Collected {
    /// Total bytes written to the host destinations.
    pub total_bytes: u64,
    /// True when the quota stopped the collection early.
    pub quota_exceeded: bool,
}

/// Does this metadata describe a symlink / junction / reparse point?
fn is_reparse(md: &fs::Metadata) -> bool {
    md.file_type().is_symlink()
}

/// Recursively provision a host source directory into the working
/// directory (`copy_in` with a directory value). Regular files and
/// subdirectories only; reparse points are skipped.
fn provision_dir(src: &Path, dst: &Path) -> io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        if is_reparse(&entry.metadata()?) {
            continue;
        }
        let md = entry.metadata()?;
        let target = dst.join(entry.file_name());
        if md.is_dir() {
            provision_dir(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

/// Recursively collect a source directory into the host destination.
fn collect_dir(
    src: &Path,
    dst: &Path,
    quota_bytes: Option<u64>,
    out: &mut Collected,
) -> io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        if out.quota_exceeded {
            return Ok(());
        }
        let entry = entry?;
        if is_reparse(&entry.metadata()?) {
            continue; // an exfiltration channel: never follow, never copy
        }
        let md = entry.metadata()?;
        let target = dst.join(entry.file_name());
        if md.is_dir() {
            collect_dir(&entry.path(), &target, quota_bytes, out)?;
        } else {
            copy_one(&entry.path(), &target, quota_bytes, out)?;
        }
    }
    Ok(())
}

/// Copy a single regular file to the host destination, updating the quota
/// accounting. Refuse reparse points (no link following, no partial files
/// on quota breach — see [`WorkDir::collect`]).
fn copy_one(
    src: &Path,
    dst: &Path,
    quota_bytes: Option<u64>,
    out: &mut Collected,
) -> io::Result<()> {
    let md = fs::symlink_metadata(src)?;
    if is_reparse(&md) {
        return Ok(());
    }
    if let Some(quota) = quota_bytes
        && out.total_bytes + md.len() > quota
    {
        // Do not collect a file that would breach the quota (no partial
        // files); the caller sees `quota_exceeded` and reports OLE.
        out.quota_exceeded = true;
        return Ok(());
    }
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(src, dst)?;
    out.total_bytes += md.len();
    Ok(())
}

/// Best-effort sweep of working directories abandoned by a **dead** judger
/// process (e.g. the judger was hard-killed mid-run: `Drop` never ran, and
/// while `KILL_ON_JOB_CLOSE` reaped the sandboxed processes, the directory
/// remained). Directory names look like `river-{pid}-{nanos}-{n}`; a dir is
/// removed only when its owning pid no longer exists, so live runs —
/// including ours — are never touched. Names without a parseable owner pid
/// (other tools' `river-*` dirs) are skipped.
///
/// Concurrency: two threads sweeping at once would race on the same
/// directory (one deletes it while the other walks it) and surface as
/// `ERROR_SHARING_VIOLATION`. The sweep is therefore serialized through a
/// process-global lock.
pub(crate) fn sweep_stale_workdirs() {
    static SWEEP_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = SWEEP_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let entries = match fs::read_dir(workdir_root()) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(pid) = owner_pid_of(name) else {
            continue;
        };
        if pid_is_alive(pid) {
            continue;
        }
        // Never follow reparse points while deleting (same rule as `Drop`).
        let _ = remove_dir_no_follow_checked(&entry.path());
    }
}

/// Owner pid encoded in a `river-{pid}-...` working-directory name.
fn owner_pid_of(dir_name: &str) -> Option<u32> {
    dir_name
        .strip_prefix("river-")?
        .split('-')
        .next()?
        .parse()
        .ok()
}

/// Does a process with this pid currently exist?
fn pid_is_alive(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
    };
    // SAFETY: querying another process by pid; handle closed on success.
    let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
    if handle.is_null() {
        return false; // pid does not exist (or is inaccessible)
    }
    // SAFETY: handle valid.
    let state = unsafe { WaitForSingleObject(handle, 0) };
    // SAFETY: handle valid.
    unsafe { CloseHandle(handle) };
    state == WAIT_TIMEOUT // still running
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

/// Remove the *contents* of `dir`, keeping the directory itself. Used to
/// wipe a profile slot's package folder between runs; reparse points are
/// removed as links, never followed.
pub(crate) fn wipe_dir_contents(dir: &Path) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type();
        let is_dir = file_type.as_ref().map(|t| t.is_dir()).unwrap_or(false);
        let is_reparse = file_type.as_ref().map(|t| t.is_symlink()).unwrap_or(false)
            || get_attributes(&path)
                .map(|a| a & FILE_ATTRIBUTE_REPARSE_POINT != 0)
                .unwrap_or(false);
        if is_reparse {
            let _ = delete_reparse_point(&path);
        } else if is_dir {
            remove_dir_no_follow_checked(&path)?;
        } else {
            delete_file(&path)?;
        }
    }
    Ok(())
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
        std::env::temp_dir().join(format!("river-wd-test-{}-{name}", std::process::id()))
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
        let provisioned = dir.provision(&files).unwrap();
        assert_eq!(provisioned.len(), 2);
        assert!(provisioned.iter().all(|entry| !entry.is_dir));

        assert_eq!(fs::read(dir.path().join("inline.txt")).unwrap(), b"inline");
        assert_eq!(
            fs::read(dir.path().join("nested/host.txt")).unwrap(),
            b"from-host"
        );
        // Immutability is enforced by the protected read-only DACL that
        // `sandbox.rs` applies (a READONLY attribute is bypassable with
        // chmod and would block the judger's own cleanup); the Python suite
        // asserts the effective deny.
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

    #[test]
    fn sweep_removes_dead_owner_and_keeps_live_and_foreign() {
        // A dir owned by our (live) pid must survive; a dir owned by a pid
        // that cannot exist must be swept; foreign names are ignored.
        let live = workdir_root().join(format!("river-{}-1-0", std::process::id()));
        let dead = workdir_root().join("river-4194303-1-0"); // pid max is smaller
        let foreign = workdir_root().join("river-not-a-judger-dir");
        fs::create_dir_all(&live).unwrap();
        fs::create_dir_all(&dead).unwrap();
        fs::create_dir_all(&foreign).unwrap();
        fs::write(dead.join("stale.txt"), b"stale").unwrap();

        assert!(pid_is_alive(std::process::id()));
        assert!(!pid_is_alive(4_194_303));

        sweep_stale_workdirs();

        assert!(live.is_dir(), "live-owner dir must survive the sweep");
        assert!(!dead.exists(), "dead-owner dir must be swept");
        assert!(foreign.is_dir(), "unparseable names must be left alone");

        fs::remove_dir_all(&live).ok();
        fs::remove_dir_all(&foreign).ok();
    }

    /// A directory-valued `copy_in` is provisioned recursively, read-only.
    #[test]
    fn provisions_a_directory_recursively() {
        let host = workdir_root().join(format!("river-wd-src-{}", std::process::id()));
        fs::create_dir_all(host.join("sub")).unwrap();
        fs::write(host.join("a.txt"), b"A").unwrap();
        fs::write(host.join("sub/b.txt"), b"B").unwrap();

        let dir = WorkDir::create().unwrap();
        let mut files = HashMap::new();
        files.insert("proj".to_string(), CopyInSource::Path(host.clone()));
        dir.provision(&files).unwrap();

        assert_eq!(fs::read(dir.path().join("proj/a.txt")).unwrap(), b"A");
        assert_eq!(fs::read(dir.path().join("proj/sub/b.txt")).unwrap(), b"B");
        fs::remove_dir_all(&host).ok();
    }

    /// `copy_out` writes the product to the host path and reports its size.
    #[test]
    fn collect_copies_products_to_host_paths() {
        let dir = WorkDir::create().unwrap();
        fs::write(dir.path().join("out.txt"), b"product").unwrap();
        fs::create_dir_all(dir.path().join("tree/nested")).unwrap();
        fs::write(dir.path().join("tree/nested/x"), b"XX").unwrap();

        let dst_dir = workdir_root().join(format!("river-wd-dst-{}", std::process::id()));
        let entries = vec![
            CopyOutEntry {
                src_rel: "out.txt".to_string(),
                dst_host: dst_dir.join("collected.txt"),
            },
            CopyOutEntry {
                src_rel: "tree".to_string(),
                dst_host: dst_dir.join("tree"),
            },
        ];
        let got = dir.collect(&entries, None).unwrap();
        assert_eq!(got.total_bytes, 9); // 7 + 2
        assert!(!got.quota_exceeded);
        assert_eq!(fs::read(dst_dir.join("collected.txt")).unwrap(), b"product");
        assert_eq!(fs::read(dst_dir.join("tree/nested/x")).unwrap(), b"XX");
        fs::remove_dir_all(&dst_dir).ok();
    }

    /// The quota stops the collection: files that would breach it are not
    /// collected (no partial files) and the caller learns why.
    #[test]
    fn collect_stops_at_the_quota() {
        let dir = WorkDir::create().unwrap();
        fs::write(dir.path().join("small"), b"12345").unwrap();
        fs::write(dir.path().join("big"), b"0123456789").unwrap();

        let dst = workdir_root().join(format!("river-wd-quota-{}", std::process::id()));
        let entries = vec![
            CopyOutEntry {
                src_rel: "small".to_string(),
                dst_host: dst.join("small"),
            },
            CopyOutEntry {
                src_rel: "big".to_string(),
                dst_host: dst.join("big"),
            },
        ];
        let got = dir.collect(&entries, Some(5)).unwrap();
        assert!(got.quota_exceeded);
        assert_eq!(got.total_bytes, 5);
        assert_eq!(fs::read(dst.join("small")).unwrap(), b"12345");
        assert!(!dst.join("big").exists(), "no partial/breach files");
        fs::remove_dir_all(&dst).ok();
    }

    /// A junction planted where a product is expected is skipped — the
    /// judger must not read through it (exfiltration channel).
    #[test]
    fn collect_never_follows_junctions() {
        let victim = workdir_root().join(format!("river-wd-victim2-{}", std::process::id()));
        fs::create_dir_all(&victim).unwrap();
        fs::write(victim.join("keep.txt"), b"host-secret").unwrap();

        let dir = WorkDir::create().unwrap();
        let status = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(dir.path().join("leak"))
            .arg(&victim)
            .status()
            .unwrap();
        if !status.success() {
            fs::remove_dir_all(&victim).ok();
            return;
        }

        let dst = workdir_root().join(format!("river-wd-junc-{}", std::process::id()));
        let entries = vec![CopyOutEntry {
            src_rel: "leak".to_string(),
            dst_host: dst.join("leak"),
        }];
        let got = dir.collect(&entries, None).unwrap();
        assert_eq!(got.total_bytes, 0);
        assert!(
            !dst.join("leak").exists(),
            "the junction must not be followed"
        );

        // A junction nested *inside* a collected directory is skipped too.
        fs::create_dir_all(dir.path().join("tree")).unwrap();
        fs::write(dir.path().join("tree/ok"), b"data").unwrap();
        let _ = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(dir.path().join("tree/leak"))
            .arg(&victim)
            .status()
            .unwrap();
        let entries = vec![CopyOutEntry {
            src_rel: "tree".to_string(),
            dst_host: dst.join("tree"),
        }];
        let got = dir.collect(&entries, None).unwrap();
        assert_eq!(got.total_bytes, 4);
        assert_eq!(fs::read(dst.join("tree/ok")).unwrap(), b"data");
        assert!(!dst.join("tree/leak").exists());
        fs::remove_dir_all(&dst).ok();
        fs::remove_dir_all(&victim).ok();
    }
}
