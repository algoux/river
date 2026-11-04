//! Per-run private working directory.
//!
//! The only writable place the sandboxed program sees. Created fresh per
//! run, provisioned with `copy_in` files (read-only for the program), and
//! removed on drop — also on every error path (RAII, mirroring the Windows
//! `WorkDir` guard).
//!
//! `copy_in` read-only enforcement: files are
//! written/copied as root and chmod'd 0444; the sandboxed program runs as
//! `nobody` (uid drop) and cannot rewrite them. No ACL machinery
//! is needed on Linux.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::contract::{CopyInSource, CopyOutEntry};

/// Monotonic per-process counter so concurrent runs never collide on the
/// same directory name (pid alone is reused over time; pid + counter +
/// nanos makes an accidental collision practically impossible).
static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Per-run working directory; removes itself on drop.
///
/// Liveness for the stale sweep is proven by an **exclusive flock on
/// `.owner`**, not by the pid in the name: pids are reused within
/// milliseconds, so `/proc/<pid>` alone would make a just-killed judger's
/// directory look alive (observed in the lifecycle test).
pub(crate) struct WorkDir {
    path: PathBuf,
    /// Held for the run's lifetime; the lock is released by the kernel when
    /// the judger dies (that is the sweep's "owner is gone" signal).
    _owner: std::fs::File,
}

impl WorkDir {
    /// Create a fresh private working directory under the system temp dir.
    pub(crate) fn create() -> io::Result<Self> {
        let base = std::env::temp_dir();
        let mut last_err = None;
        for _ in 0..8 {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = base.join(format!("river-{}-{}-{:x}", std::process::id(), n, nanos));
            match fs::create_dir(&path) {
                Ok(()) => {
                    let owner = fs::OpenOptions::new()
                        .create(true)
                        .truncate(false)
                        .write(true)
                        .open(path.join(".owner"))?;
                    lock_owner(&owner, true)?;
                    return Ok(WorkDir {
                        path,
                        _owner: owner,
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    last_err = Some(e);
                }
                Err(e) => return Err(e),
            }
        }
        Err(last_err
            .unwrap_or_else(|| io::Error::other("WorkDir::create: name collision retry exhausted")))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Provision `copy_in` entries into the working directory. Keys are
    /// sandbox-relative paths (validated upstream by `contract::validate`);
    /// parent directories are created as needed. Every file ends up
    /// root-owned mode 0444 (read-only for the untrusted nobody).
    ///
    /// A `CopyInSource::Path` value pointing at a host **directory** is
    /// provisioned recursively (regular files and subdirectories; symlinks
    /// are skipped — a trusted-source convenience that must never become a
    /// link-farm).
    pub(crate) fn provision(
        &self,
        files: &std::collections::HashMap<String, CopyInSource>,
    ) -> io::Result<()> {
        for (rel, source) in files {
            let target = self.path.join(rel);
            match source {
                CopyInSource::Bytes(bytes) => {
                    if let Some(parent) = target.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    fs::write(&target, bytes)?;
                    make_read_only(&target)?;
                }
                CopyInSource::Path(src) => {
                    let md = fs::symlink_metadata(src)?;
                    if md.is_dir() {
                        provision_dir(src, &target)?;
                    } else {
                        if let Some(parent) = target.parent() {
                            fs::create_dir_all(parent)?;
                        }
                        fs::copy(src, &target)?;
                        make_read_only(&target)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Collect `copy_out` products from the working directory into their
    /// host destinations (called after the run ended, before the Drop).
    ///
    /// **Never follows symlinks**: the program could plant a link pointing
    /// at any host path, and the judger runs as root — following it would
    /// be an arbitrary-host-file exfiltration channel. Symlinked entries
    /// are skipped entirely; missing sources are skipped (optional
    /// products). Collection stops at the first file that would push the
    /// total past `quota_bytes` (that file is *not* collected — no partial
    /// files).
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
            if md.file_type().is_symlink() {
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

    /// Hand the working directory to the unprivileged program: the tree is
    /// bind-mounted into the sandbox as `/cwd`, so its owner must be the
    /// sandbox uid or the program cannot create files there. Directories
    /// are chowned recursively; `copy_in` **files** stay root-owned mode
    /// 0444 (the read-only contract, DESIGN §3.3).
    pub(crate) fn grant_to(&self, uid: libc::uid_t, gid: libc::gid_t) -> io::Result<()> {
        use std::os::unix::ffi::OsStrExt;
        let mut stack = vec![self.path.clone()];
        while let Some(dir) = stack.pop() {
            let c = std::ffi::CString::new(dir.as_os_str().as_bytes())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))?;
            let rc = unsafe { libc::chown(c.as_ptr(), uid, gid) };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            for entry in fs::read_dir(&dir)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    stack.push(entry.path());
                }
            }
        }
        Ok(())
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        // Best effort: a leftover directory is recovered by the stale-dir
        // sweep (stage L5) rather than masking the real error of a run.
        let _ = fs::remove_dir_all(&self.path);
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

/// Recursively provision a host source directory into the working
/// directory (`copy_in` with a directory value). Regular files and
/// subdirectories only; symlinks are skipped.
fn provision_dir(src: &Path, dst: &Path) -> io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        if entry.file_type()?.is_symlink() {
            continue; // never provision link farms
        }
        let md = entry.metadata()?;
        let target = dst.join(entry.file_name());
        if md.is_dir() {
            provision_dir(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), &target)?;
            make_read_only(&target)?;
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
        if entry.file_type()?.is_symlink() {
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
/// accounting. Opened with `O_NOFOLLOW` — a symlink swapped in place of a
/// regular file after `symlink_metadata` is refused, not followed (TOCTOU).
fn copy_one(
    src: &Path,
    dst: &Path,
    quota_bytes: Option<u64>,
    out: &mut Collected,
) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut src_file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(src)?;
    let size = src_file.metadata()?.len();
    if let Some(quota) = quota_bytes
        && out.total_bytes + size > quota
    {
        // Do not collect a file that would breach the quota (no partial
        // files); the caller sees `quota_exceeded` and reports OLE.
        out.quota_exceeded = true;
        return Ok(());
    }
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut dst_file = fs::File::create(dst)?;
    std::io::copy(&mut src_file, &mut dst_file)?;
    out.total_bytes += size;
    Ok(())
}

/// Best-effort read-only (u+r, go-rwx). Must not fail provisioning: a
/// program that could write its copy_in files is an attack-suite failure,
/// so any chmod error here is loud.
fn make_read_only(path: &Path) -> io::Result<()> {
    let mut perms = fs::metadata(path)?.permissions();
    use std::os::unix::fs::PermissionsExt;
    perms.set_mode(0o444);
    fs::set_permissions(path, perms)
}

/// Try to take (or release) the ownership lock on a workdir.
///
/// `flock` is per open-file-description and survives fork/exec (the program
/// does not need it, but only the judger holds the fd), so the lock
/// disappears exactly when the last judger fd closes — including on
/// SIGKILL.
fn lock_owner(file: &std::fs::File, exclusive: bool) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let op = if exclusive {
        libc::LOCK_EX | libc::LOCK_NB
    } else {
        libc::LOCK_UN
    };
    let rc = unsafe { libc::flock(file.as_raw_fd(), op) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Does a process with this pid currently exist?
fn pid_is_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/// Best-effort sweep of working directories abandoned by a **dead** judger
/// process (e.g. the judger was hard-killed mid-run: `Drop` never ran; the
/// sandboxed processes died via the watchdog, but the directory remained).
///
/// Ownership is decided by the `.owner` lock, not by the pid:
/// - lock acquirable  => the owner process is gone => remove the directory;
/// - lock held (EWOULDBLOCK) => a live run => leave it alone;
/// - no `.owner` file (directory from an older build) => fall back to the
///   `river-{pid}-...` name check.
///
/// Concurrency: two sweeps racing on the same directory are serialized
/// through a process-global lock.
pub(crate) fn sweep_stale_workdirs() {
    static SWEEP_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = SWEEP_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let entries = match fs::read_dir(std::env::temp_dir()) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with("river-") {
            continue;
        }
        let path = entry.path();
        match fs::OpenOptions::new().write(true).open(path.join(".owner")) {
            Ok(owner) => match lock_owner(&owner, true) {
                Ok(()) => {
                    let _ = lock_owner(&owner, false);
                    drop(owner);
                    let _ = fs::remove_dir_all(&path);
                }
                Err(_) => continue, // live owner
            },
            Err(_) => {
                let Some(pid) = owner_pid_of(name) else {
                    continue;
                };
                if pid_is_alive(pid) {
                    continue;
                }
                let _ = fs::remove_dir_all(&path);
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Provisioned files exist, carry exactly the given bytes, and are
    /// mode 0444 (non-trivial: removing the chmod in `provision` must make
    /// this fail).
    #[test]
    fn provisioned_copy_in_is_read_only_0444() {
        use std::os::unix::fs::PermissionsExt;
        let workdir = WorkDir::create().unwrap();
        let mut files = std::collections::HashMap::new();
        files.insert(
            "in.txt".to_string(),
            CopyInSource::Bytes(b"payload".to_vec()),
        );
        workdir.provision(&files).unwrap();
        let p = workdir.path().join("in.txt");
        assert_eq!(fs::read(&p).unwrap(), b"payload");
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o444
        );
    }

    /// Nested copy_in keys get their parent directories created.
    #[test]
    fn provision_creates_nested_directories() {
        let workdir = WorkDir::create().unwrap();
        let mut files = std::collections::HashMap::new();
        files.insert(
            "a/b/c.txt".to_string(),
            CopyInSource::Bytes(b"nested".to_vec()),
        );
        workdir.provision(&files).unwrap();
        assert_eq!(
            fs::read(workdir.path().join("a/b/c.txt")).unwrap(),
            b"nested"
        );
    }

    /// The directory is removed on drop (non-trivial: deleting the Drop impl
    /// body must make this fail).
    #[test]
    fn workdir_is_removed_on_drop() {
        let path;
        {
            let workdir = WorkDir::create().unwrap();
            path = workdir.path().to_path_buf();
        }
        assert!(!path.exists(), "workdir survived its own Drop");
    }

    /// A directory-valued `copy_in` is provisioned recursively, read-only;
    /// symlinks inside it are skipped, not followed.
    #[test]
    fn provision_copy_in_directory_recursively() {
        let host = std::env::temp_dir().join(format!("river-wd-src-{}", std::process::id()));
        fs::create_dir_all(host.join("sub")).unwrap();
        fs::write(host.join("a.txt"), b"A").unwrap();
        fs::write(host.join("sub/b.txt"), b"B").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/etc/passwd", host.join("evil")).unwrap();
        // Non-unix: the linux module only compiles on linux anyway.

        let workdir = WorkDir::create().unwrap();
        let mut files = std::collections::HashMap::new();
        files.insert("proj".to_string(), CopyInSource::Path(host.clone()));
        workdir.provision(&files).unwrap();

        assert_eq!(fs::read(workdir.path().join("proj/a.txt")).unwrap(), b"A");
        assert_eq!(
            fs::read(workdir.path().join("proj/sub/b.txt")).unwrap(),
            b"B"
        );
        assert!(
            !workdir.path().join("proj/evil").exists(),
            "symlinks must not be provisioned"
        );
        fs::remove_dir_all(&host).ok();
    }

    /// `copy_out` writes the product to the host path and reports its size.
    #[test]
    fn collect_copies_products_to_host_paths() {
        let workdir = WorkDir::create().unwrap();
        fs::write(workdir.path().join("out.txt"), b"product").unwrap();
        fs::create_dir_all(workdir.path().join("tree/nested")).unwrap();
        fs::write(workdir.path().join("tree/nested/x"), b"XX").unwrap();

        let dst_dir = std::env::temp_dir().join(format!("river-wd-dst-{}", std::process::id()));
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
        let got = workdir.collect(&entries, None).unwrap();
        assert_eq!(got.total_bytes, 9); // 7 + 2
        assert!(!got.quota_exceeded);
        assert_eq!(fs::read(dst_dir.join("collected.txt")).unwrap(), b"product");
        assert_eq!(fs::read(dst_dir.join("tree/nested/x")).unwrap(), b"XX");
        let _ = fs::remove_dir_all(&dst_dir);
    }

    /// The quota stops the collection: files that would breach it are not
    /// collected (no partial files) and the caller learns why.
    #[test]
    fn collect_stops_at_the_quota() {
        let workdir = WorkDir::create().unwrap();
        fs::write(workdir.path().join("small"), b"12345").unwrap();
        fs::write(workdir.path().join("big"), b"0123456789").unwrap();

        let dst = std::env::temp_dir().join(format!("river-wd-quota-{}", std::process::id()));
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
        let got = workdir.collect(&entries, Some(5)).unwrap();
        assert!(got.quota_exceeded);
        assert_eq!(got.total_bytes, 5);
        assert_eq!(fs::read(dst.join("small")).unwrap(), b"12345");
        assert!(!dst.join("big").exists(), "no partial/breach files");
        let _ = fs::remove_dir_all(&dst);
    }

    /// A symlink planted where a product is expected is skipped — the
    /// judger runs as root, so following it would exfiltrate host files.
    #[cfg(unix)]
    #[test]
    fn collect_never_follows_symlinks() {
        use std::os::unix::fs::symlink;
        let victim = std::env::temp_dir().join(format!("river-wd-victim-{}", std::process::id()));
        fs::write(&victim, b"host-secret").unwrap();

        let workdir = WorkDir::create().unwrap();
        symlink(&victim, workdir.path().join("leak")).unwrap();
        symlink("/nonexistent", workdir.path().join("dangling")).unwrap();

        let dst = std::env::temp_dir().join(format!("river-wd-link-{}", std::process::id()));
        let entries = vec![CopyOutEntry {
            src_rel: "leak".to_string(),
            dst_host: dst.join("leak"),
        }];
        let got = workdir.collect(&entries, None).unwrap();
        assert_eq!(got.total_bytes, 0);
        assert!(!dst.join("leak").exists(), "the link must not be followed");

        // A symlink nested *inside* a collected directory is skipped too.
        fs::create_dir_all(workdir.path().join("tree")).unwrap();
        fs::write(workdir.path().join("tree/ok"), b"data").unwrap();
        symlink(&victim, workdir.path().join("tree/leak")).unwrap();
        let entries = vec![CopyOutEntry {
            src_rel: "tree".to_string(),
            dst_host: dst.join("tree"),
        }];
        let got = workdir.collect(&entries, None).unwrap();
        assert_eq!(got.total_bytes, 4);
        assert_eq!(fs::read(dst.join("tree/ok")).unwrap(), b"data");
        assert!(!dst.join("tree/leak").exists());
        let _ = fs::remove_file(&victim);
        let _ = fs::remove_dir_all(&dst);
    }
}
