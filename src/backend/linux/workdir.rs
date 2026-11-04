//! Per-run private working directory.
//!
//! The only writable place the sandboxed program sees. Created fresh per
//! run, provisioned with `copy_in` files (read-only for the program), and
//! removed on drop — also on every error path (RAII, mirroring the Windows
//! `WorkDir` guard).
//!
//! `copy_in` read-only enforcement (docs/linux-plan.md §2.1): files are
//! written/copyed as root and chmod'd 0444; the sandboxed program runs as
//! `nobody` (uid drop, stage L3) and cannot rewrite them. No ACL machinery
//! is needed on Linux.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::contract::CopyInSource;

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
    pub(crate) fn provision(
        &self,
        files: &std::collections::HashMap<String, CopyInSource>,
    ) -> io::Result<()> {
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
            make_read_only(&target)?;
        }
        Ok(())
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
}
