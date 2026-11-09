use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::contract::{CopyInSource, CopyOutEntry};

static COUNTER: AtomicU64 = AtomicU64::new(0);

pub(crate) struct WorkDir {
    path: PathBuf,
    _owner: std::fs::File,
}

fn owner_path(dir: &Path) -> PathBuf {
    let mut s = dir.as_os_str().to_os_string();
    s.push(".lock");
    PathBuf::from(s)
}

impl WorkDir {
    pub(crate) fn create() -> io::Result<Self> {
        let base = std::env::temp_dir();
        let mut last_err = None;
        for _ in 0..8 {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = base.join(format!("river-{}-{}-{:x}", std::process::id(), n, nanos));
            match create_private_dir(&path) {
                Ok(()) => {
                    let owner = fs::OpenOptions::new()
                        .create(true)
                        .truncate(false)
                        .write(true)
                        .open(owner_path(&path))?;
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
                Err(_) => continue,
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

    pub(crate) fn grant_to(&self, uid: libc::uid_t, gid: libc::gid_t) -> io::Result<()> {
        chown(&self.path, uid, gid)?;
        chmod(&self.path, 0o700)
    }

    pub(crate) fn grant_dir_to(dir: &Path, uid: libc::uid_t, gid: libc::gid_t) -> io::Result<()> {
        chown(dir, uid, gid)?;
        chmod(dir, 0o700)
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
        let _ = fs::remove_file(owner_path(&self.path));
    }
}

#[derive(Default)]
pub(crate) struct Collected {
    pub total_bytes: u64,
    pub quota_exceeded: bool,
}

fn provision_dir(src: &Path, dst: &Path) -> io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        if entry.file_type()?.is_symlink() {
            continue;
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
            continue;
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

fn make_read_only(path: &Path) -> io::Result<()> {
    chmod(path, 0o444)
}

fn create_private_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path)
}

fn chown(path: &Path, uid: libc::uid_t, gid: libc::gid_t) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))?;
    if unsafe { libc::chown(c.as_ptr(), uid, gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn chmod(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

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

fn pid_is_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

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
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        if !is_dir {
            continue;
        }
        match fs::OpenOptions::new().write(true).open(owner_path(&path)) {
            Ok(owner) => match lock_owner(&owner, true) {
                Ok(()) => {
                    let _ = lock_owner(&owner, false);
                    drop(owner);
                    let _ = fs::remove_dir_all(&path);
                    let _ = fs::remove_file(owner_path(&path));
                }
                Err(_) => continue,
            },
            Err(_) => {
                if path.join(".owner").exists()
                    && let Ok(owner) = fs::OpenOptions::new().write(true).open(path.join(".owner"))
                    && lock_owner(&owner, true).is_err()
                {
                    continue;
                }
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

fn owner_pid_of(dir_name: &str) -> Option<u32> {
    dir_name
        .strip_prefix("river-")?
        .split('-')
        .next()?
        .parse()
        .ok()
}
