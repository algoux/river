//! Host-side I/O (design.md §10): the `/work` directory, copy_in/copy_out
//! key validation, the hardened reads below `/work` and the stdio pipes.
//!
//! Everything the host reads out of a run's work directory goes through
//! `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)` on a dirfd of that
//! directory: the sandbox owned the tree until a moment ago, so a plain
//! path lookup could follow a symlink the sandbox planted into host files
//! (or out of the directory entirely), and a `stat`-then-`read` pair could
//! be racing a swap. `openat2` resolves and opens in one step, and the
//! regular-file and size checks happen on the resulting fd.

use std::ffi::CString;
use std::fs::{self, File};
use std::io;
use std::io::Read;
use std::os::fd::{FromRawFd, RawFd};
use std::path::{Component, Path, PathBuf};

use crate::exec::CopyInValue;

/// Lexically normalized sandbox path of a key: absolute keys are used
/// as-is, relative ones resolve against `cwd`. Pure path algebra — no
/// location enforcement (that is `sandbox_path`'s job).
pub fn normalized_sandbox_path(key: &str, cwd: &str) -> Result<PathBuf, String> {
    if key.is_empty() {
        return Err("sandbox path must not be empty".to_string());
    }
    if key.contains('\0') {
        return Err(format!("sandbox path {key:?} contains a NUL byte"));
    }
    let joined = if key.starts_with('/') {
        PathBuf::from(key)
    } else {
        Path::new(cwd).join(key)
    };
    if !joined.is_absolute() {
        return Err(format!("cwd {cwd:?} is not an absolute sandbox path"));
    }
    let mut out = PathBuf::from("/");
    for comp in joined.components() {
        match comp {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(part) => out.push(part),
            Component::ParentDir => {
                if !out.pop() {
                    return Err(format!("sandbox path {key:?} escapes the sandbox root"));
                }
            }
            Component::Prefix(_) => unreachable!("no prefix components on Linux"),
        }
    }
    Ok(out)
}

/// copy_in/copy_out key, normalized and enforced strictly below /work
/// (design.md §10).
pub fn sandbox_path(key: &str, cwd: &str) -> Result<PathBuf, String> {
    let out = normalized_sandbox_path(key, cwd)?;
    if out == Path::new("/work") {
        return Err(format!(
            "sandbox path {key:?} must name something below /work, not /work itself"
        ));
    }
    if !out.starts_with("/work") {
        return Err(format!(
            "sandbox path {key:?} resolves to {}, which is not below /work",
            out.display()
        ));
    }
    Ok(out)
}

/// Host-side location of a normalized sandbox path under this run's work
/// directory: `/work/x` maps onto `<work_dir>/x` (the bind root *is* /work).
fn host_path(work_dir: &Path, sandbox: &Path) -> PathBuf {
    work_dir.join(sandbox.strip_prefix("/work").unwrap())
}

/// Writes every copy_in entry into the host work directory (design.md §10).
/// Nested keys get their parent directories created. The directory was
/// created by river a moment ago and nothing else has seen it yet, so
/// plain path operations are fine here (contrast [`open_beneath`]).
pub fn write_copy_in(
    work_dir: &Path,
    cwd: &str,
    items: &[(String, CopyInValue)],
) -> Result<(), String> {
    for (key, value) in items {
        let host = host_path(work_dir, &sandbox_path(key, cwd)?);
        if let Some(parent) = host.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("copy_in {key:?}: cannot create {}: {e}", parent.display()))?;
        }
        match value {
            CopyInValue::Bytes(data) => fs::write(&host, data)
                .map_err(|e| format!("copy_in {key:?}: cannot write {}: {e}", host.display())),
            CopyInValue::HostFile(src) => {
                let data = fs::read(src).map_err(|e| {
                    format!("copy_in {key:?}: cannot read {}: {e}", src.display())
                })?;
                fs::write(&host, data)
                    .map_err(|e| format!("copy_in {key:?}: cannot write {}: {e}", host.display()))
            }
        }?;
    }
    Ok(())
}

// ------------------------------------------------------------ hardened reads

/// `struct open_how` from `<linux/openat2.h>`, hand-declared: libc's copy
/// is `#[non_exhaustive]`, and rustix 0.38 does not re-export the flag
/// type its `openat2` takes (same situation as `mount_setattr`, see
/// mount.rs).
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// Opens this run's host work directory as the dirfd every sandbox-path
/// lookup below it starts from (`RESOLVE_BENEATH` is relative to it, so
/// the work directory's own ancestors are not part of the resolution).
pub fn open_work_dir(work_dir: &Path) -> io::Result<File> {
    File::open(work_dir)
}

/// `openat2(work_fd, rel, O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC,
/// RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)` on a path already normalized by
/// [`sandbox_path`]: `/work/x/y` is looked up as `x/y` below the dirfd.
/// A symlink anywhere on the path answers `ELOOP`, a path leaving the
/// directory `EXDEV`, a missing component `ENOENT`, a non-directory used
/// as one `ENOTDIR` — all before any file is opened. `O_NONBLOCK` keeps a
/// planted FIFO from blocking the open (its writer is dead); the
/// regular-file check on the fd then rejects it.
pub fn open_beneath(work_fd: RawFd, sandbox: &Path) -> io::Result<File> {
    let rel = sandbox
        .strip_prefix("/work")
        .expect("sandbox_path already pinned the path below /work");
    let rel = CString::new(rel.to_string_lossy().as_bytes())
        .expect("normalized sandbox paths contain no NUL");
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS,
    };
    // SAFETY: `how` outlives the call and has the kernel's struct size;
    // the syscall only writes the return value.
    let r = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            work_fd as libc::c_int,
            rel.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh fd from a successful openat2, wrapped exactly once.
    Ok(unsafe { File::from_raw_fd(r as RawFd) })
}

/// The human-readable half of a `CopyOutError` (design.md §4: missing /
/// not a regular file / over the limit), for a lookup that failed.
fn describe_open_error(e: &io::Error) -> String {
    match e.raw_os_error() {
        Some(libc::ENOENT) => "is missing".to_string(),
        Some(libc::ELOOP) => {
            "is not a regular file: a symlink is on the path, and copy_out never follows symlinks"
                .to_string()
        }
        Some(libc::EXDEV) => "leaves /work, which copy_out refuses".to_string(),
        Some(libc::ENOTDIR) => "is not a regular file (a path component is not a directory)".to_string(),
        _ => format!("cannot be opened: {e}"),
    }
}

/// One copy_out entry that could not be retrieved (design.md §10).
pub struct CopyOutFailure {
    /// The offending `copy_out` key, exactly as the caller spelled it.
    pub key: String,
    /// Why; the `CopyOutError` message is `copy_out {key:?}: {reason}`.
    pub reason: String,
}

impl CopyOutFailure {
    fn new(key: &str, reason: String) -> Self {
        CopyOutFailure {
            key: key.to_string(),
            reason,
        }
    }
}

/// Retrieves every copy_out entry (design.md §10): `None` values land in
/// `r.files[key]`, host paths get the content written over them. Every
/// entry is read first and the host destinations are written only once
/// all of them succeeded, so a failing run leaves no half-written host
/// files; the first failing entry aborts the collection.
pub fn read_copy_out(
    work_fd: RawFd,
    cwd: &str,
    items: &[(String, Option<String>)],
    limit: Option<u64>,
) -> Result<Vec<(String, Vec<u8>)>, CopyOutFailure> {
    let mut files = Vec::new();
    let mut host_writes: Vec<(String, String, Vec<u8>)> = Vec::new();
    for (key, dest) in items {
        let sandbox = sandbox_path(key, cwd).map_err(|e| CopyOutFailure::new(key, e))?;
        let mut file = open_beneath(work_fd, &sandbox)
            .map_err(|e| CopyOutFailure::new(key, describe_open_error(&e)))?;
        // Checked on the fd, i.e. on the very object the read below uses.
        let meta = file
            .metadata()
            .map_err(|e| CopyOutFailure::new(key, format!("cannot be inspected: {e}")))?;
        if !meta.is_file() {
            return Err(CopyOutFailure::new(key, "is not a regular file".to_string()));
        }
        if let Some(limit) = limit {
            if meta.len() > limit {
                return Err(CopyOutFailure::new(
                    key,
                    format!("is {} bytes, above copy_out_limit_bytes={limit}", meta.len()),
                ));
            }
        }
        let mut data = Vec::with_capacity(meta.len() as usize);
        file.read_to_end(&mut data)
            .map_err(|e| CopyOutFailure::new(key, format!("cannot be read: {e}")))?;
        // Nothing else is alive in the tree, but the size check is free.
        if let Some(limit) = limit {
            if data.len() as u64 > limit {
                return Err(CopyOutFailure::new(
                    key,
                    format!("is {} bytes, above copy_out_limit_bytes={limit}", data.len()),
                ));
            }
        }
        match dest {
            None => files.push((key.clone(), data)),
            Some(dest) => host_writes.push((key.clone(), dest.clone(), data)),
        }
    }
    for (key, dest, data) in host_writes {
        fs::write(&dest, &data).map_err(|e| {
            CopyOutFailure::new(&key, format!("cannot be written to {}: {e}", dest))
        })?;
    }
    Ok(files)
}

// ------------------------------------------------------------------- pipes

/// `pipe2(O_CLOEXEC)`.
pub fn pipe() -> io::Result<(RawFd, RawFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` is a valid out-array of two ints.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((fds[0], fds[1]))
}

/// `socketpair(AF_UNIX, SOCK_SEQPACKET|O_CLOEXEC)`: datagram semantics keep
/// the 8-byte failure report a single message.
pub fn socketpair_seqpacket() -> io::Result<(RawFd, RawFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` is a valid out-array of two ints.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((fds[0], fds[1]))
}

/// Sets `O_NONBLOCK` on an fd the parent will poll.
pub fn set_nonblock(fd: RawFd) -> io::Result<()> {
    // SAFETY: plain fcntl(F_GETFL/F_SETFL).
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: plain fcntl(F_SETFL).
    let r = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Writes the whole buffer to a seqpacket/socket fd; returns the errno on
/// failure.
pub fn write_all_fd(fd: RawFd, data: &[u8]) -> io::Result<()> {
    let mut done = 0;
    while done < data.len() {
        // SAFETY: write(2) on a private buffer slice.
        let r = unsafe {
            libc::write(
                fd,
                data[done..].as_ptr() as *const libc::c_void,
                data.len() - done,
            )
        };
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        done += r as usize;
    }
    Ok(())
}
