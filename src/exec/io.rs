//! Host-side I/O (design.md §10): the `/work` directory, copy_in/copy_out
//! key validation and the stdio pipes. The `openat2`
//! `RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS` hardening and `CopyOutError.result`
//! are PR 5's scope; PR 2 uses plain fs operations on lexically validated
//! paths (the work directory only ever contains what copy_in put there).

use std::fs;
use std::io;
use std::os::fd::RawFd;
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
/// Nested keys get their parent directories created.
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

/// Retrieves every copy_out entry (design.md §10): `None` values land in
/// `r.files[key]`, host paths get the content written over them. The first
/// failing entry aborts the run's collection and surfaces as `CopyOutError`.
pub fn read_copy_out(
    work_dir: &Path,
    cwd: &str,
    items: &[(String, Option<String>)],
    limit: Option<u64>,
) -> Result<Vec<(String, Vec<u8>)>, (String, String)> {
    let mut out = Vec::new();
    for (key, dest) in items {
        let host = host_path(work_dir, &sandbox_path(key, cwd).map_err(|e| (key.clone(), e))?);
        let fail = |reason: String| (key.clone(), reason);
        let meta = fs::symlink_metadata(&host)
            .map_err(|e| fail(format!("cannot read {}: {e}", host.display())))?;
        if !meta.is_file() {
            return Err(fail(format!(
                "{} is not a regular file",
                host.display()
            )));
        }
        if let Some(limit) = limit {
            if meta.len() > limit {
                return Err(fail(format!(
                    "{} bytes exceeds copy_out_limit_bytes={limit}",
                    meta.len()
                )));
            }
        }
        let data = fs::read(&host)
            .map_err(|e| fail(format!("cannot read {}: {e}", host.display())))?;
        match dest {
            None => out.push((key.clone(), data)),
            Some(host_dest) => fs::write(host_dest, &data)
                .map_err(|e| fail(format!("cannot write {}: {e}", host_dest)))?,
        }
    }
    Ok(out)
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
