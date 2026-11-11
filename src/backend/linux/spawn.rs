//! Sandbox process creation: one `clone3` call that puts the child into fresh
//! PID/mount/UTS/IPC/network namespaces, hands the parent a pidfd, and lets
//! the child report initialization failures over a CLOEXEC status pipe before
//! it `execve`s the payload.
//!
//! Handshake protocol (same shape as the `examples/linux_*` demos):
//! - child writes 4 bytes (a native-endian errno) once initialization and
//!   `execve` have either succeeded (0) or failed (the errno), then exits;
//! - parent reads exactly 4 bytes: anything non-zero means the run never
//!   started and the errno becomes the caller's error.

use std::ffi::{CStr, CString};
use std::io;
use std::os::raw::{c_char, c_int};

use rustix::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use rustix::pipe::{PipeFlags, pipe_with};

use super::rootfs;
use super::seccomp;

const CLONE_NEWNS: u64 = 0x0002_0000;
const CLONE_NEWUTS: u64 = 0x0400_0000;
const CLONE_NEWIPC: u64 = 0x0800_0000;
const CLONE_NEWPID: u64 = 0x2000_0000;
const CLONE_NEWNET: u64 = 0x4000_0000;
const CLONE_PIDFD: u64 = 0x0000_1000;
const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;

const SANDBOX_NAMESPACES: u64 =
    CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWPID | CLONE_NEWNET;

/// Kernel `struct clone_args` for the raw `clone3` syscall.
#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

/// Everything the child needs, pre-built: after `clone3` the child must not
/// allocate through the Python-embedding heap, so every path and string is
/// a finished `CString` before the fork point.
pub(crate) struct ChildSpec {
    pub executable: CString,
    pub args: Vec<CString>,
    pub envp: Vec<CString>,
    /// Working directory inside the sandbox (e.g. `/workspace`).
    pub cwd: CString,
    /// Host path of the session scratch directory (bind source).
    pub workdir: CString,
    /// Host runtime directories to expose read-only at `/runtime/<name>`.
    pub runtimes: Vec<CString>,
    /// Host directory used as the sandbox root via overlayfs, if any.
    pub rootfs: Option<CString>,
    /// Inheritable fds for stdin/stdout/stderr; `None` keeps the parent's.
    pub stdio: [Option<OwnedFd>; 3],
    /// Directory fd of the cgroup the child is born into (limits must
    /// already be applied to it), if any.
    pub cgroup: Option<OwnedFd>,
    /// Pre-compiled seccomp program (built before the fork point: the child
    /// must not allocate through the Python-embedding heap).
    pub seccomp: seccompiler::BpfProgram,
}

/// A started sandbox child: the pidfd to wait on and the read end of the
/// status pipe that carries the handshake.
pub(crate) struct Child {
    pub pidfd: OwnedFd,
    pub status: OwnedFd,
}

/// Spawns the sandboxed child. The caller waits on the pidfd (never on the
/// namespace-external pid, which avoids PID-reuse races).
pub(crate) fn spawn(spec: ChildSpec) -> io::Result<Child> {
    let (status_r, status_w) = pipe_with(PipeFlags::CLOEXEC)?;

    let mut pidfd_raw: c_int = -1;
    let (cgroup_flag, cgroup_fd) = match &spec.cgroup {
        Some(fd) => (CLONE_INTO_CGROUP, fd.as_fd().as_raw_fd() as u64),
        None => (0, 0),
    };
    let args = CloneArgs {
        flags: SANDBOX_NAMESPACES | CLONE_PIDFD | cgroup_flag,
        pidfd: std::ptr::addr_of_mut!(pidfd_raw) as u64,
        exit_signal: libc::SIGCHLD as u64,
        cgroup: cgroup_fd,
        ..Default::default()
    };

    // SAFETY: `clone_args` matches the kernel layout; without CLONE_VM the
    // child is a plain fork-style copy and both sides return through here.
    let pid_raw = unsafe { libc::syscall(libc::SYS_clone3, &args, std::mem::size_of::<CloneArgs>()) };

    if pid_raw == 0 {
        drop(status_r);
        child(spec, status_w);
    }
    if pid_raw < 0 {
        return Err(io::Error::last_os_error());
    }

    drop(status_w); // from here on only the child holds the write end
    // SAFETY: the kernel installed this fresh pidfd for this process.
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd_raw) };
    Ok(Child {
        pidfd,
        status: status_r,
    })
}

/// The child side. Never returns: it reports the outcome over the status
/// pipe (a native-endian errno + stage code pair) and either becomes the
/// payload or exits.
fn child(spec: ChildSpec, status_w: OwnedFd) -> ! {
    // The parent may run under any signal disposition; reset everything so
    // the payload starts with the default table. 65 covers the real-time
    // signals on Linux.
    let mut stage = 0u32;
    unsafe {
        for signal in 1..65 {
            libc::signal(signal, libc::SIG_DFL);
        }
    }

    let result = child_setup(&spec, &mut stage);
    if let Err(errno) = result {
        report(&status_w, errno, stage);
        unsafe { libc::_exit(126) };
    }

    // chdir before execve: after the pivot the cwd path is container-relative.
    stage = 2;
    if unsafe { libc::chdir(spec.cwd.as_ptr()) } != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        report(&status_w, errno, stage);
        unsafe { libc::_exit(126) };
    }

    // seccomp last: the rootfs setup above needs mount/pivot_root, which
    // the filter denies.
    stage = 5;
    if let Err(errno) = seccomp::apply(&spec.seccomp) {
        report(&status_w, errno, stage);
        unsafe { libc::_exit(126) };
    }

    // No "0" report here: a successful execve closes the CLOEXEC pipe and
    // the parent reads EOF; only a failed execve reports (below).
    let err = exec_payload(&spec);
    report(&status_w, err, 4);
    unsafe { libc::_exit(127) };
}

/// Stage names owned by this module (the rootfs phases map their own).
pub(crate) fn stage_name(stage: u32) -> &'static str {
    match stage {
        0 | 1 => "sandbox setup",
        2 => "chdir into the sandbox cwd",
        4 => "execve",
        5 => "seccomp",
        other => rootfs::stage_name(other),
    }
}

fn child_setup(spec: &ChildSpec, stage: &mut u32) -> Result<(), i32> {
    *stage = 1;
    rootfs::setup_and_pivot(&spec.workdir, &spec.runtimes, spec.rootfs.as_deref(), stage)?;
    for (slot, fd) in spec.stdio.iter().enumerate() {
        if let Some(fd) = fd {
            let raw = fd.as_fd().as_raw_fd();
            if unsafe { libc::dup2(raw, slot as c_int) } < 0 {
                return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1));
            }
        }
    }
    Ok(())
}

/// `execve` with `execvp`-style PATH search against the sandbox view. A name
/// without `/` is looked up in the `PATH` variable of `envp`.
fn exec_payload(spec: &ChildSpec) -> i32 {
    let mut argv: Vec<*const c_char> = Vec::with_capacity(spec.args.len() + 2);
    argv.push(spec.executable.as_ptr());
    for arg in &spec.args {
        argv.push(arg.as_ptr());
    }
    argv.push(std::ptr::null());
    let mut envp: Vec<*const c_char> = Vec::with_capacity(spec.envp.len() + 1);
    for var in &spec.envp {
        envp.push(var.as_ptr());
    }
    envp.push(std::ptr::null());

    unsafe fn execve(path: &CStr, argv: &[*const c_char], envp: &[*const c_char]) -> i32 {
        let ret = unsafe {
            libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr())
        };
        debug_assert!(ret != 0, "a successful execve never returns");
        std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
    }

    let path_bytes = spec.executable.to_bytes();
    if path_bytes.contains(&b'/') {
        return unsafe { execve(&spec.executable, &argv, &envp) };
    }
    let path_var = spec
        .envp
        .iter()
        .find(|var| var.to_bytes().starts_with(b"PATH="))
        .map(|var| &var.to_bytes()[b"PATH=".len()..])
        .unwrap_or(b"/bin:/usr/bin");
    for dir in path_var.split(|&b| b == b':') {
        let dir = if dir.is_empty() { b"." } else { dir };
        let mut candidate_bytes = dir.to_vec();
        candidate_bytes.extend_from_slice(b"/");
        candidate_bytes.extend_from_slice(path_bytes);
        let Ok(candidate) = CString::new(candidate_bytes) else {
            continue;
        };
        let errno = unsafe { execve(&candidate, &argv, &envp) };
        if errno != libc::ENOENT && errno != libc::ENOTDIR {
            return errno;
        }
    }
    libc::ENOENT
}

fn report(pipe: &OwnedFd, errno: i32, stage: u32) {
    let mut message = errno.to_ne_bytes().to_vec();
    message.extend_from_slice(&stage.to_ne_bytes());
    let _ = rustix::io::write(pipe, &message);
}
