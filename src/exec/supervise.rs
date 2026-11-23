//! Parent-side event loop (design.md §3 step 7): a single-threaded epoll over
//! the pidfd, the sync socket, the output pipes and the stdin write end.
//!
//! PR 2 uses the epoll timeout only to watch for Ctrl-C (the wall-clock
//! deadline kill lands in PR 3, together with the run cgroup). Output past
//! the limits keeps being read and discarded; the `OLE` verdict and kill are
//! PR 3's as well.

use std::io;
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};

use pyo3::Python;
use rustix::event::epoll;
use rustix::io::Errno;

use super::SyncMsg;

// Epoll tokens; `EventData::new_u64` carries them back on every event.
const TOKEN_PIDFD: u64 = 1;
const TOKEN_SYNC: u64 = 2;
const TOKEN_STDOUT: u64 = 3;
const TOKEN_STDERR: u64 = 4;
const TOKEN_STDIN: u64 = 5;

/// Everything supervise owns for one run; dropping it closes every fd still
/// held (closing the stdin write end is what signals EOF to the sandbox).
pub struct Input {
    pub pid: i32,
    pub pidfd: OwnedFd,
    pub sync: OwnedFd,
    /// Parent read end of the stdout pipe; `None` when `stdout_file` is used.
    pub stdout: Option<OwnedFd>,
    /// Parent read end of the stderr pipe; `None` when `stderr_file` is used.
    pub stderr: Option<OwnedFd>,
    /// Parent write end of the stdin pipe; `None` without `stdin`.
    pub stdin: Option<OwnedFd>,
    pub stdin_bytes: Vec<u8>,
    pub stdout_limit_bytes: Option<u64>,
    pub stderr_limit_bytes: Option<u64>,
}

/// Outcome of a supervised run.
pub struct Supervised {
    /// `(step, errno)` when the child failed before execve; the parent turns
    /// it into `ExecSetupError`.
    pub setup_error: Option<(u32, i32)>,
}

/// Supervise failure: on every variant the child was already killed and
/// reaped, so no sandbox survives the call.
pub enum Error {
    /// A Python signal arrived (typically Ctrl-C).
    Interrupted,
    /// The event loop itself broke.
    Io(String),
}

/// Runs the loop until the sandbox child and every pipe have gone quiet
/// (design.md §3 step 7, §10). Returns the collected `(stdout, stderr)`.
pub fn run(mut input: Input) -> Result<(Supervised, Vec<u8>, Vec<u8>), Error> {
    let epfd = epoll::create(epoll::CreateFlags::CLOEXEC).map_err(io_fail("epoll_create"))?;
    let add = |fd: &OwnedFd, token: u64| {
        epoll::add(
            &epfd,
            fd.as_fd(),
            epoll::EventData::new_u64(token),
            epoll::EventFlags::IN,
        )
    };
    add(&input.pidfd, TOKEN_PIDFD).map_err(io_fail("epoll add pidfd"))?;
    add(&input.sync, TOKEN_SYNC).map_err(io_fail("epoll add sync"))?;
    if let Some(fd) = &input.stdout {
        add(fd, TOKEN_STDOUT).map_err(io_fail("epoll add stdout"))?;
    }
    if let Some(fd) = &input.stderr {
        add(fd, TOKEN_STDERR).map_err(io_fail("epoll add stderr"))?;
    }
    if let Some(fd) = &input.stdin {
        epoll::add(
            &epfd,
            fd.as_fd(),
            epoll::EventData::new_u64(TOKEN_STDIN),
            epoll::EventFlags::OUT,
        )
        .map_err(io_fail("epoll add stdin"))?;
    }

    let mut stdout_buf: Vec<u8> = Vec::new();
    let mut stderr_buf: Vec<u8> = Vec::new();
    let mut setup_error = None;
    let mut pid_exited = false;
    let mut sync_done = false;
    let mut stdout_eof = input.stdout.is_none();
    let mut stderr_eof = input.stderr.is_none();
    // One borrow over `input.stdin_bytes` for the whole loop; the field is
    // never mutated afterwards.
    let mut stdin_rest: &[u8] = if input.stdin.is_some() { &input.stdin_bytes } else { &[] };
    let mut events = epoll::EventVec::with_capacity(8);

    let result = loop {
        // PR 3 will clamp this to the wall-clock deadline.
        let timeout: libc::c_int = 100;
        match epoll::wait(&epfd, &mut events, timeout) {
            Ok(()) => {}
            Err(Errno::INTR) => {}
            Err(e) => break Err(Error::Io(format!("epoll_wait: {e}"))),
        }

        // Event dispatch. `break` cannot carry a value out of a `for`, so a
        // failure is parked and breaks the outer loop right after.
        let mut failure: Option<Error> = None;
        for event in &events {
            if failure.is_some() {
                break;
            }
            match event.data.u64() {
                TOKEN_PIDFD => {
                    pid_exited = true;
                    // The child (pid 1 of the new pid namespace) is gone; the
                    // kernel killed the rest of the namespace with it.
                    let _ = epoll::delete(&epfd, input.pidfd.as_fd());
                }
                TOKEN_SYNC => {
                    let mut msg = SyncMsg {
                        step: 0,
                        errno: 0,
                    };
                    let n = read_sync(input.sync.as_raw_fd(), &mut msg);
                    if n == std::mem::size_of::<SyncMsg>() as usize {
                        setup_error = Some((msg.step, msg.errno));
                    }
                    // n == 0: EOF — the CLOEXEC socket closed at execve.
                    // Short reads cannot happen on SOCK_SEQPACKET.
                    sync_done = true;
                    let _ = epoll::delete(&epfd, input.sync.as_fd());
                }
                TOKEN_STDOUT => {
                    let fd = input.stdout.as_ref().unwrap();
                    match drain(fd.as_raw_fd(), &mut stdout_buf, input.stdout_limit_bytes) {
                        Ok(true) => {
                            stdout_eof = true;
                            let _ = epoll::delete(&epfd, fd.as_fd());
                        }
                        Ok(false) => {}
                        Err(e) => failure = Some(Error::Io(format!("stdout read: {e}"))),
                    }
                }
                TOKEN_STDERR => {
                    let fd = input.stderr.as_ref().unwrap();
                    match drain(fd.as_raw_fd(), &mut stderr_buf, input.stderr_limit_bytes) {
                        Ok(true) => {
                            stderr_eof = true;
                            let _ = epoll::delete(&epfd, fd.as_fd());
                        }
                        Ok(false) => {}
                        Err(e) => failure = Some(Error::Io(format!("stderr read: {e}"))),
                    }
                }
                TOKEN_STDIN => {
                    let done = match input.stdin.as_ref() {
                        None => true,
                        Some(fd) => match rustix::io::write(fd.as_fd(), stdin_rest) {
                            Ok(n) => {
                                stdin_rest = &stdin_rest[n..];
                                stdin_rest.is_empty()
                            }
                            Err(Errno::PIPE) => true,
                            Err(Errno::AGAIN) => false,
                            Err(Errno::INTR) => false,
                            Err(e) => {
                                failure = Some(Error::Io(format!("stdin write: {e}")));
                                true
                            }
                        },
                    };
                    if done {
                        // Closing the write end is the EOF the sandboxed
                        // program may be waiting for.
                        if let Some(fd) = input.stdin.take() {
                            let _ = epoll::delete(&epfd, fd.as_fd());
                        }
                    }
                }
                _ => {}
            }
        }
        if let Some(e) = failure {
            break Err(e);
        }

        if pid_exited && sync_done && stdout_eof && stderr_eof && input.stdin.is_none() {
            break Ok(());
        }

        // Ctrl-C checkpoint (design.md §4): every wakeup checks for pending
        // Python signals; on error the child is killed and reaped below.
        if Python::attach(|py| py.check_signals()).is_err() {
            break Err(Error::Interrupted);
        }
    };

    if result.is_err() {
        // No orphan sandbox: SIGKILL through the pidfd, then reap. The child
        // is pid 1 of the pid namespace, so its death tears the rest down.
        kill_and_reap(input.pid, input.pidfd.as_raw_fd());
    }

    result.map(|_| (Supervised { setup_error }, stdout_buf, stderr_buf))
}

/// Reads until `EAGAIN` or EOF; `Ok(true)` = EOF reached. Bytes past the cap
/// are read and discarded (design.md §10); the kill on the limit is PR 3.
fn drain(fd: RawFd, buf: &mut Vec<u8>, limit: Option<u64>) -> io::Result<bool> {
    let mut chunk = [0u8; 64 * 1024];
    loop {
        // SAFETY: read(2) into a private stack buffer.
        let n = unsafe { libc::read(fd, chunk.as_mut_ptr() as *mut libc::c_void, chunk.len()) };
        if n < 0 {
            let e = io::Error::last_os_error();
            return match e.kind() {
                io::ErrorKind::WouldBlock => Ok(false),
                io::ErrorKind::Interrupted => continue,
                _ => Err(e),
            };
        }
        if n == 0 {
            return Ok(true);
        }
        append_capped(buf, &chunk[..n as usize], limit);
    }
}

fn append_capped(buf: &mut Vec<u8>, chunk: &[u8], limit: Option<u64>) {
    match limit {
        None => buf.extend_from_slice(chunk),
        Some(limit) => {
            let used = buf.len() as u64;
            let room = limit.saturating_sub(used) as usize;
            buf.extend_from_slice(&chunk[..room.min(chunk.len())]);
        }
    }
}

/// One read(2) into the 8-byte `SyncMsg`; returns the byte count.
fn read_sync(fd: RawFd, msg: &mut SyncMsg) -> usize {
    // SAFETY: read(2) into a private 8-byte struct.
    let n = unsafe {
        libc::read(
            fd,
            msg as *mut SyncMsg as *mut libc::c_void,
            std::mem::size_of::<SyncMsg>(),
        )
    };
    if n < 0 {
        0 // EOF and errors are indistinguishable here; both end the wait
    } else {
        n as usize
    }
}

fn kill_and_reap(pid: i32, pidfd: RawFd) {
    // SAFETY: pidfd_send_signal(2) with a null siginfo.
    let _ = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd,
            libc::SIGKILL as libc::c_int,
            std::ptr::null::<libc::c_void>(),
            0u32,
        )
    };
    reap(pid);
}

/// waitpid(2) with the EINTR loop; the child is dying, so this is quick.
pub fn reap(pid: i32) {
    let mut status: libc::c_int = 0;
    loop {
        // SAFETY: `status` is a valid out-pointer.
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r == pid {
            return;
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return;
        }
    }
}

fn io_fail(what: &'static str) -> impl Fn(Errno) -> Error {
    move |e| Error::Io(format!("{what}: {e}"))
}
