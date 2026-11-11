//! Output capture: a redirected stream with a limit becomes a pipe; the
//! supervisor loop `splice`s pipe bytes straight into the output file
//! (zero-copy) and kills the run when the total passes the limit. Without a
//! limit the child gets the output file directly; without a file it inherits
//! the caller's stream. A limit without a file is not enforced.
//!
//! shortcut: limit-without-file is ignored, wire it to /dev/null accounting
//! if a judge ever needs it.

use std::fs::File;
use std::io;
use std::path::Path;

use rustix::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};

/// Drain chunk for one splice call: big enough to need few wakeups, small
/// enough for a tight limit check.
const SPLICE_CHUNK: usize = 64 * 1024;

pub(super) struct Capture {
    streams: [Stream; 2], // stdout, stderr
}

struct Stream {
    /// The pipe read end this stream drains (limited streams only).
    reader: Option<OwnedFd>,
    /// The file the bytes are archived into, when redirected.
    file: Option<File>,
    limit: Option<u64>,
    total: u64,
    exceeded: bool,
}

impl Capture {
    /// Builds the child-side stdio for the run. The returned fds, in the
    /// stdin/stdout/stderr order, are what gets `dup2`ed onto 0/1/2.
    pub(super) fn new(
        stdin_file: Option<&Path>,
        stdout_file: Option<&Path>,
        stderr_file: Option<&Path>,
        stdout_limit: Option<u64>,
        stderr_limit: Option<u64>,
    ) -> io::Result<(Self, [Option<OwnedFd>; 3])> {
        let stdin = match stdin_file {
            Some(path) => Some(into_fd(File::open(path)?)),
            None => None,
        };

        let mut streams = [None, None];
        let mut writers = [None, None];
        for (index, (file, limit)) in [
            (stdout_file, stdout_limit),
            (stderr_file, stderr_limit),
        ]
        .into_iter()
        .enumerate()
        {
            if let Some(limit) = limit {
                let (reader, writer) = pipe_nonblocking()?;
                let file = match file {
                    Some(path) => Some(File::create(path)?),
                    None => None,
                };
                streams[index] = Some(Stream {
                    reader: Some(reader),
                    file,
                    limit: Some(limit),
                    total: 0,
                    exceeded: false,
                });
                writers[index] = Some(writer);
            } else {
                let fd = match file {
                    Some(path) => Some(into_fd(File::create(path)?)),
                    None => None,
                };
                writers[index] = fd;
            }
        }

        let capture = Self {
            streams: streams.map(|stream| stream.unwrap_or(Stream {
                reader: None,
                file: None,
                limit: None,
                total: 0,
                exceeded: false,
            })),
        };
        Ok((capture, [stdin, writers[0].take(), writers[1].take()]))
    }

    /// Drains every limited stream once. Returns `true` when a stream has
    /// passed its limit (a kill threshold; exactly the limit is legal).
    pub(super) fn poll(&mut self) -> bool {
        for stream in &mut self.streams {
            if stream.reader.is_none() {
                continue;
            }
            let exceeded = drain(stream);
            if exceeded {
                return true;
            }
        }
        false
    }

    /// True when a stream passed its limit at any point of the run.
    pub(super) fn exceeded(&self) -> bool {
        self.streams.iter().any(|stream| stream.exceeded)
    }
}

/// Moves pipe bytes into the stream's file until the pipe is empty. Without
/// a file the bytes are read and dropped, but still counted against the
/// limit.
fn drain(stream: &mut Stream) -> bool {
    let Some(reader) = stream.reader.as_ref() else {
        return false;
    };
    loop {
        let moved = match stream.file.as_ref() {
            Some(file) => {
                let fd = file.as_fd().as_raw_fd();
                unsafe {
                    // SAFETY: splice moves whole pipe buffers, and the
                    // kernel never writes past `SPLICE_CHUNK`.
                    libc::splice(
                        reader.as_fd().as_raw_fd(),
                        std::ptr::null_mut(),
                        fd,
                        std::ptr::null_mut(),
                        SPLICE_CHUNK,
                        libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
                    )
                }
            }
            None => unsafe {
                let mut buffer = [0u8; SPLICE_CHUNK];
                libc::read(
                    reader.as_fd().as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    SPLICE_CHUNK,
                )
            },
        };
        if moved < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK || errno == libc::EINTR {
                return stream.exceeded;
            }
            return stream.exceeded;
        }
        if moved == 0 {
            return stream.exceeded;
        }
        stream.total = stream.total.saturating_add(moved as u64);
        if stream.limit.is_some_and(|limit| stream.total > limit) {
            stream.exceeded = true;
            return true;
        }
    }
}

fn pipe_nonblocking() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as std::os::raw::c_int; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fresh fds from pipe2, owned from here on.
    unsafe {
        Ok((
            OwnedFd::from_raw_fd(fds[0]),
            OwnedFd::from_raw_fd(fds[1]),
        ))
    }
}

fn into_fd(file: File) -> OwnedFd {
    use std::os::unix::io::IntoRawFd;
    // SAFETY: `into_raw_fd` hands over a live fd that `OwnedFd` now owns.
    unsafe { OwnedFd::from_raw_fd(file.into_raw_fd()) }
}
