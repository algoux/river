//! stdio plumbing: stdin feeding, stdout/stderr capture with kill
//! thresholds, truncation flags, and full-stream archive files.
//!
//! Mirrors `backend::windows::stdio` semantics (the frozen contract, DESIGN
//! §2.2): `*_limit` is a kill threshold (the reader fires past it, the
//! monitor reaps the process, verdict `OLE`), `*_file` receives the
//! complete stream up to the kill, and the returned buffer is the truncated
//! sample (at most `limit` bytes) with a per-channel truncation flag.
//!
//! Fork-safety note (docs/linux-plan.md §2.2): the pipes are created before
//! the fork, but **all threads are started after it** — the reader and
//! feeder threads exist only in the parent, and the parent drops the child
//! ends immediately after the fork so EOF semantics work.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Where the child's stdin comes from.
#[derive(Clone)]
pub(crate) enum StdinSource {
    /// Nothing (child reads EOF immediately).
    Null,
    /// Feed these bytes, then EOF.
    Bytes(Vec<u8>),
    /// Stream a host file (zero-copy intent), then EOF.
    File(PathBuf),
}

/// Per-channel overflow flags the monitor watches (the Linux counterpart of
/// the Windows overflow event: set by a reader thread, observed by the
/// monitor loop).
#[derive(Default)]
pub(crate) struct OverflowFlags {
    pub(crate) stdout: AtomicBool,
    pub(crate) stderr: AtomicBool,
}

impl OverflowFlags {
    pub(crate) fn any(&self) -> bool {
        self.stdout.load(Ordering::Relaxed) || self.stderr.load(Ordering::Relaxed)
    }

    fn fire(&self, index: usize) {
        let flag = if index == 0 {
            &self.stdout
        } else {
            &self.stderr
        };
        flag.store(true, Ordering::Relaxed);
    }
}

/// One captured channel after the run finished.
pub(crate) struct ChannelResult {
    /// Truncated sample: at most `limit` bytes (unbounded without a limit).
    pub(crate) data: Vec<u8>,
    pub(crate) truncated: bool,
}

/// One output channel: parent-held read end + archive writer + kill limit.
struct ChannelPipe {
    read_end: OwnedFd,
    /// Kill threshold in bytes; `None` = no caller-imposed limit.
    limit: Option<u64>,
    /// Optional full-stream archive (host path, `*_file` parameter).
    archive: Option<File>,
}

/// The full stdio set for one run.
pub(crate) struct StdioSet {
    stdin: StdinSource,
    /// Parent write end (feeder thread); child got a dup2'd copy on fd 0.
    /// `None` once ownership passed to the feeder thread.
    stdin_write: Option<OwnedFd>,
    /// Child read end; dropped by the parent right after the fork.
    stdin_read: Option<OwnedFd>,
    /// Child write ends for stdout/stderr; dropped by the parent right
    /// after the fork (child got dup2'd copies on fds 1 / 2).
    stdout_write: Option<OwnedFd>,
    stderr_write: Option<OwnedFd>,
    channels: Vec<ChannelPipe>,
    overflow: Arc<OverflowFlags>,
    /// Started by `after_fork` (parent side, after the fork), joined by
    /// `finish`. Readers run **during** the run so a fountain is killed by
    /// the monitor instead of blocking on a full pipe.
    feeder: Option<std::thread::JoinHandle<io::Result<()>>>,
    readers: Vec<std::thread::JoinHandle<io::Result<ChannelResult>>>,
    readers_started: bool,
}

impl StdioSet {
    pub(crate) fn new(
        stdin: StdinSource,
        stdout_limit_bytes: Option<u64>,
        stderr_limit_bytes: Option<u64>,
        stdout_file: Option<PathBuf>,
        stderr_file: Option<PathBuf>,
    ) -> io::Result<Self> {
        // Every parent-held end is CLOEXEC; the child's ends survive only as
        // dup2'd copies on 0/1/2 (dup2 clears CLOEXEC on the target fd).
        let (stdin_read, stdin_write) = pipe_cloexec()?;
        let (stdout_read, stdout_write) = pipe_cloexec()?;
        let (stderr_read, stderr_write) = pipe_cloexec()?;
        Ok(StdioSet {
            stdin,
            stdin_write: Some(stdin_write),
            stdin_read: Some(stdin_read),
            stdout_write: Some(stdout_write),
            stderr_write: Some(stderr_write),
            channels: vec![
                ChannelPipe {
                    read_end: stdout_read,
                    limit: stdout_limit_bytes,
                    archive: open_archive(stdout_file)?,
                },
                ChannelPipe {
                    read_end: stderr_read,
                    limit: stderr_limit_bytes,
                    archive: open_archive(stderr_file)?,
                },
            ],
            overflow: Arc::new(OverflowFlags::default()),
            feeder: None,
            readers: Vec::new(),
            readers_started: false,
        })
    }

    /// Child-side fds for dup2 in the forked child: (stdin, stdout, stderr).
    /// Raw fds are valid until `after_fork`.
    pub(crate) fn child_fds(&self) -> (RawFd, RawFd, RawFd) {
        let as_raw = |fd: &Option<OwnedFd>| fd.as_ref().unwrap().as_raw_fd();
        (
            as_raw(&self.stdin_read),
            as_raw(&self.stdout_write),
            as_raw(&self.stderr_write),
        )
    }

    /// Called by the parent right after the fork: drops the child-side pipe
    /// ends (the child has its dup2'd copies), then starts the feeder and
    /// the two output readers. Starting the readers here (not at `finish`)
    /// is what makes an output fountain killable: a full pipe would
    /// otherwise block the child until the wall watchdog.
    ///
    /// The feeder takes **ownership** of the stdin write end: wrapping a
    /// borrowed raw fd in a `File` would double-close it when `StdioSet`
    /// drops (the IO-safety abort).
    pub(crate) fn after_fork(&mut self) {
        drop(self.stdin_read.take());
        drop(self.stdout_write.take());
        drop(self.stderr_write.take());
        let write_end = self
            .stdin_write
            .take()
            .expect("stdin write end must exist until after_fork");
        self.feeder = start_feeder(&self.stdin, write_end);
        let overflow = Arc::clone(&self.overflow);
        for (index, ch) in std::mem::take(&mut self.channels).into_iter().enumerate() {
            let overflow = Arc::clone(&overflow);
            self.readers.push(
                std::thread::Builder::new()
                    .name(format!("river-stdio-{index}"))
                    .spawn(move || drain_channel(ch, index, &overflow))
                    .expect("spawn stdio reader thread"),
            );
        }
        self.readers_started = true;
    }

    /// Overflow flags shared with the monitor.
    pub(crate) fn overflow(&self) -> Arc<OverflowFlags> {
        Arc::clone(&self.overflow)
    }

    /// Join every stdio thread and collect the per-channel results. Must be
    /// called after the child exited (or was killed) so EOF is guaranteed;
    /// the feeder is joined first, then the readers.
    ///
    /// The returned `overflowed` flag is the *complete* observation: a fast
    /// writer can exit before the monitor notices the flag mid-run, so the
    /// caller must treat "bytes past a kill threshold were read" as an
    /// output-limit kill regardless of when the reader noticed (evidence
    /// outranks the exit code — contract §classify priority 2).
    pub(crate) fn finish(self) -> io::Result<(ChannelResult, ChannelResult, bool)> {
        let StdioSet {
            stdin_write,
            feeder,
            mut readers,
            overflow,
            ..
        } = self;
        // Drop the parent's stdin write end first: if the feeder already
        // finished (or there is none), the child's stdin hits EOF.
        drop(stdin_write);
        if let Some(handle) = feeder {
            // EPIPE from a child that died early is not an error.
            handle
                .join()
                .map_err(|_| io::Error::other("stdin feeder panicked"))??;
        }
        let mut results = Vec::with_capacity(2);
        for handle in readers.drain(..) {
            results.push(
                handle
                    .join()
                    .map_err(|_| io::Error::other("reader thread panicked"))??,
            );
        }
        let overflowed = overflow.any();
        let mut it = results.into_iter();
        Ok((it.next().unwrap(), it.next().unwrap(), overflowed))
    }
}

/// Feed stdin from a dedicated thread; the fd is consumed as a `File`.
fn start_feeder(
    source: &StdinSource,
    write_end: OwnedFd,
) -> Option<std::thread::JoinHandle<io::Result<()>>> {
    let mut writer = File::from(write_end);
    match source {
        StdinSource::Null => None,
        StdinSource::Bytes(bytes) => {
            let bytes = bytes.clone();
            Some(
                std::thread::Builder::new()
                    .name("river-stdin".into())
                    .spawn(move || {
                        // BrokenPipe = the child died without reading; not
                        // an infrastructure failure.
                        writer.write_all(&bytes).or_else(ignore_epipe)
                    })
                    .expect("spawn stdin feeder thread"),
            )
        }
        StdinSource::File(path) => {
            let path = path.clone();
            Some(
                std::thread::Builder::new()
                    .name("river-stdin".into())
                    .spawn(move || {
                        let mut file = match File::open(&path) {
                            Ok(f) => f,
                            Err(e) => return Err(e),
                        };
                        // BrokenPipe = the child died without reading.
                        io::copy(&mut file, &mut writer)
                            .map(|_| ())
                            .or_else(ignore_epipe)
                    })
                    .expect("spawn stdin feeder thread"),
            )
        }
    }
}

fn ignore_epipe(e: io::Error) -> io::Result<()> {
    if e.kind() == io::ErrorKind::BrokenPipe {
        Ok(())
    } else {
        Err(e)
    }
}

/// Drain one output channel to EOF: archive everything, keep at most
/// `limit` bytes as the sample, fire the overflow flag past the limit.
fn drain_channel(
    ch: ChannelPipe,
    index: usize,
    overflow: &OverflowFlags,
) -> io::Result<ChannelResult> {
    let ChannelPipe {
        read_end,
        limit,
        mut archive,
    } = ch;
    let mut reader = File::from(read_end);
    let cap = limit.map(|l| l as usize);
    let mut sample: Vec<u8> = Vec::with_capacity(cap.unwrap_or(4096).min(1 << 20));
    let mut total: u64 = 0;
    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if let Some(archive) = archive.as_mut() {
            archive.write_all(&buf[..n])?;
        }
        let remaining = cap.map_or(n, |cap| cap.saturating_sub(sample.len()));
        sample.extend_from_slice(&buf[..remaining.min(n)]);
        total += n as u64;
        if let Some(limit) = limit {
            if total > limit {
                overflow.fire(index);
            }
        }
    }
    if let Some(archive) = archive.as_mut() {
        archive.flush()?;
    }
    let truncated = limit.is_some_and(|limit| total > limit);
    Ok(ChannelResult {
        data: sample,
        truncated,
    })
}

fn open_archive(path: Option<PathBuf>) -> io::Result<Option<File>> {
    match path {
        Some(p) => Ok(Some(File::create(p)?)),
        None => Ok(None),
    }
}

fn pipe_cloexec() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((unsafe { OwnedFd::from_raw_fd(fds[0]) }, unsafe {
        OwnedFd::from_raw_fd(fds[1])
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A channel without a limit captures the full stream; with a limit the
    /// sample is capped at exactly `limit` bytes and the truncation flag is
    /// set when the stream was longer (removing either behavior must fail
    /// this test).
    #[test]
    fn drain_channel_truncates_and_flags() {
        let (read_end, write_end) = pipe_cloexec().unwrap();
        {
            let mut w = File::from(write_end);
            w.write_all(&vec![b'x'; 5000]).unwrap();
        }
        let ch = ChannelPipe {
            read_end,
            limit: Some(1024),
            archive: None,
        };
        let overflow = OverflowFlags::default();
        let r = drain_channel(ch, 0, &overflow).unwrap();
        assert_eq!(r.data.len(), 1024);
        assert!(r.truncated);
        assert!(overflow.any());
    }

    /// Exactly at the limit: no truncation, no overflow (the frozen
    /// "exactly at the stdout limit is AC" conformance case).
    #[test]
    fn drain_channel_exactly_at_limit_is_clean() {
        let (read_end, write_end) = pipe_cloexec().unwrap();
        {
            let mut w = File::from(write_end);
            w.write_all(&vec![b'z'; 1024]).unwrap();
        }
        let ch = ChannelPipe {
            read_end,
            limit: Some(1024),
            archive: None,
        };
        let overflow = OverflowFlags::default();
        let r = drain_channel(ch, 0, &overflow).unwrap();
        assert_eq!(r.data.len(), 1024);
        assert!(!r.truncated);
        assert!(!overflow.any());
    }
}
