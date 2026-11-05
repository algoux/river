//! stdio plumbing: stdin feeding, stdout/stderr capture with kill
//! thresholds, truncation flags, and full-stream archive files.
//!
//! Mirrors `backend::windows::stdio` semantics (the frozen contract, DESIGN
//! §2.2): `*_limit` is a kill threshold (the reader fires past it, the
//! monitor reaps the process, verdict `OLE`), `*_file` receives the
//! complete stream up to the kill, and the returned buffer is the truncated
//! sample (at most `limit` bytes) with a per-channel truncation flag.
//!
//! Fork-safety note: the pipes are created before
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
///
/// Besides the atomics there is an `eventfd`: a reader that crosses a kill
/// threshold writes one byte to it, which wakes the monitor's `poll()`
/// immediately. The atomics remain the source of truth (a run whose
/// `eventfd` could not be created still works — the monitor then falls back
/// to its legacy polling loop) and are re-checked on every wake, so a lost
/// wakeup cannot delay an output kill.
pub(crate) struct OverflowFlags {
    pub(crate) stdout: AtomicBool,
    pub(crate) stderr: AtomicBool,
    /// Wakeup channel for the monitor (`None` if `eventfd` is unavailable).
    event: Option<OwnedFd>,
}

impl Default for OverflowFlags {
    fn default() -> Self {
        OverflowFlags {
            stdout: AtomicBool::new(false),
            stderr: AtomicBool::new(false),
            event: make_eventfd(),
        }
    }
}

fn make_eventfd() -> Option<OwnedFd> {
    // SAFETY: plain syscall; the fd is owned from here on.
    let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if fd < 0 {
        None
    } else {
        Some(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

impl OverflowFlags {
    pub(crate) fn any(&self) -> bool {
        self.stdout.load(Ordering::Relaxed) || self.stderr.load(Ordering::Relaxed)
    }

    /// File descriptor the monitor can `poll` for overflow wakeups.
    pub(crate) fn event_fd(&self) -> Option<RawFd> {
        self.event.as_ref().map(|fd| fd.as_raw_fd())
    }

    /// Drain the eventfd (it is level-triggered per `read`, not per write).
    pub(crate) fn drain_event(&self) {
        if let Some(fd) = &self.event {
            let mut buf = [0u8; 8];
            // SAFETY: 8-byte buffer for the eventfd counter; EAGAIN when
            // already drained is fine (and expected).
            unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), 8) };
        }
    }

    pub(crate) fn fire(&self, index: usize) {
        let flag = if index == 0 {
            &self.stdout
        } else {
            &self.stderr
        };
        flag.store(true, Ordering::Relaxed);
        if let Some(fd) = &self.event {
            let one: u64 = 1;
            // SAFETY: 8-byte write to the eventfd; a full counter
            // (EAGAIN) only means a wakeup is already pending, which is
            // enough — the flag is the source of truth.
            unsafe { libc::write(fd.as_raw_fd(), (&one as *const u64).cast(), 8) };
        }
    }
}

/// One captured channel after the run finished.
pub(crate) struct ChannelResult {
    /// Truncated sample: at most `limit` bytes, or the internal capture
    /// ceiling when no user limit was set.
    pub(crate) data: Vec<u8>,
    pub(crate) truncated: bool,
    /// The `*_file` archive stopped early (sink ceiling reached).
    pub(crate) sink_truncated: bool,
}

/// One output channel: parent-held read end + archive writer + kill limit.
struct ChannelPipe {
    read_end: OwnedFd,
    /// Kill threshold in bytes; `None` = no caller-imposed limit.
    limit: Option<u64>,
    /// Memory-capture ceiling (user limit, or the internal safety ceiling).
    capture_ceiling: u64,
    /// File-archive ceiling (internal safety net against filling the disk).
    sink_ceiling: u64,
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
        ceilings: crate::contract::StdioCeilings,
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
                    capture_ceiling: crate::contract::capture_ceiling(
                        stdout_limit_bytes,
                        ceilings.capture_limit_bytes,
                    ),
                    sink_ceiling: ceilings.sink_limit_bytes,
                    archive: open_archive(stdout_file)?,
                },
                ChannelPipe {
                    read_end: stderr_read,
                    limit: stderr_limit_bytes,
                    capture_ceiling: crate::contract::capture_ceiling(
                        stderr_limit_bytes,
                        ceilings.capture_limit_bytes,
                    ),
                    sink_ceiling: ceilings.sink_limit_bytes,
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
    ///
    /// Thread creation can fail (`EAGAIN`/`ENOMEM` under fd or memory
    /// pressure). That is an **infrastructure** failure, not a panic: the
    /// caller must learn about it as an `io::Error` so the run can be
    /// classified `SE`. Panicking here would abort the *judger* — and on a
    /// thread that does not hold the GIL (this runs inside `py.detach`), a
    /// panic terminates the process with SIGSEGV instead of surfacing as a
    /// `PanicException`.
    pub(crate) fn after_fork(&mut self) -> io::Result<()> {
        drop(self.stdin_read.take());
        drop(self.stdout_write.take());
        drop(self.stderr_write.take());
        let write_end = self
            .stdin_write
            .take()
            .ok_or_else(|| io::Error::other("stdin write end missing at after_fork"))?;
        self.feeder = start_feeder(&self.stdin, write_end)?;
        let overflow = Arc::clone(&self.overflow);
        for (index, ch) in std::mem::take(&mut self.channels).into_iter().enumerate() {
            let overflow = Arc::clone(&overflow);
            let handle = std::thread::Builder::new()
                .name(format!("river-stdio-{index}"))
                .spawn(move || drain_channel(ch, index, &overflow))
                .map_err(|e| io::Error::other(format!("spawn stdio reader thread: {e}")))?;
            self.readers.push(handle);
        }
        self.readers_started = true;
        Ok(())
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
///
/// Thread creation can fail (fd/memory pressure). The error is returned so
/// the caller can classify the run `SE` instead of panicking the judge (see
/// [`StdioSet::after_fork`]).
fn start_feeder(
    source: &StdinSource,
    write_end: OwnedFd,
) -> io::Result<Option<std::thread::JoinHandle<io::Result<()>>>> {
    let mut writer = File::from(write_end);
    match source {
        StdinSource::Null => Ok(None),
        StdinSource::Bytes(bytes) => {
            let bytes = bytes.clone();
            let handle = std::thread::Builder::new()
                .name("river-stdin".into())
                .spawn(move || {
                    // BrokenPipe = the child died without reading; not
                    // an infrastructure failure.
                    writer.write_all(&bytes).or_else(ignore_epipe)
                })
                .map_err(|e| io::Error::other(format!("spawn stdin feeder thread: {e}")))?;
            Ok(Some(handle))
        }
        StdinSource::File(path) => {
            let path = path.clone();
            let handle = std::thread::Builder::new()
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
                .map_err(|e| io::Error::other(format!("spawn stdin feeder thread: {e}")))?;
            Ok(Some(handle))
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

/// Drain one output channel to EOF: archive up to the sink ceiling, keep at
/// most `capture_ceiling` bytes as the sample, fire the overflow flag only
/// past an explicit *user* limit (the internal ceilings are safety nets,
/// not kill thresholds).
fn drain_channel(
    ch: ChannelPipe,
    index: usize,
    overflow: &OverflowFlags,
) -> io::Result<ChannelResult> {
    let ChannelPipe {
        read_end,
        limit,
        capture_ceiling,
        sink_ceiling,
        mut archive,
    } = ch;
    let mut reader = File::from(read_end);
    let mut sample: Vec<u8> = Vec::with_capacity((capture_ceiling as usize).min(1 << 20));
    let mut total: u64 = 0;
    let mut sink_bytes: u64 = 0;
    let mut sink_truncated = false;
    // 64 KiB: a 1 GiB archive costs ~16k reads instead of ~131k with the
    // 8 KiB buffer; truncation slices by limit, so the buffer size never
    // changes the captured byte count.
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        // Archive up to the sink ceiling ("full archive" is the caller
        // semantic; the ceiling is the safety net so an output fountain
        // cannot fill the host disk before the run is reaped).
        if let Some(archive) = archive.as_mut() {
            if sink_bytes < sink_ceiling {
                let room = ((sink_ceiling - sink_bytes) as usize).min(n);
                archive.write_all(&buf[..room])?;
                sink_bytes += room as u64;
                if room < n {
                    sink_truncated = true;
                }
            } else {
                sink_truncated = true;
            }
        }
        let remaining = (capture_ceiling.saturating_sub(sample.len() as u64) as usize).min(n);
        sample.extend_from_slice(&buf[..remaining]);
        total += n as u64;
        if let Some(limit) = limit
            && total > limit
        {
            overflow.fire(index);
        }
    }
    if let Some(archive) = archive.as_mut() {
        archive.flush()?;
    }
    let truncated = total > capture_ceiling;
    Ok(ChannelResult {
        data: sample,
        truncated,
        sink_truncated,
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
            capture_ceiling: 1024,
            sink_ceiling: 1 << 20,
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
            capture_ceiling: 1024,
            sink_ceiling: 1 << 20,
            archive: None,
        };
        let overflow = OverflowFlags::default();
        let r = drain_channel(ch, 0, &overflow).unwrap();
        assert_eq!(r.data.len(), 1024);
        assert!(!r.truncated);
        assert!(!overflow.any());
    }

    /// No user limit: the internal capture ceiling still caps the sample and
    /// marks it truncated, and no overflow (kill) fires — "unlimited" is a
    /// caller-side semantic, never a missing mechanism.
    #[test]
    fn capture_ceiling_caps_unlimited_run() {
        let (read_end, write_end) = pipe_cloexec().unwrap();
        {
            let mut w = File::from(write_end);
            w.write_all(&vec![b'x'; 5000]).unwrap();
        }
        let ch = ChannelPipe {
            read_end,
            limit: None,
            capture_ceiling: 1024,
            sink_ceiling: 1 << 20,
            archive: None,
        };
        let overflow = OverflowFlags::default();
        let r = drain_channel(ch, 0, &overflow).unwrap();
        assert_eq!(r.data.len(), 1024);
        assert!(r.truncated);
        assert!(!overflow.any());
    }

    /// The archive stops at the sink ceiling and reports `sink_truncated`
    /// (the archive file itself receives exactly `sink_ceiling` bytes).
    #[test]
    fn archive_stops_at_sink_ceiling() {
        let (read_end, write_end) = pipe_cloexec().unwrap();
        {
            let mut w = File::from(write_end);
            w.write_all(&vec![b'x'; 5000]).unwrap();
        }
        let mut path = std::env::temp_dir();
        path.push(format!(
            "river-sink-test-{}-{}.bin",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let archive = File::create(&path).unwrap();
        let ch = ChannelPipe {
            read_end,
            limit: None,
            capture_ceiling: 1 << 20,
            sink_ceiling: 1024,
            archive: Some(archive),
        };
        let r = drain_channel(ch, 0, &OverflowFlags::default()).unwrap();
        assert!(r.sink_truncated);
        assert!(!r.truncated); // sample ceiling not reached
        let written = std::fs::metadata(&path).unwrap().len();
        std::fs::remove_file(&path).ok();
        assert_eq!(written, 1024);
    }
}
