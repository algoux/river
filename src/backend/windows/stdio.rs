//! Piped stdio for a sandboxed child: stdin feeding (bytes via feeder thread
//! or host file handle), stdout/stderr capture with truncation limits and
//! optional full-capture file sinks.
//!
//! Judger-side pipe ends never need to be inheritable; only the three
//! child-facing ends are marked inheritable at creation (the future
//! `STARTUPINFOEX` handle-list attribute will pass exactly those).

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::PathBuf;
use std::thread::JoinHandle;

use windows_sys::Win32::Foundation::{HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::SetEvent;

/// Source of the child's stdin.
pub(crate) enum StdinSource {
    /// Nothing to feed; child stdin is the `NUL` device (readable, EOF-free).
    Null,
    /// Bytes pumped by a feeder thread; broken pipe (child exited early) is
    /// not an error.
    Bytes(Vec<u8>),
    /// Host file opened by the judger; its read handle is passed to the child
    /// directly (zero copy, and the child cannot reopen it by path).
    File(PathBuf),
}

/// What one captured output channel produced.
#[derive(Debug)]
pub(crate) struct Output {
    /// Captured bytes, truncated to the effective capture limit.
    pub data: Vec<u8>,
    /// Total bytes the channel produced (may exceed `data.len()`).
    pub total: u64,
    /// Whether bytes beyond the capture limit were dropped. With
    /// `limit == None` the internal safety ceiling applies (capture stops at
    /// `capture_limit_bytes`); with a user limit the semantics are unchanged.
    pub truncated: bool,
    /// Bytes written to the optional file sink (stops at the sink ceiling).
    pub sink_bytes: u64,
    /// Whether sink output was dropped (sink ceiling reached).
    pub sink_truncated: bool,
    /// Error from the optional file sink, if any (capture continues past it).
    pub sink_error: Option<io::Error>,
}

/// Internal safety ceilings for stdio capture (never disableable; see
/// `contract::StdioCeilings` / `SafetyCeilings`). Re-exported so callers can
/// pass them without reaching into `contract` directly.
pub(crate) use crate::contract::StdioCeilings;

struct ReaderSpec {
    /// User kill threshold (`*_limit_kb`); `None` = no kill threshold.
    limit: Option<u64>,
    /// Memory-capture ceiling (user limit, or the internal safety ceiling).
    capture_ceiling: u64,
    /// File-sink ceiling.
    sink_ceiling: u64,
    sink: Option<PathBuf>,
    /// Raw handle (as `usize`: raw pointers are not `Send`) of the
    /// output-overflow event (see `StdioSet`); set when the channel's total
    /// output strictly exceeds `limit` — the kill threshold (DESIGN.md §2.2:
    /// `*_limit` kills, `*_file` archives, `r.stdout` samples). `None` in
    /// stdio-only tests without a monitor.
    overflow_event: Option<usize>,
}

/// All plumbing for one run's stdio. Owns the judger-side ends and the worker
/// threads; child-facing ends are moved out by the caller before spawn.
pub(crate) struct StdioSet {
    /// Child stdin (pipe read end or NUL handle). Inheritable.
    pub child_stdin: File,
    /// Child stdout (pipe write end). Inheritable.
    pub child_stdout: File,
    /// Child stderr (pipe write end). Inheritable.
    pub child_stderr: File,
    feeder: Option<JoinHandle<()>>,
    stdout_reader: JoinHandle<Output>,
    stderr_reader: JoinHandle<Output>,
    /// Manual-reset event fired by a reader thread when a channel's total
    /// output strictly exceeds its kill threshold. The monitor waits on it
    /// alongside the process handle so an output fountain is killed mid-run
    /// (verdict OLE) instead of only being flagged at exit.
    overflow_event: OwnedHandle,
}

fn make_pipe() -> io::Result<(File, File)> {
    let mut read: HANDLE = std::ptr::null_mut();
    let mut write: HANDLE = std::ptr::null_mut();
    // SAFETY: out-pointers are valid; no security attributes (non-inheritable
    // by default); inheritability of specific ends is set below.
    unsafe {
        if CreatePipe(&mut read, &mut write, std::ptr::null(), 0) == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    // SAFETY: on success both handles are valid, owned, and not aliased.
    let (read, write) = unsafe {
        (
            File::from_raw_handle(read as RawHandle),
            File::from_raw_handle(write as RawHandle),
        )
    };
    Ok((read, write))
}

/// Mark a handle inheritable so the child process can receive it.
fn set_inheritable(f: &File) -> io::Result<()> {
    // SAFETY: handle is owned by `f` and still open.
    unsafe {
        if SetHandleInformation(
            f.as_raw_handle() as HANDLE,
            HANDLE_FLAG_INHERIT,
            HANDLE_FLAG_INHERIT,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

fn reader_thread(mut read: File, spec: ReaderSpec) -> Output {
    let mut out = Output {
        data: Vec::new(),
        total: 0,
        truncated: false,
        sink_bytes: 0,
        sink_truncated: false,
        sink_error: None,
    };
    let mut sink = spec.sink.as_ref().and_then(|p| match File::create(p) {
        Ok(f) => Some(f),
        Err(e) => {
            out.sink_error = Some(e);
            None
        }
    });
    // 64 KiB: a 1 GiB archive costs ~16k reads instead of ~131k with the
    // 8 KiB buffer; the truncation logic slices by limit, so the buffer
    // size never changes the captured byte count.
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match read.read(&mut buf) {
            Ok(0) => break, // EOF: child closed its end (and exited)
            Ok(n) => {
                let chunk = &buf[..n];
                out.total += n as u64;
                // File sink: archive up to the ceiling (user semantic: "full
                // archive"; the ceiling is the internal safety net so an
                // output fountain cannot fill the host disk before the run
                // is reaped).
                if let Some(f) = sink.as_mut()
                    && out.sink_error.is_none()
                {
                    if out.sink_bytes < spec.sink_ceiling {
                        let room = (spec.sink_ceiling - out.sink_bytes).min(n as u64) as usize;
                        if let Err(e) = f.write_all(&chunk[..room]) {
                            out.sink_error = Some(e);
                        } else {
                            out.sink_bytes += room as u64;
                            if room < n {
                                out.sink_truncated = true;
                            }
                        }
                    } else {
                        out.sink_truncated = true;
                    }
                }
                // Memory capture: user limit when set, else the internal
                // safety ceiling ("unlimited" is a caller-side semantic,
                // never a missing mechanism).
                let cap = spec.limit.unwrap_or(spec.capture_ceiling);
                let room = (cap - out.data.len() as u64).min(n as u64) as usize;
                if room > 0 {
                    out.data.extend_from_slice(&chunk[..room]);
                }
                // Kill threshold: only an explicit user limit kills. Total
                // output strictly past the limit wakes the monitor, which
                // terminates the job and classifies OLE. Exactly `limit`
                // bytes is still legal (AC), and only then is the capture
                // marked truncated (bytes were actually dropped).
                if out.total > cap {
                    out.truncated = true;
                }
                if let Some(limit) = spec.limit
                    && out.total > limit
                    && let Some(ev) = spec.overflow_event
                {
                    // SAFETY: the event handle is owned by the
                    // `StdioSet`, which outlives this thread (it
                    // is dropped by `finish`, after this thread
                    // joins).
                    unsafe { SetEvent(ev as HANDLE) };
                }
            }
            // A pipe that is closed mid-read behaves like EOF.
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => break,
            Err(e) if e.raw_os_error() == Some(232 /* ERROR_NO_DATA */) => break,
            Err(_) => break, // best effort: capture what we have
        }
    }
    out
}

impl StdioSet {
    /// Build the stdio plumbing for one run.
    pub(crate) fn new(
        stdin: StdinSource,
        stdout_limit: Option<u64>,
        stderr_limit: Option<u64>,
        stdout_file: Option<PathBuf>,
        stderr_file: Option<PathBuf>,
        ceilings: StdioCeilings,
    ) -> io::Result<Self> {
        // stdin
        let (child_stdin, feeder) = match stdin {
            StdinSource::Null => (File::open("NUL")?, None),
            StdinSource::Bytes(bytes) => {
                let (read, mut write) = make_pipe()?;
                // `Builder::spawn` returns the failure instead of panicking:
                // thread creation can fail under fd/memory pressure, and a
                // panic here would abort the judge (on a GIL-free worker
                // thread: SIGSEGV instead of a catchable exception).
                let feeder = std::thread::Builder::new()
                    .name("river-stdin".into())
                    .spawn(move || {
                        // Broken pipe is fine: the child may have exited without
                        // reading all of stdin.
                        let _ = write.write_all(&bytes);
                    })
                    .map_err(|e| io::Error::other(format!("spawn stdin feeder thread: {e}")))?;
                (read, Some(feeder))
            }
            StdinSource::File(path) => (File::open(path)?, None),
        };
        set_inheritable(&child_stdin)?;

        // stdout / stderr
        // Manual-reset overflow event: both readers may fire it; manual reset
        // keeps the signal latched until the monitor observes it.
        // SAFETY: out-pointer valid; handle wrapped on success.
        let ev_raw = unsafe {
            windows_sys::Win32::System::Threading::CreateEventW(
                std::ptr::null(),
                1, // manual reset
                0,
                std::ptr::null(),
            )
        };
        if ev_raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        let overflow_event = unsafe { OwnedHandle::from_raw_handle(ev_raw as RawHandle) };
        // Stored as usize in ReaderSpec: raw pointers are not Send.
        let ev = overflow_event.as_raw_handle() as usize;

        let (out_read, child_stdout) = make_pipe()?;
        set_inheritable(&child_stdout)?;
        let stdout_reader = std::thread::Builder::new()
            .name("river-stdio-0".into())
            .spawn(move || {
                reader_thread(
                    out_read,
                    ReaderSpec {
                        limit: stdout_limit,
                        capture_ceiling: crate::contract::capture_ceiling(
                            stdout_limit,
                            ceilings.capture_limit_bytes,
                        ),
                        sink_ceiling: ceilings.sink_limit_bytes,
                        sink: stdout_file,
                        overflow_event: Some(ev),
                    },
                )
            })
            .map_err(|e| io::Error::other(format!("spawn stdio reader thread: {e}")))?;

        let (err_read, child_stderr) = make_pipe()?;
        set_inheritable(&child_stderr)?;
        let stderr_reader = std::thread::Builder::new()
            .name("river-stdio-1".into())
            .spawn(move || {
                reader_thread(
                    err_read,
                    ReaderSpec {
                        limit: stderr_limit,
                        capture_ceiling: crate::contract::capture_ceiling(
                            stderr_limit,
                            ceilings.capture_limit_bytes,
                        ),
                        sink_ceiling: ceilings.sink_limit_bytes,
                        sink: stderr_file,
                        overflow_event: Some(ev),
                    },
                )
            })
            .map_err(|e| io::Error::other(format!("spawn stdio reader thread: {e}")))?;

        Ok(Self {
            child_stdin,
            child_stdout,
            child_stderr,
            feeder,
            stdout_reader,
            stderr_reader,
            overflow_event,
        })
    }

    /// Raw handle of the output-overflow event for the monitor's wait set.
    pub(crate) fn overflow_event_handle(&self) -> HANDLE {
        self.overflow_event.as_raw_handle() as HANDLE
    }

    /// Move the three child-facing ends out (they go into `STARTUPINFO`).
    /// The set keeps inert NUL handles so it stays droppable.
    pub(crate) fn take_child_ends(&mut self) -> io::Result<(File, File, File)> {
        Ok((
            std::mem::replace(&mut self.child_stdin, File::open("NUL")?),
            std::mem::replace(&mut self.child_stdout, File::open("NUL")?),
            std::mem::replace(&mut self.child_stderr, File::open("NUL")?),
        ))
    }

    /// Wait for all worker threads and collect both outputs.
    pub(crate) fn finish(self) -> io::Result<(Output, Output)> {
        if let Some(feeder) = self.feeder {
            feeder
                .join()
                .map_err(|_| io::Error::other("stdin feeder thread panicked"))?;
        }
        let stdout = self
            .stdout_reader
            .join()
            .map_err(|_| io::Error::other("stdout reader thread panicked"))?;
        let stderr = self
            .stderr_reader
            .join()
            .map_err(|_| io::Error::other("stderr reader thread panicked"))?;
        Ok((stdout, stderr))
    }
}
