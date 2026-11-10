//! Child stdio redirection.
//!
//! `stdin_file` is a host path opened by the judger and passed to the child
//! as an already-open, inheritable handle (the child never reopens it).
//! `stdout_file` / `stderr_file` are host paths as well: without a limit the
//! child receives the opened file handle directly; with a limit the stream is
//! piped through a reader thread that archives every byte to the file and
//! counts the total.
//!
//! A limit is a kill threshold: once a channel has produced more than
//! `*_limit_bytes` the reader signals the manual-reset overflow event and the
//! run is terminated (verdict `OLE`). Exactly the limit is legal. Without any
//! redirection the child inherits the caller's standard streams, duplicated
//! as inheritable handles so a redirected Python parent still works.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::Path;
use std::thread::JoinHandle;

use windows_sys::Win32::Foundation::{
    DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
    SetHandleInformation,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_ALWAYS, CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{CreateEventW, GetCurrentProcess, SetEvent};

/// 64 KiB: the pipe could otherwise wake the reader thousands of times per
/// output megabyte.
const READ_BUFFER_BYTES: usize = 64 * 1024;

/// The three child-facing handles, in the stdin/stdout/stderr order used by
/// `STARTUPINFOW`, plus the judger-side reader threads and the overflow event.
pub(crate) struct StdioSet {
    handles: [OwnedHandle; 3],
    stdout_reader: Option<JoinHandle<io::Result<u64>>>,
    stderr_reader: Option<JoinHandle<io::Result<u64>>>,
    /// Manual-reset event fired when a limited channel passes its limit.
    overflow: OwnedHandle,
}

impl StdioSet {
    pub(crate) fn new(
        stdin_file: Option<&Path>,
        stdout_file: Option<&Path>,
        stderr_file: Option<&Path>,
        stdout_limit: Option<u64>,
        stderr_limit: Option<u64>,
    ) -> io::Result<Self> {
        let stdin = match stdin_file {
            Some(path) => open_inheritable(path, FILE_GENERIC_READ, OPEN_EXISTING)?,
            None => duplicate_or_nul(STD_INPUT_HANDLE, false)?,
        };

        // SAFETY: no security attributes and an unnamed, initially unsignaled
        // manual-reset event; the returned handle is owned from here on.
        let raw = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a fresh, owned handle.
        let overflow = unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) };
        // Raw pointers are not `Send`; the reader threads only use the event
        // while the `StdioSet` (which owns it) is alive.
        let overflow_raw = overflow.as_raw_handle() as usize;

        let (stdout, stdout_reader) = output(
            STD_OUTPUT_HANDLE,
            stdout_file,
            stdout_limit,
            overflow_raw,
            "stdout",
        )?;
        let (stderr, stderr_reader) = output(
            STD_ERROR_HANDLE,
            stderr_file,
            stderr_limit,
            overflow_raw,
            "stderr",
        )?;

        Ok(Self {
            handles: [stdin, stdout, stderr],
            stdout_reader,
            stderr_reader,
            overflow,
        })
    }

    /// The inheritable handles for `STARTUPINFOW` / the handle list.
    pub(crate) fn raw_handles(&self) -> [HANDLE; 3] {
        [
            self.handles[0].as_raw_handle() as HANDLE,
            self.handles[1].as_raw_handle() as HANDLE,
            self.handles[2].as_raw_handle() as HANDLE,
        ]
    }

    /// Event that wakes the run wait when a channel passes its limit.
    pub(crate) fn overflow_handle(&self) -> HANDLE {
        self.overflow.as_raw_handle() as HANDLE
    }

    /// Closes the judger's copies of the child-facing ends (so the pipe
    /// readers see EOF) and joins them. Returns the total bytes per channel.
    pub(crate) fn finish(self) -> io::Result<(u64, u64)> {
        drop(self.handles);
        let stdout = join(self.stdout_reader)?;
        let stderr = join(self.stderr_reader)?;
        Ok((stdout, stderr))
    }
}

/// Builds one output channel: a direct inheritable file handle when there is
/// no limit (zero-copy), otherwise a pipe with a reader thread.
fn output(
    std_handle: u32,
    file: Option<&Path>,
    limit: Option<u64>,
    overflow: usize,
    label: &'static str,
) -> io::Result<(OwnedHandle, Option<JoinHandle<io::Result<u64>>>)> {
    let Some(limit) = limit else {
        return Ok((
            match file {
                Some(path) => open_inheritable(path, FILE_GENERIC_WRITE, CREATE_ALWAYS)?,
                None => duplicate_or_nul(std_handle, true)?,
            },
            None,
        ));
    };

    // Open the sink before spawning so a bad path fails the run instead of a
    // background thread.
    // shortcut: the archive has no internal size ceiling; add one when a run
    // without a limit must not fill the host disk.
    let sink = match file {
        Some(path) => Some(File::create(path)?),
        None => None,
    };
    let (pipe_read, pipe_write) = make_pipe()?;
    set_inheritable(&pipe_write)?;
    let reader = std::thread::Builder::new()
        .name(format!("river-{label}"))
        .spawn(move || pump(File::from(pipe_read), sink, limit, overflow))
        .map_err(|error| {
            io::Error::other(format!("failed to start the {label} reader: {error}"))
        })?;
    Ok((pipe_write, Some(reader)))
}

/// Drains one pipe into the optional archive file and counts the total.
fn pump(mut pipe: File, mut sink: Option<File>, limit: u64, overflow: usize) -> io::Result<u64> {
    let mut buffer = vec![0u8; READ_BUFFER_BYTES];
    let mut total = 0u64;
    let mut sink_error = None;
    loop {
        match pipe.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                total = total.saturating_add(n as u64);
                if let Some(file) = sink.as_mut()
                    && let Err(error) = file.write_all(&buffer[..n])
                {
                    // Keep draining: a stopped reader would block the child
                    // once the pipe buffer fills.
                    sink_error = Some(error);
                }
                if sink_error.is_some() {
                    sink = None;
                }
                if total > limit {
                    // SAFETY: the event handle is owned by the `StdioSet`,
                    // which is alive until `finish` joins this thread.
                    unsafe { SetEvent(overflow as HANDLE) };
                }
            }
            // A pipe closed mid-read behaves like EOF.
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => break,
            Err(error) if error.raw_os_error() == Some(232 /* ERROR_NO_DATA */) => break,
            Err(error) => return Err(error),
        }
    }
    match sink_error {
        Some(error) => Err(error),
        None => Ok(total),
    }
}

fn join(reader: Option<JoinHandle<io::Result<u64>>>) -> io::Result<u64> {
    match reader {
        None => Ok(0),
        Some(handle) => handle
            .join()
            .map_err(|_| io::Error::other("the stdio reader thread panicked"))?,
    }
}

fn make_pipe() -> io::Result<(OwnedHandle, OwnedHandle)> {
    let mut read: HANDLE = std::ptr::null_mut();
    let mut write: HANDLE = std::ptr::null_mut();
    // SAFETY: both out-pointers are valid; no security attributes, so neither
    // end is inheritable until `set_inheritable` marks the child end.
    if unsafe { CreatePipe(&mut read, &mut write, std::ptr::null(), 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both handles are fresh and owned.
    Ok(unsafe {
        (
            OwnedHandle::from_raw_handle(read as RawHandle),
            OwnedHandle::from_raw_handle(write as RawHandle),
        )
    })
}

fn set_inheritable(handle: &OwnedHandle) -> io::Result<()> {
    // SAFETY: the handle is owned and open.
    let ok = unsafe {
        SetHandleInformation(
            handle.as_raw_handle() as HANDLE,
            HANDLE_FLAG_INHERIT,
            HANDLE_FLAG_INHERIT,
        )
    };
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Opens a host path as an inheritable handle for the child.
fn open_inheritable(path: &Path, access: u32, disposition: u32) -> io::Result<OwnedHandle> {
    let name: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    // SAFETY: the name is NUL-terminated, `attributes` is valid for the call,
    // and the returned handle is owned.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &attributes,
            disposition,
            0,
            std::ptr::null_mut(),
        )
    };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `handle` is a fresh, owned handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) })
}

fn duplicate_or_nul(std_handle: u32, write: bool) -> io::Result<OwnedHandle> {
    // SAFETY: GetStdHandle only reads the per-process std handle table.
    let source = unsafe { GetStdHandle(std_handle) };
    if source.is_null() || source == INVALID_HANDLE_VALUE {
        return open_nul(write);
    }

    let mut duplicate: HANDLE = std::ptr::null_mut();
    // SAFETY: both process pseudo-handles are valid, `source` is an open
    // handle, and `duplicate` is a valid out-pointer.
    let ok = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            source,
            GetCurrentProcess(),
            &mut duplicate,
            0,
            1, // bInheritHandle
            DUPLICATE_SAME_ACCESS,
        )
    };
    if ok == 0 || duplicate.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `duplicate` is a fresh, owned handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(duplicate as RawHandle) })
}

fn open_nul(write: bool) -> io::Result<OwnedHandle> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    let name: [u16; 4] = ['N' as u16, 'U' as u16, 'L' as u16, 0];
    let access = if write {
        FILE_GENERIC_WRITE
    } else {
        FILE_GENERIC_READ
    };
    // SAFETY: the name is NUL-terminated, `attributes` is valid, and the
    // returned handle is owned.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &attributes,
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `handle` is a fresh, owned handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) })
}
