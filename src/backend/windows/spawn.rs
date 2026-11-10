//! Process creation for the sandbox child.
//!
//! The child is created suspended, assigned to its Job Object and only then
//! resumed, so a fast child cannot spawn descendants outside the job. The
//! initial thread inherits exactly the three standard handles prepared by
//! [`super::stdio`] (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`); when an
//! AppContainer SID is supplied, it additionally becomes an AppContainer at
//! creation time through `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`.

use std::ffi::OsStr;
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::Path;

use windows_sys::Win32::Foundation::{HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::Security::{PSID, SECURITY_CAPABILITIES};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, INFINITE, InitializeProcThreadAttributeList,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess,
    UpdateProcThreadAttribute, WaitForMultipleObjects, WaitForSingleObject,
};

use super::job::Job;
use super::stdio::StdioSet;

pub(crate) struct SpawnConfig<'a> {
    pub executable: &'a Path,
    pub args: &'a [String],
    pub cwd: Option<&'a Path>,
    /// UTF-16 `K=V\0` pairs, double-NUL terminated.
    pub env_block: &'a [u16],
    /// `Some` runs the child as an AppContainer with this identity.
    pub appcontainer_sid: Option<PSID>,
    pub job: &'a Job,
}

/// A suspended child that has already been assigned to the job.
pub(crate) struct SpawnedChild {
    process: OwnedHandle,
    thread: OwnedHandle,
}

impl SpawnedChild {
    /// Lets the initial thread run.
    pub(crate) fn resume(&self) -> io::Result<()> {
        // SAFETY: the thread handle is owned.
        let previous = unsafe { ResumeThread(self.thread.as_raw_handle() as HANDLE) };
        if previous == u32::MAX {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Waits up to `timeout_ms` (`None` = infinite).
    ///
    /// Returns `None` when the timeout expired, or the exit code once the
    /// process has exited.
    pub(crate) fn wait(&self, timeout_ms: Option<u32>) -> io::Result<Option<u32>> {
        let timeout = timeout_ms.unwrap_or(INFINITE);
        // SAFETY: the process handle is owned.
        match unsafe { WaitForSingleObject(self.process_handle(), timeout) } {
            WAIT_OBJECT_0 => Ok(Some(self.exit_code()?)),
            WAIT_TIMEOUT => Ok(None),
            WAIT_FAILED => Err(io::Error::last_os_error()),
            other => Err(io::Error::other(format!(
                "WaitForSingleObject returned unexpected value {other}"
            ))),
        }
    }

    pub(crate) fn exit_code(&self) -> io::Result<u32> {
        let mut code = 0u32;
        // SAFETY: the process handle is owned; `code` is a valid out-pointer.
        if unsafe { GetExitCodeProcess(self.process_handle(), &mut code) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(code)
        }
    }

    fn process_handle(&self) -> HANDLE {
        self.process.as_raw_handle() as HANDLE
    }

    /// Waits for the child or for the stdio overflow event, whichever comes
    /// first.
    pub(crate) fn wait_with_overflow(
        &self,
        overflow: HANDLE,
        timeout_ms: Option<u32>,
    ) -> io::Result<WaitResult> {
        let handles = [self.process_handle(), overflow];
        let timeout = timeout_ms.unwrap_or(INFINITE);
        // SAFETY: both handles are valid for the call and `handles` has two
        // entries as declared.
        let result = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, timeout) };
        match result {
            WAIT_OBJECT_0 => Ok(WaitResult::Exited(self.exit_code()?)),
            WAIT_OUTPUT_OVERFLOW => Ok(WaitResult::OutputOverflow),
            WAIT_TIMEOUT => Ok(WaitResult::TimedOut),
            WAIT_FAILED => Err(io::Error::last_os_error()),
            other => Err(io::Error::other(format!(
                "WaitForMultipleObjects returned unexpected value {other}"
            ))),
        }
    }
}

/// How a wait on the child plus the output-overflow event ended.
#[derive(Clone, Copy)]
pub(crate) enum WaitResult {
    Exited(u32),
    TimedOut,
    OutputOverflow,
}

/// `WAIT_OBJECT_0 + 1`: the output-overflow event's index in the wait set.
const WAIT_OUTPUT_OVERFLOW: u32 = WAIT_OBJECT_0 + 1;

/// Spawns `config.executable`, assigns it to the job and returns it while
/// still suspended. On any failure the not-yet-handed-off child is
/// terminated (closing its handles alone would leave a suspended process
/// running outside the job).
pub(crate) fn spawn(config: SpawnConfig<'_>, stdio: &StdioSet) -> io::Result<SpawnedChild> {
    let raw_handles = stdio.raw_handles();

    let mut command_line = build_command_line(config.executable, config.args);
    let cwd_wide = config.cwd.map(wide_of_path);

    let attribute_count = if config.appcontainer_sid.is_some() {
        2
    } else {
        1
    };
    let mut attributes = AttributeList::new(attribute_count)?;
    attributes.add(
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        raw_handles.as_ptr() as *const core::ffi::c_void,
        size_of::<[HANDLE; 3]>(),
    )?;

    let capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: config.appcontainer_sid.unwrap_or(std::ptr::null_mut()),
        Capabilities: std::ptr::null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };
    if config.appcontainer_sid.is_some() {
        attributes.add(
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            &capabilities as *const _ as *const core::ffi::c_void,
            size_of::<SECURITY_CAPABILITIES>(),
        )?;
    }

    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = raw_handles[0];
    startup.StartupInfo.hStdOutput = raw_handles[1];
    startup.StartupInfo.hStdError = raw_handles[2];
    startup.lpAttributeList = attributes.as_ptr();

    let mut process_info = PROCESS_INFORMATION::default();
    let flags = CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT;
    // SAFETY: the command line is mutable and NUL-terminated, the environment
    // block is a valid double-NUL UTF-16 block, the attribute list and its
    // values outlive the call, and `process_info` is a valid out-struct.
    let ok = unsafe {
        CreateProcessW(
            std::ptr::null(),
            command_line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1, // bInheritHandles
            flags,
            config.env_block.as_ptr() as *const core::ffi::c_void,
            cwd_wide
                .as_ref()
                .map_or(std::ptr::null(), |cwd| cwd.as_ptr()),
            &startup.StartupInfo,
            &mut process_info,
        )
    };
    // The attribute list may be deleted once CreateProcessW returns.
    drop(attributes);

    if ok == 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: both handles are fresh and owned by this process.
    let child = SpawnedChild {
        process: unsafe { OwnedHandle::from_raw_handle(process_info.hProcess as RawHandle) },
        thread: unsafe { OwnedHandle::from_raw_handle(process_info.hThread as RawHandle) },
    };
    // Until the assign succeeds the child is outside the job; if anything
    // fails, the guard terminates it.
    let guard = SuspendedGuard::new(child);
    config.job.assign(guard.child().process_handle())?;
    let child = guard.disarm();

    // The child-facing handles stay owned by `stdio`; `StdioSet::finish`
    // closes the judger's copies once the run is over.
    Ok(child)
}

struct SuspendedGuard {
    child: Option<SpawnedChild>,
}

impl SuspendedGuard {
    fn new(child: SpawnedChild) -> Self {
        SuspendedGuard { child: Some(child) }
    }

    fn child(&self) -> &SpawnedChild {
        self.child.as_ref().expect("suspended guard disarmed")
    }

    fn disarm(mut self) -> SpawnedChild {
        self.child.take().expect("suspended guard disarmed twice")
    }
}

impl Drop for SuspendedGuard {
    fn drop(&mut self) {
        if let Some(child) = &self.child {
            // SAFETY: the process handle is owned.
            unsafe { TerminateProcess(child.process_handle(), 1) };
            let _ = child.wait(None);
        }
    }
}

/// Builds the mutable UTF-16 command line expected by `CreateProcessW`.
pub(crate) fn build_command_line(executable: &Path, args: &[String]) -> Vec<u16> {
    let mut line = Vec::new();
    append_arg(&mut line, executable.as_os_str());
    for arg in args {
        line.push(b' ' as u16);
        append_arg(&mut line, OsStr::new(arg));
    }
    line.push(0);
    line
}

/// Quotes one argument using the `CommandLineToArgvW` rules.
fn append_arg(line: &mut Vec<u16>, arg: &OsStr) {
    let units: Vec<u16> = arg.encode_wide().collect();
    if units.is_empty() {
        line.push(b'"' as u16);
        line.push(b'"' as u16);
        return;
    }
    let needs_quotes = units.iter().any(|unit| matches!(*unit, 0x20 | 0x09 | 0x22));
    if !needs_quotes {
        line.extend(units);
        return;
    }

    line.push(b'"' as u16);
    let mut backslashes = 0usize;
    for unit in units {
        if unit == b'\\' as u16 {
            backslashes += 1;
            continue;
        }
        if unit == b'"' as u16 {
            line.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2 + 1));
            line.push(unit);
        } else {
            line.extend(std::iter::repeat_n(b'\\' as u16, backslashes));
            line.push(unit);
        }
        backslashes = 0;
    }
    // Trailing backslashes must be doubled, otherwise they escape the
    // closing quote.
    line.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2));
    line.push(b'"' as u16);
}

/// Builds a sorted, double-NUL terminated UTF-16 environment block.
pub(crate) fn env_block(vars: &[(String, String)]) -> Vec<u16> {
    let mut sorted: Vec<&(String, String)> = vars.iter().collect();
    sorted.sort_unstable_by(|(a, _), (b, _)| {
        a.bytes()
            .map(|c| c.to_ascii_lowercase())
            .cmp(b.bytes().map(|c| c.to_ascii_lowercase()))
    });

    let mut block = Vec::new();
    for (key, value) in sorted {
        block.extend(key.encode_utf16());
        block.push(b'=' as u16);
        block.extend(value.encode_utf16());
        block.push(0);
    }
    block.push(0);
    block
}

fn wide_of_path(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// RAII `PROC_THREAD_ATTRIBUTE_LIST`.
struct AttributeList {
    buffer: Vec<usize>,
    initialized: bool,
}

impl AttributeList {
    fn new(count: u32) -> io::Result<Self> {
        let mut size = 0usize;
        // SAFETY: the first call with a null list only queries the size.
        unsafe {
            InitializeProcThreadAttributeList(std::ptr::null_mut(), count, 0, &mut size);
        }
        if size == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut list = AttributeList {
            buffer: vec![0usize; size.div_ceil(size_of::<usize>())],
            initialized: false,
        };
        // SAFETY: the buffer is large enough for `count` attributes.
        let ok = unsafe {
            InitializeProcThreadAttributeList(
                list.buffer.as_mut_ptr() as *mut core::ffi::c_void,
                count,
                0,
                &mut size,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        list.initialized = true;
        Ok(list)
    }

    fn add(
        &mut self,
        attribute: u32,
        value: *const core::ffi::c_void,
        value_size: usize,
    ) -> io::Result<()> {
        // SAFETY: the list is initialized and `value` points at `value_size`
        // bytes that stay valid through `CreateProcessW`.
        let ok = unsafe {
            UpdateProcThreadAttribute(
                self.buffer.as_mut_ptr() as *mut core::ffi::c_void,
                0,
                attribute as usize,
                value,
                value_size,
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn as_ptr(&mut self) -> *mut core::ffi::c_void {
        self.buffer.as_mut_ptr() as *mut core::ffi::c_void
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        if self.initialized {
            // SAFETY: the list was initialized exactly once and is deleted
            // exactly once.
            unsafe {
                DeleteProcThreadAttributeList(self.buffer.as_mut_ptr() as *mut core::ffi::c_void);
            }
        }
    }
}
