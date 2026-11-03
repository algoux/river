//! Job Object: resource limits (memory / CPU time / process count) and the
//! post-mortem memory measurement for a sandboxed child.
//!
//! A job is always created with `KILL_ON_JOB_CLOSE` so that a crashed judger
//! cannot leave the child running. When no user memory limit is set, the
//! internal safety ceiling (physical memory) is applied instead — "unlimited"
//! is a caller-side semantic, never a missing mechanism (see DESIGN.md §2.2).

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::time::Duration;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    JOB_OBJECT_LIMIT_PROCESS_TIME, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
    TerminateJobObject,
};
use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
use windows_sys::Win32::System::Threading::GetExitCodeProcess;

/// 100ns ticks per millisecond (Win32 time limit units).
const TICKS_PER_MS: u64 = 10_000;

pub(crate) fn physical_memory_bytes() -> u64 {
    let mut status = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    // SAFETY: `status` is a valid out-struct with dwLength set.
    unsafe { GlobalMemoryStatusEx(&mut status) };
    status.ullTotalPhys
}

/// RAII job object. Closing the handle kills every assigned process
/// (KILL_ON_JOB_CLOSE is always set).
pub(crate) struct Job {
    handle: OwnedHandle,
}

pub(crate) struct JobLimits {
    /// None = no caller limit; the physical-memory safety ceiling applies.
    pub memory_limit_bytes: Option<u64>,
    /// None = no CPU time limit.
    pub cpu_time_limit_ms: Option<u64>,
    /// Hard cap on concurrently alive processes in the job.
    pub max_processes: u32,
}

impl JobLimits {
    /// Effective memory limit: the user limit, or the physical-memory safety
    /// ceiling. `JOB_OBJECT_LIMIT_PROCESS_MEMORY` is therefore always set,
    /// which also enables `PeakProcessMemoryUsed` tracking.
    fn effective_memory_bytes(&self) -> u64 {
        self.memory_limit_bytes
            .unwrap_or_else(physical_memory_bytes)
    }
}

impl Job {
    pub(crate) fn new(limits: &JobLimits) -> io::Result<Self> {
        // SAFETY: no name; handle returned on success and wrapped in OwnedHandle.
        let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        let job = Job {
            handle: unsafe { OwnedHandle::from_raw_handle(raw as _) },
        };

        let mut basic = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        let li = &mut basic.BasicLimitInformation;
        li.LimitFlags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        li.ActiveProcessLimit = limits.max_processes.max(1);

        let mem = limits.effective_memory_bytes();
        li.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        basic.ProcessMemoryLimit = mem as usize;

        if let Some(ms) = limits.cpu_time_limit_ms {
            li.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_TIME;
            li.PerProcessUserTimeLimit = ms.saturating_mul(TICKS_PER_MS) as _;
        }

        // SAFETY: handle owned by `job`; info struct sized correctly.
        let ok = unsafe {
            SetInformationJobObject(
                job.raw(),
                JobObjectExtendedLimitInformation,
                &basic as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(job)
    }

    fn raw(&self) -> HANDLE {
        self.handle.as_raw_handle() as _
    }

    /// Attach a (suspended) process. Must happen before the first thread runs
    /// so no grandchild escapes the job.
    pub(crate) fn assign(&self, process: HANDLE) -> io::Result<()> {
        // SAFETY: both handles are valid and open.
        if unsafe { AssignProcessToJobObject(self.raw(), process) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Peak committed memory of the job's process tree, in bytes.
    pub(crate) fn peak_process_memory_used(&self) -> io::Result<u64> {
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        // SAFETY: handle owned; out-struct sized correctly.
        let ok = unsafe {
            QueryInformationJobObject(
                self.raw(),
                JobObjectExtendedLimitInformation,
                &mut info as *mut _ as *mut _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(info.PeakProcessMemoryUsed as u64)
        }
    }

    /// Kill every process in the job.
    pub(crate) fn terminate(&self, exit_code: u32) -> io::Result<()> {
        // SAFETY: handle owned.
        if unsafe { TerminateJobObject(self.raw(), exit_code) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

/// Convenience for tests (and later the monitor): block until `process` is
/// signaled, then return its exit code.
pub(crate) fn wait_process_exit(process: HANDLE) -> io::Result<u32> {
    // SAFETY: caller owns a valid process handle.
    let waited =
        unsafe { windows_sys::Win32::System::Threading::WaitForSingleObject(process, 0xFFFF_FFFF) };
    if waited != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut code: u32 = 0;
    // SAFETY: out-pointer valid.
    if unsafe { GetExitCodeProcess(process, &mut code) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(code)
}

/// Sleep helper so tests do not depend on external timing behaviour.
pub(crate) fn brief_pause() {
    std::thread::sleep(Duration::from_millis(150));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_memory_is_sane() {
        let m = physical_memory_bytes();
        assert!(m > 1024 * 1024 * 1024, "physical memory: {m}");
    }
}
