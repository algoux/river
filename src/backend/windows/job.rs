//! Job Object: a kill-on-close container plus the resource limits and
//! accounting used by the sandbox.
//!
//! The job is created before the child and the child is assigned while it is
//! still suspended, so no descendant can escape the job. `KILL_ON_JOB_CLOSE`
//! guarantees that closing the job handle reaps the whole tree, even when the
//! judger dies between the spawn and the wait.
//!
//! Limits use the native job mechanisms:
//! - CPU: `JOB_OBJECT_LIMIT_JOB_TIME` (the *user-mode* execution time of the
//!   whole job; the system terminates the job with `ERROR_NOT_ENOUGH_QUOTA`).
//!   The system checks this limit periodically, so a run can overshoot it;
//!   the measured user + kernel total is still reported in `Status`.
//! - memory: `JOB_OBJECT_LIMIT_JOB_MEMORY` (the commit charge of the whole
//!   tree; allocations past the limit fail).
//!
//! Accounting is read back from the same job: `TotalUserTime + TotalKernelTime`
//! for CPU and `PeakJobMemoryUsed` for the peak commit of the tree.

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_JOB_MEMORY,
    JOB_OBJECT_LIMIT_JOB_TIME, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
    QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
};

/// Exit code used when the sandbox itself terminates the job.
pub(crate) const KILL_EXIT_CODE: u32 = 1;

/// One 100-nanosecond tick, the unit of the job accounting fields.
const TICKS_PER_MS: u64 = 10_000;

pub(crate) struct JobLimits {
    /// Total CPU time ceiling for the job (native job time limit is
    /// user-mode only).
    pub cpu_time_limit_ms: Option<u64>,
    /// Peak committed memory ceiling for the whole job.
    pub memory_limit_bytes: Option<u64>,
}

/// RAII Job Object. Dropping it closes the handle, which terminates every
/// process still assigned to the job.
pub(crate) struct Job {
    handle: OwnedHandle,
}

impl Job {
    pub(crate) fn new(limits: &JobLimits) -> io::Result<Self> {
        // SAFETY: no name and no security attributes; the returned handle is
        // owned from here on.
        let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        let job = Job {
            // SAFETY: `raw` is a fresh, owned kernel handle.
            handle: unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) },
        };

        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

        if let Some(limit_ms) = limits.cpu_time_limit_ms {
            info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_TIME;
            let ticks = limit_ms.saturating_mul(TICKS_PER_MS).min(i64::MAX as u64);
            info.BasicLimitInformation.PerJobUserTimeLimit = ticks as i64;
        }
        if let Some(limit_bytes) = limits.memory_limit_bytes {
            info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
            info.JobMemoryLimit = limit_bytes.min(usize::MAX as u64) as usize;
        }

        // SAFETY: the job handle is owned and `info` is a valid, correctly
        // sized JOBOBJECT_EXTENDED_LIMIT_INFORMATION.
        let ok = unsafe {
            SetInformationJobObject(
                job.raw(),
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(job)
    }

    fn raw(&self) -> HANDLE {
        self.handle.as_raw_handle() as HANDLE
    }

    /// Assigns a suspended process to the job.
    pub(crate) fn assign(&self, process: HANDLE) -> io::Result<()> {
        // SAFETY: both handles are valid for the duration of the call.
        if unsafe { AssignProcessToJobObject(self.raw(), process) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Terminates every process in the job.
    pub(crate) fn terminate(&self, exit_code: u32) -> io::Result<()> {
        // SAFETY: the job handle is owned.
        if unsafe { TerminateJobObject(self.raw(), exit_code) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Total CPU time (user + kernel) consumed by every process that ever
    /// belonged to the job, in milliseconds.
    pub(crate) fn cpu_time_ms(&self) -> io::Result<u64> {
        let mut info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        // SAFETY: the job handle is owned and `info` is correctly sized.
        let ok = unsafe {
            QueryInformationJobObject(
                self.raw(),
                JobObjectBasicAccountingInformation,
                &mut info as *mut _ as *mut _,
                std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let user = info.TotalUserTime.max(0) as u64;
        let kernel = info.TotalKernelTime.max(0) as u64;
        Ok(user.saturating_add(kernel) / TICKS_PER_MS)
    }

    /// Peak committed memory of the whole job, in bytes.
    pub(crate) fn peak_job_memory_used(&self) -> io::Result<u64> {
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        // SAFETY: the job handle is owned and `info` is correctly sized.
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
            return Err(io::Error::last_os_error());
        }
        Ok(info.PeakJobMemoryUsed as u64)
    }
}
