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
    JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_PROCESS_MEMORY, JOB_OBJECT_LIMIT_PROCESS_TIME,
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_BASIC_PROCESS_ID_LIST,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicAccountingInformation,
    JobObjectBasicProcessIdList, JobObjectExtendedLimitInformation, QueryInformationJobObject,
    SetInformationJobObject, TerminateJobObject,
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
    /// Cap on concurrently alive processes in the job (main process
    /// included). The main process is the only *judged* process; descendants
    /// are tolerated up to this cap so ordinary wrappers (`cmd /c`,
    /// interpreter helpers) keep working, while fork bombs stay bounded.
    /// Residual descendants are killed as soon as the main process exits
    /// (see `monitor`), so a program cannot offload its work to a child.
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
        // Per-process limit: the MLE semantics (peak single process vs the
        // limit) are measured against this.
        li.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        basic.ProcessMemoryLimit = mem as usize;
        // Tree-level limit (option A semantics: the user limit is the whole
        // tree's budget, matching the Linux cgroup `memory.max` semantics).
        // Without it, N descendants each get their own full budget and the
        // tree's total commit reaches N x limit (verified: 8 children held
        // 18 MiB each under a 20 MiB per-process limit — 208 MiB peak tree
        // commit, ~10x the limit).
        li.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
        basic.JobMemoryLimit = mem as usize;

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
        Ok(self.job_memory_info()?.0)
    }

    /// Peak total commit of the whole tree (JobMemoryLimit accounting), in
    /// bytes. Feeds the MLE evidence when the *tree* pinned the limit even
    /// though no single process did.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn peak_job_memory_used(&self) -> io::Result<u64> {
        Ok(self.job_memory_info()?.1)
    }

    /// (PeakProcessMemoryUsed, PeakJobMemoryUsed) in bytes.
    fn job_memory_info(&self) -> io::Result<(u64, u64)> {
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
            Ok((
                info.PeakProcessMemoryUsed as u64,
                info.PeakJobMemoryUsed as u64,
            ))
        }
    }

    /// Total CPU time (user + kernel) consumed by the job's process tree.
    ///
    /// Why the job and not `GetProcessTimes` (S13 finding): on Windows 8+ the
    /// per-process CPU times of *another* process read back as 0 through
    /// `GetProcessTimes` — even with `PROCESS_ALL_ACCESS`, and even after the
    /// target exited (only a sliver of kernel time shows up). A process
    /// reading *its own* times works fine, which is why this looked like a
    /// river bug but is a Windows accounting rule.
    /// The job's accounting information is the supported way to get CPU time
    /// for a whole tree — and it is what a judge actually wants: the CPU of
    /// the main process *and* its descendants.
    pub(crate) fn cpu_time_ms(&self) -> io::Result<u64> {
        let mut info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        // SAFETY: handle owned; out-struct sized correctly.
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
        // The accounting times are in 100ns ticks.
        let ticks = info.TotalUserTime.max(0) as u64 + info.TotalKernelTime.max(0) as u64;
        Ok(ticks / 10_000)
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

    /// Number of processes currently alive in the job (tests).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn alive_process_count(&self) -> io::Result<u32> {
        Ok(self.alive_process_ids()?.len() as u32)
    }

    /// Pids of the processes currently alive in the job.
    ///
    /// The pid list lets the caller exclude the *main* process: the kernel
    /// updates the job's process list asynchronously, so right after the
    /// main process is signaled it may still be listed — counting it as a
    /// "residual descendant" produced spurious `SE` verdicts under load
    /// (observed: 1 in 400 concurrent runs).
    pub(crate) fn alive_process_ids(&self) -> io::Result<Vec<u32>> {
        // The process-id list is variable-length; query with a generous
        // buffer and grow it if the job holds more processes than fit.
        const INITIAL_CAPACITY: u32 = 64;
        let mut capacity = INITIAL_CAPACITY;
        loop {
            let byte_len = std::mem::size_of::<JOBOBJECT_BASIC_PROCESS_ID_LIST>()
                + (capacity as usize - 1) * std::mem::size_of::<usize>();
            let mut buf = vec![0u8; byte_len];
            // SAFETY: buffer is at least as large as the structure requires
            // for `capacity` entries; the length is passed along.
            let ok = unsafe {
                QueryInformationJobObject(
                    self.raw(),
                    JobObjectBasicProcessIdList,
                    buf.as_mut_ptr() as *mut _,
                    byte_len as u32,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                // ERROR_MORE_DATA (234) means the buffer was too small.
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(234) {
                    capacity = capacity.saturating_mul(2);
                    if capacity > 4096 {
                        return Err(err);
                    }
                    continue;
                }
                return Err(err);
            }
            // SAFETY: the call filled the buffer with a valid structure.
            let list = unsafe { &*(buf.as_ptr() as *const JOBOBJECT_BASIC_PROCESS_ID_LIST) };
            let count = list.NumberOfProcessIdsInList as usize;
            let ids = list.ProcessIdList.as_ptr();
            return Ok((0..count)
                .map(|i| {
                    // SAFETY: `ids` points at `count` valid entries inside
                    // the buffer we own.
                    unsafe { *ids.add(i) as u32 }
                })
                .collect());
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
#[cfg_attr(not(test), allow(dead_code))]
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
