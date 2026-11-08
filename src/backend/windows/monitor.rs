//! Wait loop, wall-clock watchdog, CPU-limit enforcement and time
//! measurement for one run.
//!
//! CPU time comes from the **job accounting** (`Job::cpu_time_ms`: user +
//! kernel of the whole tree), never from `GetProcessTimes` — on Windows 8+
//! another process' per-process times read back as 0. A CPU limit is
//! enforced by polling that accounting every 10 ms and terminating the job,
//! the same contract as the Linux backend's `cpu.stat` poll. Wall time comes
//! from `Instant` (QPC-backed). A run whose wall limit is `None` still gets
//! the 24h internal safety ceiling (DESIGN.md §2.2: "unlimited" is caller
//! semantics, never a missing mechanism).

use std::io;
use std::os::windows::io::AsRawHandle;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::Threading::{WaitForMultipleObjects, WaitForSingleObject};

use crate::backend::windows::job::Job;
use crate::backend::windows::spawn::SpawnedChild;
use crate::contract::SafetyCeilings;
use crate::contract::verdict::KillOrigin;

/// Exit code used when the sandbox kills the process tree.
pub(crate) const KILL_EXIT_CODE: u32 = 1;

pub(crate) struct RunOutcome {
    pub exit_code: u32,
    pub cpu_time_ms: u64,
    pub wall_time_ms: u64,
    /// Why (and whether) the sandbox ended the run itself.
    pub kill: KillOrigin,
    /// Processes still alive in the job after the main process exited.
    /// Non-zero means the program handed its work to a child that outlived
    /// it; the sandbox killed those children and the verdict becomes `SE`
    /// (sandbox anomaly) instead of `AC`.
    pub residual_processes: u32,
}

fn limit_ms(limit: &Duration) -> u32 {
    // `u32::MAX` is `INFINITE` for the wait APIs: never produce it from a
    // computed duration (a 49.7-day wall limit would disable the watchdog).
    limit.as_millis().min((u32::MAX - 1) as u128) as u32
}

/// Count the processes still alive in the job (excluding the main pid, see
/// the note above). The query is retried a few times: the kernel updates the
/// job's process list asynchronously right after the main process exits, so
/// a single failed read is not evidence of "no residuals" — after
/// [`RESIDUAL_RETRIES`] consecutive failures the caller treats the invariant
/// as unverifiable (fail closed, verdict `SE`).
fn residual_count(job: &Job, main_pid: u32) -> io::Result<u32> {
    let mut last_err = None;
    for _ in 0..RESIDUAL_RETRIES {
        match job.alive_process_ids() {
            Ok(ids) => return Ok(ids.iter().filter(|pid| **pid != main_pid).count() as u32),
            Err(e) => {
                last_err = Some(e);
                std::thread::sleep(RESIDUAL_RETRY_DELAY);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::other("residual query failed")))
}

/// How often the job's CPU accounting is polled while a CPU limit is set.
/// Overshoot of the limit is bounded by this interval (the same contract as
/// the Linux `cpu.stat` poll).
const CPU_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Relaxed CPU poll interval used while the measured usage is well below the
/// limit (< 80%): a long CPU-limited run then costs ~5x fewer accounting
/// syscalls, while the final approach still runs at
/// [`CPU_POLL_INTERVAL`] so the kill overshoot bound is unchanged.
const CPU_POLL_INTERVAL_SLOW: Duration = Duration::from_millis(50);

/// Usage/limit ratio (percent) above which the monitor switches back to the
/// fast poll interval.
const CPU_POLL_FAST_ABOVE_PCT: u64 = 80;

/// Retry budget for the post-run residual-process query (see
/// [`residual_count`]); each retry waits
/// [`RESIDUAL_RETRY_DELAY`] to let the kernel settle the job list.
const RESIDUAL_RETRIES: usize = 3;
const RESIDUAL_RETRY_DELAY: Duration = Duration::from_millis(10);

fn wait_forever(handle: HANDLE) {
    // SAFETY: the process handle is owned and valid; INFINITE is fine here
    // because the job termination above guarantees the process signals.
    unsafe { WaitForSingleObject(handle, 0xFFFF_FFFF) };
}

/// Resume the child, wait up to `wall_limit` (None = safety ceiling) for the
/// process to exit, an output channel to overflow, or the tree's CPU time to
/// pass `cpu_limit_ms`, kill on any of those, and collect timing.
///
/// CPU is enforced by polling the job accounting (user + kernel of the whole
/// tree), not by `JOB_OBJECT_LIMIT_JOB_TIME`: a kernel job-time kill carries
/// no `KillOrigin`, and the recorded CPU can sit exactly at the limit, which
/// would classify a CPU-limit kill as `AC`.
pub(crate) fn monitor(
    child: &SpawnedChild,
    job: &Job,
    wall_limit: Option<Duration>,
    overflow_event: Option<HANDLE>,
    cpu_limit_ms: Option<u64>,
) -> io::Result<RunOutcome> {
    let limit = wall_limit.unwrap_or_else(|| SafetyCeilings::default().wall_limit);
    let started = Instant::now();
    child.resume()?;

    let handle = child.process.as_raw_handle() as _;
    let mut handles = vec![handle];
    if let Some(event) = overflow_event {
        handles.push(event);
    }
    let overflow_index = overflow_event.map(|_| 1usize);
    // Adaptive accounting poll: relaxed while far from the limit, fast near
    // it (and immediately after start, so a short limit still kills with the
    // 10 ms bound).
    let mut cpu_poll = CPU_POLL_INTERVAL;

    let kill = loop {
        let elapsed = started.elapsed();
        if elapsed >= limit {
            job.terminate(KILL_EXIT_CODE)?;
            wait_forever(handle);
            break KillOrigin::WallTimeout;
        }
        let remaining = limit - elapsed;
        // With a CPU limit, wake up on the current poll interval to read the
        // job accounting; otherwise block until the process/overflow event
        // or the deadline.
        let wait_ms = if cpu_limit_ms.is_some() {
            limit_ms(&remaining.min(cpu_poll))
        } else {
            limit_ms(&remaining)
        };
        // SAFETY: handles are valid (process handle owned; event owned by
        // StdioSet, which outlives this call).
        let rc =
            unsafe { WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, wait_ms) };
        match rc {
            WAIT_OBJECT_0 => break KillOrigin::None,
            WAIT_TIMEOUT => {
                if let Some(cpu_limit) = cpu_limit_ms {
                    let used = job.cpu_time_ms()?;
                    if used > cpu_limit {
                        job.terminate(KILL_EXIT_CODE)?;
                        wait_forever(handle);
                        break KillOrigin::CpuLimit;
                    }
                    cpu_poll = if used.saturating_mul(100)
                        < cpu_limit.saturating_mul(CPU_POLL_FAST_ABOVE_PCT)
                    {
                        CPU_POLL_INTERVAL_SLOW
                    } else {
                        CPU_POLL_INTERVAL
                    };
                }
                continue;
            }
            rc if overflow_index.is_some_and(|index| rc == WAIT_OBJECT_0 + index as u32) => {
                job.terminate(KILL_EXIT_CODE)?;
                wait_forever(handle);
                break KillOrigin::OutputLimit;
            }
            _ => return Err(io::Error::last_os_error()),
        }
    };

    let exit_code = child.wait_exit()?;
    let wall = started.elapsed();

    // The main process is done: any process still alive in the job is a
    // descendant that outlived its parent. Kill it immediately (no program
    // may keep running after the judged process is gone) and report it so
    // the verdict can be `SE` instead of a misleading `AC`.
    //
    // The main process' own pid is excluded: the kernel updates the job's
    // process list asynchronously, so right after the main process is
    // signaled it may still be listed — counting it as a residual
    // descendant produced spurious `SE` verdicts under load (1 in 400
    // concurrent runs).
    let main_pid = child.pid;
    let residual_processes = match residual_count(job, main_pid) {
        Ok(n) => n,
        Err(e) => {
            // Fail closed: the anti-cheat invariant ("no descendant may
            // outlive the main process") could not be verified. Reporting 0
            // here would silently disable it; `infra_se` keeps the verdict
            // `SE` instead of a potentially misleading `AC`/`RE`.
            let _ = job.terminate(KILL_EXIT_CODE);
            return Err(e);
        }
    };
    if residual_processes > 0 {
        let _ = job.terminate(KILL_EXIT_CODE);
    }

    // CPU time comes from the *job* accounting, not from `GetProcessTimes`:
    // on Windows 8+ the CPU times of another process read back as 0 through
    // `GetProcessTimes` (even with PROCESS_ALL_ACCESS), while the job
    // accounting reports the whole tree — which is also what a judge wants.
    // See `Job::cpu_time_ms`.
    let cpu_time_ms = job.cpu_time_ms().unwrap_or(0);

    Ok(RunOutcome {
        exit_code,
        cpu_time_ms,
        wall_time_ms: wall.as_millis() as u64,
        kill,
        residual_processes,
    })
}
