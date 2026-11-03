//! Wait loop, wall-clock watchdog and time measurement for one run.
//!
//! CPU time comes from `GetProcessTimes` (kernel + user of the process;
//! with the one-process job limit there are no children to account for).
//! Wall time comes from `Instant` (QPC-backed on Windows). A run whose wall
//! limit is `None` still gets the 24h internal safety ceiling
//! (DESIGN.md §2.2: "unlimited" is caller semantics, never a missing
//! mechanism).

use std::io;
use std::os::windows::io::AsRawHandle;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{FILETIME, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::Threading::{GetProcessTimes, WaitForSingleObject};

use crate::platform::windows::job::Job;
use crate::platform::windows::spawn::SpawnedChild;

/// Internal safety ceiling applied when no wall limit is configured.
pub(crate) const SAFETY_WALL_LIMIT: Duration = Duration::from_secs(24 * 3600);

/// Exit code used when the sandbox kills the process tree.
pub(crate) const KILL_EXIT_CODE: u32 = 1;

/// Why the run ended the way it did.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum KillReason {
    /// The process exited on its own.
    None,
    /// Wall clock limit exceeded; the job was terminated by us.
    WallTimeout,
}

pub(crate) struct RunOutcome {
    pub exit_code: u32,
    pub cpu_time_ms: u64,
    pub wall_time_ms: u64,
    pub kill_reason: KillReason,
}

/// FILETIME (100ns ticks since epoch) -> milliseconds.
fn filetime_to_ms(ft: &FILETIME) -> u64 {
    let ticks = (ft.dwHighDateTime as u64) << 32 | ft.dwLowDateTime as u64;
    ticks / 10_000
}

/// Resume the child, wait up to `wall_limit` (None = safety ceiling), kill on
/// timeout, and collect timing.
pub(crate) fn monitor(
    child: &SpawnedChild,
    job: &Job,
    wall_limit: Option<Duration>,
) -> io::Result<RunOutcome> {
    let limit = wall_limit.unwrap_or(SAFETY_WALL_LIMIT);
    let started = Instant::now();
    child.resume()?;

    let handle = child.process.as_raw_handle() as _;
    // SAFETY: process handle is owned and valid.
    let wait =
        unsafe { WaitForSingleObject(handle, limit.as_millis().min(u32::MAX as u128) as u32) };

    let kill_reason = if wait == WAIT_OBJECT_0 {
        KillReason::None
    } else if wait == WAIT_TIMEOUT {
        job.terminate(KILL_EXIT_CODE)?;
        // SAFETY: handle still valid; the job kill guarantees signaling.
        unsafe { WaitForSingleObject(handle, 0xFFFF_FFFF) };
        KillReason::WallTimeout
    } else {
        return Err(io::Error::last_os_error());
    };

    let exit_code = child.wait_exit()?;
    let wall = started.elapsed();

    let (mut create, mut exit, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: process handle valid, out-pointers valid. Times remain readable
    // after exit because we still own the process handle.
    if unsafe { GetProcessTimes(handle, &mut create, &mut exit, &mut kernel, &mut user) } == 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(RunOutcome {
        exit_code,
        cpu_time_ms: filetime_to_ms(&kernel) + filetime_to_ms(&user),
        wall_time_ms: wall.as_millis() as u64,
        kill_reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::windows::job::JobLimits;
    use crate::platform::windows::spawn::spawn_bare;
    use crate::platform::windows::stdio::{StdinSource, StdioSet};
    use std::path::Path;

    fn run_monitored(
        exe: &str,
        args: &[&str],
        wall_limit: Option<Duration>,
    ) -> io::Result<RunOutcome> {
        let job = Job::new(&JobLimits {
            memory_limit_bytes: Some(512 * 1024 * 1024),
            cpu_time_limit_ms: None,
            max_processes: 1,
        })?;
        let mut set = StdioSet::new(StdinSource::Null, None, None, None, None)?;
        let argvec: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let child = spawn_bare(Path::new(exe), &argvec, &job, &mut set)?;
        let outcome = monitor(&child, &job, wall_limit)?;
        set.finish()?;
        Ok(outcome)
    }

    #[test]
    fn wall_time_exceeds_cpu_time_for_sleeping_process() {
        // ping waits ~2s (mostly idle) between two probes
        let o = run_monitored("ping", &["/n", "2", "127.0.0.1"], None).unwrap();
        assert_eq!(o.kill_reason, KillReason::None);
        assert_eq!(o.exit_code, 0);
        assert!(o.wall_time_ms >= 900, "wall {}ms", o.wall_time_ms);
        assert!(
            o.cpu_time_ms < o.wall_time_ms / 2,
            "cpu {}ms vs wall {}ms",
            o.cpu_time_ms,
            o.wall_time_ms
        );
    }

    #[test]
    fn cpu_time_is_measured_for_busy_process() {
        // cmd for-loop burning CPU
        let o = run_monitored("cmd", &["/c", "for /l %i in (1,1,2000000) do @rem"], None).unwrap();
        assert_eq!(o.kill_reason, KillReason::None);
        assert!(o.cpu_time_ms > 0, "cpu {}ms", o.cpu_time_ms);
    }

    #[test]
    fn wall_timeout_kills_and_reports() {
        let started = Instant::now();
        let o = run_monitored(
            "ping",
            &["/n", "10", "127.0.0.1"],
            Some(Duration::from_millis(300)),
        )
        .unwrap();
        assert_eq!(o.kill_reason, KillReason::WallTimeout);
        assert!(started.elapsed() < Duration::from_secs(5));
        // The job kill uses our exit code.
        assert_eq!(o.exit_code, KILL_EXIT_CODE);
    }
}
