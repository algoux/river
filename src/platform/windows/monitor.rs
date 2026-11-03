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
    /// Processes still alive in the job after the main process exited.
    /// Non-zero means the program handed its work to a child that outlived
    /// it; the sandbox killed those children and the verdict becomes `SE`
    /// (sandbox anomaly) instead of `AC`.
    pub residual_processes: u32,
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

    // The main process is done: any process still alive in the job is a
    // descendant that outlived its parent. Kill it immediately (no program
    // may keep running after the judged process is gone) and report it so
    // the verdict can be `SE` instead of a misleading `AC`.
    let residual_processes = job.alive_process_count().unwrap_or(0);
    if residual_processes > 0 {
        let _ = job.terminate(KILL_EXIT_CODE);
    }

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
        residual_processes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use crate::platform::windows::verdict::{SIGKILL, classify_with_evidence};
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
            max_processes: crate::platform::windows::job::DEFAULT_MAX_PROCESSES,
        })?;
        let mut set = StdioSet::new(StdinSource::Null, None, None, None, None)?;
        let argvec: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let child = spawn_bare(Path::new(exe), &argvec, &job, &mut set, None, None)?;
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

    #[test]
    fn residual_descendants_are_detected_and_killed() {
        // The main process exits immediately while a child keeps running:
        // the child must be reported as residual and killed, not left behind.
        let job = Job::new(&JobLimits {
            memory_limit_bytes: Some(512 * 1024 * 1024),
            cpu_time_limit_ms: None,
            max_processes: crate::platform::windows::job::DEFAULT_MAX_PROCESSES,
        })
        .unwrap();
        let mut set = StdioSet::new(StdinSource::Null, None, None, None, None).unwrap();
        let args: Vec<String> = ["/c", "start /b ping -n 30 127.0.0.1 & exit 0"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let child = spawn_bare(Path::new("cmd"), &args, &job, &mut set, None, None).unwrap();
        let outcome = monitor(&child, &job, None).unwrap();
        assert_eq!(outcome.kill_reason, KillReason::None);
        assert!(
            outcome.residual_processes > 0,
            "expected a residual descendant, got {}",
            outcome.residual_processes
        );
        // After the monitor returned, nothing may still be alive.
        assert_eq!(job.alive_process_count().unwrap(), 0);
        set.finish().unwrap();
    }

    /// Compile a tiny native probe with rustc (same pattern as the S8
    /// mitigation probes in spawn.rs).
    fn compile_probe(dir: &Path, code: &str) -> PathBuf {
        let src = dir.join("probe.rs");
        let exe = dir.join("probe.exe");
        std::fs::write(&src, code).unwrap();
        let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
        let out = std::process::Command::new(rustc)
            .args(["-O", "-C", "panic=abort"])
            .arg("-o")
            .arg(&exe)
            .arg(&src)
            .output()
            .expect("spawn rustc");
        assert!(out.status.success(), "rustc failed: {}", String::from_utf8_lossy(&out.stderr));
        exe
    }

    #[test]
    fn cpu_limit_kill_is_tle_evidence() {
        // The job's PROCESS_TIME limit terminates the busy process; the
        // verdict must come from the CPU evidence, not the exit code.
        let cpu_limit = 500;
        let job = Job::new(&JobLimits {
            memory_limit_bytes: Some(512 * 1024 * 1024),
            cpu_time_limit_ms: Some(cpu_limit),
            max_processes: crate::platform::windows::job::DEFAULT_MAX_PROCESSES,
        })
        .unwrap();
        let mut set = StdioSet::new(StdinSource::Null, None, None, None, None).unwrap();
        let args: Vec<String> = ["/c", "for /l %i in (1,1,20000000) do @rem"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let child = spawn_bare(Path::new("cmd"), &args, &job, &mut set, None, None).unwrap();
        let outcome = monitor(&child, &job, None).unwrap();
        set.finish().unwrap();
        assert!(
            outcome.cpu_time_ms > u64::from(cpu_limit),
            "cpu {}ms over limit {cpu_limit}ms",
            outcome.cpu_time_ms
        );
        let v = classify_with_evidence(
            &outcome.kill_reason,
            outcome.exit_code,
            outcome.residual_processes,
            Some(u64::from(cpu_limit)),
            outcome.cpu_time_ms,
            None,
            0,
        );
        assert_eq!(v.status, "TLE");
        assert_eq!(v.signal, SIGKILL);
    }

    #[test]
    fn malloc_bomb_is_mle_evidence() {
        // A program that commits memory until the job's commit cap blocks
        // the next allocation ends abnormally; the peak pinned at the cap is
        // the MLE evidence — the exit code must not downgrade it to RE.
        let mem_limit = 32 * 1024 * 1024;
        let job = Job::new(&JobLimits {
            memory_limit_bytes: Some(mem_limit),
            cpu_time_limit_ms: None,
            max_processes: crate::platform::windows::job::DEFAULT_MAX_PROCESSES,
        })
        .unwrap();
        let work = tempfile_dir("river-s9-mle");
        let probe = compile_probe(
            &work,
            "fn main() { \
                 let mut bufs: Vec<Vec<u8>> = Vec::new(); \
                 loop { \
                     let mut b = vec![1u8; 4 << 20]; \
                     b[0] = 2; \
                     bufs.push(b); \
                 } \
             }",
        );
        let mut set = StdioSet::new(StdinSource::Null, None, None, None, None).unwrap();
        let child = spawn_bare(&probe, &[], &job, &mut set, None, None).unwrap();
        // Wall watchdog as a backstop: whichever comes first (heap abort or
        // watchdog kill), the evidence must classify MLE.
        let outcome = monitor(&child, &job, Some(std::time::Duration::from_secs(15))).unwrap();
        set.finish().unwrap();
        let peak = job.peak_process_memory_used().unwrap();
        assert!(
            peak + mem_limit as u64 / 8 >= mem_limit as u64,
            "peak {peak} should pin at the {mem_limit}-byte commit cap"
        );
        let v = classify_with_evidence(
            &outcome.kill_reason,
            outcome.exit_code,
            outcome.residual_processes,
            None,
            outcome.cpu_time_ms,
            Some(mem_limit as u64),
            peak,
        );
        assert_eq!(v.status, "MLE");
        assert_eq!(v.signal, SIGKILL);
        let _ = std::fs::remove_dir_all(&work);
    }

    /// Small unique temp dir for probe compilation.
    fn tempfile_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "{tag}-{}",
            std::process::id() as u64
                ^ std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u64
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
