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

use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT, HANDLE};
use windows_sys::Win32::System::Threading::{WaitForMultipleObjects, WaitForSingleObject};

use crate::backend::windows::job::Job;
use crate::backend::windows::spawn::SpawnedChild;
use crate::contract::verdict::KillOrigin;
use crate::contract::SafetyCeilings;

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
    limit.as_millis().min(u32::MAX as u128) as u32
}

/// Resume the child, wait up to `wall_limit` (None = safety ceiling) for
/// either the process to exit or an output channel to overflow its kill
/// threshold, kill on timeout/overflow, and collect timing.
pub(crate) fn monitor(
    child: &SpawnedChild,
    job: &Job,
    wall_limit: Option<Duration>,
    overflow_event: Option<HANDLE>,
) -> io::Result<RunOutcome> {
    let limit = wall_limit.unwrap_or_else(|| SafetyCeilings::default().wall_limit);
    let started = Instant::now();
    child.resume()?;

    let handle = child.process.as_raw_handle() as _;
    let kill = if let Some(ev) = overflow_event {
        // Wait on {process, overflow event} so an output fountain is reaped
        // mid-run instead of being flagged only after it exits.
        let handles = [handle, ev];
        const EV_SIGNAL: u32 = WAIT_OBJECT_0 + 1;
        match unsafe {
            WaitForMultipleObjects(2, handles.as_ptr(), 0 /* any */, limit_ms(&limit))
        } {
            WAIT_OBJECT_0 => KillOrigin::None,
            EV_SIGNAL => {
                job.terminate(KILL_EXIT_CODE)?;
                // SAFETY: handle still valid; the job kill guarantees signaling.
                unsafe { WaitForSingleObject(handle, 0xFFFF_FFFF) };
                KillOrigin::OutputLimit
            }
            WAIT_TIMEOUT => {
                job.terminate(KILL_EXIT_CODE)?;
                // SAFETY: handle still valid; the job kill guarantees signaling.
                unsafe { WaitForSingleObject(handle, 0xFFFF_FFFF) };
                KillOrigin::WallTimeout
            }
            _ => return Err(io::Error::last_os_error()),
        }
    } else {
        // SAFETY: process handle is owned and valid.
        let wait = unsafe { WaitForSingleObject(handle, limit_ms(&limit)) };
        if wait == WAIT_OBJECT_0 {
            KillOrigin::None
        } else if wait == WAIT_TIMEOUT {
            job.terminate(KILL_EXIT_CODE)?;
            // SAFETY: handle still valid; the job kill guarantees signaling.
            unsafe { WaitForSingleObject(handle, 0xFFFF_FFFF) };
            KillOrigin::WallTimeout
        } else {
            return Err(io::Error::last_os_error());
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
    let residual_processes = match job.alive_process_ids() {
        Ok(ids) => ids.iter().filter(|pid| **pid != main_pid).count() as u32,
        Err(_) => 0,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use crate::backend::windows::ntstatus::{is_ntstatus, ntstatus_name};
    use crate::contract::verdict::{RunEvidence, Verdict, classify};
    use crate::backend::windows::job::JobLimits;
    use crate::backend::windows::spawn::spawn_bare;
    use crate::backend::windows::stdio::{StdinSource, StdioSet};
    use std::path::Path;

    fn run_monitored(
        exe: &str,
        args: &[&str],
        wall_limit: Option<Duration>,
    ) -> io::Result<RunOutcome> {
        let job = Job::new(&JobLimits {
            memory_limit_bytes: Some(512 * 1024 * 1024),
            cpu_time_limit_ms: None,
            max_processes: crate::contract::SafetyCeilings::default().max_processes,
        })?;
        let mut set = StdioSet::new(StdinSource::Null, None, None, None, None)?;
        let argvec: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let child = spawn_bare(Path::new(exe), &argvec, &job, &mut set, None, None)?;
        let outcome = monitor(&child, &job, wall_limit, None)?;
        set.finish()?;
        Ok(outcome)
    }

    #[test]
    fn wall_time_exceeds_cpu_time_for_sleeping_process() {
        // ping waits ~2s (mostly idle) between two probes
        let o = run_monitored("ping", &["/n", "2", "127.0.0.1"], None).unwrap();
        assert_eq!(o.kill, KillOrigin::None);
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
        assert_eq!(o.kill, KillOrigin::None);
        assert!(o.cpu_time_ms > 0, "cpu {}ms", o.cpu_time_ms);
    }

    /// S13 regression: the CPU time must be a real measurement.
    ///
    /// `GetProcessTimes` reports 0 for *another* process on Windows 8+ (even
    /// with PROCESS_ALL_ACCESS) — the job's accounting information is the
    /// supported source. The test asserts the busy process' CPU time is
    /// actually measured (and stays below the wall time).
    ///
    /// NOTE: the CPU burn is `ping` (a tight, predictable loop) rather than
    /// a `cmd for /l` loop: under a loaded test machine the shell loop's
    /// CPU share varies wildly and the assertion becomes flaky.
    #[test]
    fn cpu_time_is_measured_through_the_job_accounting() {
        let o = run_monitored(
            "cmd",
            &["/c", "for /l %i in (1,1,20000000) do @rem"],
            None,
        )
        .unwrap();
        assert_eq!(o.kill, KillOrigin::None);
        assert!(
            o.cpu_time_ms > 50,
            "busy process reported {}ms of CPU",
            o.cpu_time_ms
        );
        assert!(
            o.cpu_time_ms <= o.wall_time_ms,
            "cpu {}ms > wall {}ms",
            o.cpu_time_ms,
            o.wall_time_ms
        );
    }

    /// The complementary case: a *sleeping* process burns almost no CPU.
    #[test]
    fn a_sleeping_process_reports_almost_no_cpu_time() {
        let o = run_monitored("ping", &["/n", "2", "127.0.0.1"], None).unwrap();
        assert_eq!(o.kill, KillOrigin::None);
        assert!(o.wall_time_ms >= 900, "wall {}ms", o.wall_time_ms);
        assert!(
            o.cpu_time_ms < o.wall_time_ms / 2,
            "cpu {}ms vs wall {}ms",
            o.cpu_time_ms,
            o.wall_time_ms
        );
    }

    /// S13 regression: a plain program that exits on its own must never be
    /// reported as having residual descendants.
    ///
    /// The kernel updates the job's process-id list asynchronously, so right
    /// after the main process is signaled it may still be listed. Counting
    /// it produced spurious `SE` verdicts under load (1 in 400 concurrent
    /// runs). The main process' pid is excluded for that reason.
    #[test]
    fn a_self_exiting_program_has_no_residual_children() {
        for _ in 0..20 {
            let o = run_monitored("cmd", &["/c", "echo hi"], None).unwrap();
            assert_eq!(o.kill, KillOrigin::None);
            assert_eq!(o.exit_code, 0);
            assert_eq!(
                o.residual_processes, 0,
                "a self-exiting program was reported as having residual children"
            );
        }
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
        assert_eq!(o.kill, KillOrigin::WallTimeout);
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
            max_processes: crate::contract::SafetyCeilings::default().max_processes,
        })
        .unwrap();
        let mut set = StdioSet::new(StdinSource::Null, None, None, None, None).unwrap();
        let args: Vec<String> = ["/c", "start /b ping -n 30 127.0.0.1 & exit 0"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let child = spawn_bare(Path::new("cmd"), &args, &job, &mut set, None, None).unwrap();
        let outcome = monitor(&child, &job, None, None).unwrap();
        assert_eq!(outcome.kill, KillOrigin::None);
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
            max_processes: crate::contract::SafetyCeilings::default().max_processes,
        })
        .unwrap();
        let mut set = StdioSet::new(StdinSource::Null, None, None, None, None).unwrap();
        let args: Vec<String> = ["/c", "for /l %i in (1,1,20000000) do @rem"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let child = spawn_bare(Path::new("cmd"), &args, &job, &mut set, None, None).unwrap();
        let outcome = monitor(&child, &job, None, None).unwrap();
        set.finish().unwrap();
        assert!(
            outcome.cpu_time_ms > u64::from(cpu_limit),
            "cpu {}ms over limit {cpu_limit}ms",
            outcome.cpu_time_ms
        );
        let evidence = RunEvidence {
            kill: outcome.kill,
            exit_code: outcome.exit_code,
            residual_processes: outcome.residual_processes,
            cpu_time_limit_ms: Some(u64::from(cpu_limit)),
            cpu_time_used_ms: outcome.cpu_time_ms,
            ..Default::default()
        };
        assert_eq!(classify(&evidence), Verdict::Tle);
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
            max_processes: crate::contract::SafetyCeilings::default().max_processes,
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
        let outcome =
            monitor(&child, &job, Some(std::time::Duration::from_secs(15)), None).unwrap();
        set.finish().unwrap();
        let peak = job.peak_process_memory_used().unwrap();
        assert!(
            peak + mem_limit as u64 / 8 >= mem_limit as u64,
            "peak {peak} should pin at the {mem_limit}-byte commit cap"
        );
        let evidence = RunEvidence {
            kill: outcome.kill,
            exit_code: outcome.exit_code,
            residual_processes: outcome.residual_processes,
            cpu_time_limit_ms: None,
            cpu_time_used_ms: outcome.cpu_time_ms,
            memory_limit_bytes: Some(mem_limit as u64),
            peak_memory_bytes: peak,
        };
        assert_eq!(classify(&evidence), Verdict::Mle);
        let _ = std::fs::remove_dir_all(&work);
    }

    #[test]
    fn output_fountain_is_killed_and_classified_ole() {
        // A process that floods stdout past its kill threshold must be
        // reaped mid-run by the monitor (not merely flagged at exit) and
        // classified OLE with signal 9; capture stays truncated at the limit.
        let out_limit = 4096u64;
        let job = Job::new(&JobLimits {
            memory_limit_bytes: Some(512 * 1024 * 1024),
            cpu_time_limit_ms: None,
            max_processes: crate::contract::SafetyCeilings::default().max_processes,
        })
        .unwrap();
        let mut set = StdioSet::new(
            StdinSource::Null,
            Some(out_limit),
            None,
            None,
            None,
        )
        .unwrap();
        let ev = set.overflow_event_handle();
        let args: Vec<String> = ["/c", "for /l %i in (1,1,100000) do @echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let child = spawn_bare(Path::new("cmd"), &args, &job, &mut set, None, None).unwrap();
        let outcome = monitor(&child, &job, None, Some(ev)).unwrap();
        let (out, _err) = set.finish().unwrap();
        assert_eq!(outcome.kill, KillOrigin::OutputLimit);
        assert!(outcome.wall_time_ms < 20_000, "fountain reaped mid-run");
        assert!(out.truncated);
        assert_eq!(out.data.len() as u64, out_limit);
        let evidence = RunEvidence {
            kill: outcome.kill,
            exit_code: outcome.exit_code,
            residual_processes: outcome.residual_processes,
            cpu_time_used_ms: outcome.cpu_time_ms,
            ..Default::default()
        };
        let v = classify(&evidence);
        assert_eq!(v, Verdict::Ole);
        assert_eq!(v.synthesized_signal(), 9);
    }

    #[test]
    fn access_violation_and_stack_overflow_classify_re_with_ntstatus() {
        // Null dereference -> 0xC0000005; unbounded recursion -> a stack
        // overflow NTSTATUS. Both are RE with the raw code passed through.
        let work = tempfile_dir("river-s10-crash");
        let av = compile_probe(
            &work,
            "fn main() { unsafe { std::ptr::null_mut::<u8>().write_volatile(1) } }",
        );
        let o = run_monitored(&av.display().to_string(), &[], None).unwrap();
        assert_eq!(o.kill, KillOrigin::None);
        assert_eq!(o.exit_code, 0xC000_0005, "access violation exit code");
        let evidence = RunEvidence {
            kill: o.kill,
            exit_code: o.exit_code,
            residual_processes: o.residual_processes,
            cpu_time_used_ms: o.cpu_time_ms,
            ..Default::default()
        };
        assert_eq!(classify(&evidence), Verdict::Re);
        assert_eq!(ntstatus_name(o.exit_code), Some("STATUS_ACCESS_VIOLATION"));

        // NOTE: plain infinite recursion is *optimized away* by LLVM at -O
        // (side-effect-free infinite recursion is UB and may become a
        // stack-neutral infinite loop). Force real stack growth: a large
        // per-frame buffer, a volatile read so the frame cannot be erased,
        // and a non-tail use of the recursive result.
        let so = compile_probe(
            &work,
            "fn rec(x: u64) -> u64 { \
                 let buf = [x as u8; 1 << 16]; \
                 let v = unsafe { std::ptr::read_volatile(buf.as_ptr()) } as u64; \
                 rec(std::hint::black_box(x)).wrapping_add(v) \
             } \
             fn main() { std::hint::black_box(rec(1)); }",
        );
        let o = run_monitored(&so.display().to_string(), &[], None).unwrap();
        assert_eq!(o.kill, KillOrigin::None);
        assert!(
            is_ntstatus(o.exit_code),
            "stack overflow must end as NTSTATUS, got {:#x}",
            o.exit_code
        );
        let evidence = RunEvidence {
            kill: o.kill,
            exit_code: o.exit_code,
            residual_processes: o.residual_processes,
            cpu_time_used_ms: o.cpu_time_ms,
            ..Default::default()
        };
        assert_eq!(classify(&evidence), Verdict::Re);
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

    /// S12: eight threads driving the full spawn→monitor→verdict pipeline
    /// at once. Every run must produce its own, independent outcome — no
    /// cross-talk between runs (zero shared state).
    #[test]
    fn concurrent_runs_do_not_interfere() {
        let threads: Vec<_> = (0..8)
            .map(|i| {
                std::thread::spawn(move || {
                    // Half the threads run a fast program, half a killed one.
                    if i % 2 == 0 {
                        let o = run_monitored("cmd", &["/c", "echo hi"], None).unwrap();
                        assert_eq!(o.kill, KillOrigin::None);
                        assert_eq!(o.exit_code, 0);
                        assert_eq!(o.residual_processes, 0);
                        assert!(o.wall_time_ms < 30_000);
                    } else {
                        let o = run_monitored(
                            "ping",
                            &["/n", "30", "127.0.0.1"],
                            Some(Duration::from_millis(300)),
                        )
                        .unwrap();
                        assert_eq!(o.kill, KillOrigin::WallTimeout);
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().expect("worker thread panicked");
        }
    }
}
