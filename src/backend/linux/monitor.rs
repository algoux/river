//! Run monitoring: reap the main process, enforce the wall clock and the
//! CPU limit, and observe the output-kill events — the Linux counterpart of
//! `backend::windows::monitor`.
//!
//! Reaping goes through `wait4` so the rusage (CPU time, peak RSS of the
//! reaped tree) arrives with the exit status; the authoritative CPU and
//! memory numbers come from the run's cgroup (`cpu.stat` / `memory.peak`),
//! which also covers already-exited descendants.
//!
//! The CPU limit is enforced **actively**: every `CPU_POLL_INTERVAL` the
//! monitor reads `cpu.stat` and kills the tree once the measured usage
//! passes the limit. (Without this the limit was only a post-mortem verdict:
//! a 500ms CPU limit let the program run for the whole wall allowance —
//! measured at ~2s.)

use std::io;
use std::time::{Duration, Instant};

use super::cgroup::Cgroup;
use super::stdio::OverflowFlags;
use crate::contract::verdict::KillOrigin;

/// Everything the monitor observed about one finished run.
pub(crate) struct Outcome {
    pub(crate) kill: KillOrigin,
    /// Raw exit code: `WEXITSTATUS`, or `128 + WTERMSIG` on a signal
    /// termination.
    pub(crate) exit_code: u32,
    /// CPU time of the reaped tree, in milliseconds (rusage).
    pub(crate) cpu_time_ms: u64,
    /// Peak RSS of the reaped tree, in bytes (`ru_maxrss`).
    pub(crate) peak_memory_bytes: u64,
    pub(crate) wall_time_ms: u64,
}

/// How often the wait loop re-checks the overflow flags / wall deadline.
const POLL_INTERVAL: Duration = Duration::from_millis(2);

/// How often `cpu.stat` is read while the program runs. Overshoot of the CPU
/// limit is bounded by this interval (documented in DESIGN §5).
const CPU_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Consecutive `cpu.stat` read failures tolerated before the monitor gives
/// up, kills the tree and reports an infrastructure error (fail closed —
/// the verdict becomes `SE` instead of the CPU limit silently degrading to
/// the `RLIMIT_CPU` backstop).
const CPU_READ_FAILURE_LIMIT: u32 = 5;

/// Wait for `pid`, enforcing `wall_limit`, `cpu_limit_ms` (when given) and
/// the stdio overflow flags. On a sandbox kill the process group gets
/// SIGKILL and is reaped before returning.
pub(crate) fn monitor(
    pid: libc::pid_t,
    wall_limit: Duration,
    overflow: &OverflowFlags,
    cgroup: Option<&Cgroup>,
    cpu_limit_ms: Option<u64>,
) -> io::Result<Outcome> {
    let start = Instant::now();
    let deadline = start + wall_limit;
    let mut status: libc::c_int = 0;
    let mut rusage: libc::rusage = unsafe { std::mem::zeroed() };
    let mut last_cpu_check = start;
    let mut cpu_read_failures: u32 = 0;

    // wait4 with WNOHANG reaps as soon as the child exits AND carries the
    // rusage — waitpid(2) has no rusage, so wait4 is used from the start.
    loop {
        let rc = unsafe { libc::wait4(pid, &mut status, libc::WNOHANG, &mut rusage) };
        if rc == pid {
            break;
        }
        if rc < 0 {
            // A signal (e.g. SIGCHLD of an unrelated child) can interrupt the
            // wait; retrying is required, otherwise the run would be reported
            // as an infrastructure error while the program keeps running
            // without a watchdog.
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        // Still running: check the sandbox-kill conditions.
        if overflow.any() {
            return finish_killed(
                pid,
                KillOrigin::OutputLimit,
                start,
                &mut status,
                &mut rusage,
            );
        }
        if Instant::now() >= deadline {
            return finish_killed(
                pid,
                KillOrigin::WallTimeout,
                start,
                &mut status,
                &mut rusage,
            );
        }
        if let (Some(cg), Some(limit)) = (cgroup, cpu_limit_ms) {
            if last_cpu_check.elapsed() >= CPU_POLL_INTERVAL {
                last_cpu_check = Instant::now();
                match cg.usage_usec() {
                    Ok(usec) => {
                        cpu_read_failures = 0;
                        if usec / 1000 > limit {
                            return finish_killed(
                                pid,
                                KillOrigin::CpuLimit,
                                start,
                                &mut status,
                                &mut rusage,
                            );
                        }
                    }
                    Err(e) => {
                        // Fail closed: a transient read error is retried on
                        // the next tick, but persistent failures must not
                        // silently degrade the CPU limit to the RLIMIT_CPU
                        // backstop (whose overshoot is a full second). Kill
                        // and surface an infrastructure error (verdict SE).
                        cpu_read_failures += 1;
                        if cpu_read_failures >= CPU_READ_FAILURE_LIMIT {
                            let _ = unsafe { libc::kill(-pid, libc::SIGKILL) };
                            let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
                            return Err(e);
                        }
                    }
                }
            }
        }
        std::thread::sleep(POLL_INTERVAL);
    }

    Ok(Outcome {
        kill: KillOrigin::None,
        exit_code: decode_exit_code(status),
        cpu_time_ms: rusage_cpu_ms(&rusage),
        peak_memory_bytes: rusage_peak_bytes(&rusage),
        wall_time_ms: start.elapsed().as_millis() as u64,
    })
}

/// Kill the child's whole process group (the supervisor called `setsid`, so
/// its pid is the pgid; the program and its descendants all inherit it).
/// Falls back to the single pid if the group does not exist yet (the kill
/// can race the supervisor's `setsid`).
fn finish_killed(
    pid: libc::pid_t,
    kill: KillOrigin,
    start: Instant,
    status: &mut libc::c_int,
    rusage: &mut libc::rusage,
) -> io::Result<Outcome> {
    let rc = unsafe { libc::kill(-pid, libc::SIGKILL) };
    if rc != 0 {
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    let got = loop {
        let got = unsafe { libc::wait4(pid, status, 0, rusage) };
        if got == pid {
            break got;
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(err);
    };
    debug_assert_eq!(got, pid);
    Ok(Outcome {
        kill,
        exit_code: decode_exit_code(*status),
        cpu_time_ms: rusage_cpu_ms(rusage),
        peak_memory_bytes: rusage_peak_bytes(rusage),
        wall_time_ms: start.elapsed().as_millis() as u64,
    })
}

fn decode_exit_code(status: libc::c_int) -> u32 {
    if libc::WIFSIGNALED(status) {
        libc::WTERMSIG(status) as u32 + 128
    } else if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status) as u32
    } else {
        // Stopped/continued cannot appear for a reaped child without
        // WUNTRACED; treat defensively as abnormal.
        128 + libc::SIGKILL as u32
    }
}

fn rusage_cpu_ms(rusage: &libc::rusage) -> u64 {
    let secs = rusage.ru_utime.tv_sec + rusage.ru_stime.tv_sec;
    let usecs = rusage.ru_utime.tv_usec + rusage.ru_stime.tv_usec;
    (secs as u64 * 1000) + (usecs as u64 / 1000)
}

fn rusage_peak_bytes(rusage: &libc::rusage) -> u64 {
    // Linux reports ru_maxrss in KiB.
    rusage.ru_maxrss as u64 * 1024
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    fn monitor_simple(
        pid: libc::pid_t,
        wall: Duration,
        overflow: &OverflowFlags,
    ) -> io::Result<Outcome> {
        monitor(pid, wall, overflow, None, None)
    }

    /// A child that exits 0 is reaped with exit code 0 and no kill origin
    /// (removing the wait4 loop must make this hang or fail).
    #[test]
    fn clean_child_exit_is_reaped_without_kill() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe { libc::_exit(0) };
        }
        let outcome =
            monitor_simple(pid, Duration::from_secs(5), &OverflowFlags::default()).unwrap();
        assert_eq!(outcome.kill, KillOrigin::None);
        assert_eq!(outcome.exit_code, 0);
    }

    /// A hanging child is killed by the wall watchdog: kill origin
    /// WallTimeout, exit code 128+9 (the frozen signal-death encoding).
    #[test]
    fn wall_watchdog_kills_a_hanging_child() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            std::thread::sleep(Duration::from_secs(30));
            unsafe { libc::_exit(0) };
        }
        let outcome =
            monitor_simple(pid, Duration::from_millis(150), &OverflowFlags::default()).unwrap();
        assert_eq!(outcome.kill, KillOrigin::WallTimeout);
        assert_eq!(outcome.exit_code, 128 + libc::SIGKILL as u32);
        assert!(outcome.wall_time_ms < 5_000);
    }

    /// An overflow flag ends the run as an output kill (direct observation
    /// outranks the wall clock — contract classify priority 2).
    #[test]
    fn overflow_flag_kills_as_output_limit() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            std::thread::sleep(Duration::from_secs(30));
            unsafe { libc::_exit(0) };
        }
        let overflow = OverflowFlags::default();
        overflow.stdout.store(true, Ordering::Relaxed);
        let outcome = monitor(pid, Duration::from_secs(30), &overflow, None, None).unwrap();
        assert_eq!(outcome.kill, KillOrigin::OutputLimit);
    }

    /// With a cgroup + CPU limit the monitor kills a CPU-bound child long
    /// before the wall deadline (non-trivial: without the active poll the
    /// run lasts the full wall allowance).
    #[test]
    fn cpu_limit_kills_before_the_wall_deadline() {
        let cg = match Cgroup::create(512 * 1024 * 1024, 16) {
            Ok(cg) => cg,
            Err(e) => {
                eprintln!("skipping: cgroups unavailable: {e}");
                return;
            }
        };
        let procs = cg.procs_path_c().unwrap();
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe {
                let fd = libc::open(procs.as_ptr(), libc::O_WRONLY);
                let mut buf = [0u8; 16];
                let mut n = buf.len();
                let mut v = libc::getpid() as u64;
                loop {
                    n -= 1;
                    buf[n] = b'0' + (v % 10) as u8;
                    v /= 10;
                    if v == 0 {
                        break;
                    }
                }
                libc::write(fd, buf[n..].as_ptr().cast(), buf.len() - n);
                libc::close(fd);
            }
            let start = Instant::now();
            while start.elapsed() < Duration::from_secs(30) {}
            unsafe { libc::_exit(0) };
        }
        let t0 = Instant::now();
        let outcome = monitor(
            pid,
            Duration::from_secs(30),
            &OverflowFlags::default(),
            Some(&cg),
            Some(200),
        )
        .unwrap();
        assert_eq!(outcome.kill, KillOrigin::CpuLimit);
        assert!(t0.elapsed() < Duration::from_secs(5), "{:?}", t0.elapsed());
    }
}
