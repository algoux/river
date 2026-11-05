//! Run monitoring: reap the main process, enforce the wall clock and the
//! CPU limit, and observe the output-kill events — the Linux counterpart of
//! `backend::windows::monitor`.
//!
//! Reaping goes through `wait4` so the rusage (CPU time, peak RSS of the
//! reaped tree) arrives with the exit status; the authoritative CPU and
//! memory numbers come from the run's cgroup (`cpu.stat` / `memory.peak`),
//! which also covers already-exited descendants.
//!
//! **Waiting is event-driven**: `pidfd_open` + `poll` on the pidfd and on the
//! stdio overflow `eventfd` wakes the monitor exactly when the process exits
//! or an output channel crosses its kill threshold, so an idle run costs
//! **zero** wakeups (the old loop polled `wait4(WNOHANG)` every 2 ms —
//! measured at ~458 wakeups/s per run). Kernels without `pidfd_open` fall
//! back to that polling loop ([`monitor_polling`]).
//!
//! The CPU limit is enforced **actively**: while it is set, the `poll`
//! timeout is capped at `CPU_POLL_INTERVAL` so `cpu.stat` is re-read on that
//! cadence; once the measured usage passes the limit the tree is killed
//! (the same contract as the Windows job-accounting poll).

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

/// Legacy polling cadence (only used when `pidfd_open` is unavailable): how
/// often the wait loop re-checks the overflow flags / wall deadline.
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
    match pidfd_open(pid) {
        Ok(pidfd) => {
            let result = monitor_evented(pid, pidfd, wall_limit, overflow, cgroup, cpu_limit_ms);
            // SAFETY: the fd is ours and no longer used after this point.
            unsafe { libc::close(pidfd) };
            result
        }
        // Old kernels (no SYS_pidfd_open): the polling loop still enforces
        // every limit, it just costs wakeups. `EINVAL` means the kernel
        // knows the syscall but rejected the flags -- same "not supported
        // here" situation.
        //
        // Every OTHER error (EMFILE/ENFILE: the *judger* ran out of
        // descriptors) is an infrastructure failure, not a reason to
        // silently degrade every concurrent run to the 2 ms polling path
        // (measured: ~458 wakeups/second per run). Report it instead.
        Err(e) => match e.raw_os_error() {
            Some(libc::ENOSYS) | Some(libc::EINVAL) => {
                monitor_polling(pid, wall_limit, overflow, cgroup, cpu_limit_ms)
            }
            _ => Err(e),
        },
    }
}

/// Is `pidfd_open` usable on this kernel? Reported by `doctor()` so an
/// operator can tell whether the judge pays the polling cost.
pub(crate) fn pidfd_available() -> bool {
    // A pid always fits a pid_t (the kernel's own pid space is pid_t).
    let pid = std::process::id() as libc::pid_t;
    match pidfd_open(pid) {
        Ok(fd) => {
            // SAFETY: the fd is ours and no longer used after this point.
            unsafe { libc::close(fd) };
            true
        }
        Err(_) => false,
    }
}

fn pidfd_open(pid: libc::pid_t) -> io::Result<libc::c_int> {
    // SAFETY: plain syscall, no pointers involved.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd as libc::c_int)
    }
}

/// Event-driven wait: `poll` on the pidfd (process exit) and the overflow
/// eventfd (kill threshold crossed), with the CPU poll interval as the
/// timeout when a CPU limit is set.
fn monitor_evented(
    pid: libc::pid_t,
    pidfd: libc::c_int,
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
    let overflow_fd = overflow.event_fd();

    loop {
        // The atomics are the source of truth: an eventfd write may have
        // been lost (counter full) and a reader may fire before the poll
        // starts.
        if overflow.any() {
            overflow.drain_event();
            return finish_killed(
                pid,
                KillOrigin::OutputLimit,
                start,
                &mut status,
                &mut rusage,
            );
        }
        let now = Instant::now();
        if now >= deadline {
            return finish_killed(
                pid,
                KillOrigin::WallTimeout,
                start,
                &mut status,
                &mut rusage,
            );
        }
        let remaining_ms = (deadline - now).as_millis().min(i32::MAX as u128) as i32;
        // With a CPU limit the poll must wake at least every
        // CPU_POLL_INTERVAL to read `cpu.stat`; otherwise it sleeps until
        // the deadline and only the pidfd/eventfd can wake it.
        let timeout_ms = if cpu_limit_ms.is_some() {
            let poll_ms = CPU_POLL_INTERVAL.as_millis().min(i32::MAX as u128) as i32;
            poll_ms.min(remaining_ms)
        } else {
            remaining_ms
        };

        let mut fds = [
            libc::pollfd {
                fd: pidfd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: overflow_fd.unwrap_or(-1),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let nfds = if overflow_fd.is_some() { 2 } else { 1 };
        // SAFETY: the array outlives the call; nfds matches the filled
        // entries.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), nfds, timeout_ms) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        if rc > 0 {
            if fds[0].revents != 0 {
                // The process exited (or the pidfd reported an error): reap
                // it with a blocking wait4 to collect the exit status and
                // rusage.
                wait4_blocking(pid, &mut status, &mut rusage)?;
                return Ok(Outcome {
                    kill: KillOrigin::None,
                    exit_code: decode_exit_code(status),
                    cpu_time_ms: rusage_cpu_ms(&rusage),
                    peak_memory_bytes: rusage_peak_bytes(&rusage),
                    wall_time_ms: start.elapsed().as_millis() as u64,
                });
            }
            if nfds == 2 && fds[1].revents != 0 {
                overflow.drain_event();
                return finish_killed(
                    pid,
                    KillOrigin::OutputLimit,
                    start,
                    &mut status,
                    &mut rusage,
                );
            }
        }
        // Either the poll timed out or it woke for a reason we do not act on
        // (pidfd has POLLPRI in some kernels); check the CPU limit on its
        // own cadence.
        if let (Some(cg), Some(limit)) = (cgroup, cpu_limit_ms)
            && last_cpu_check.elapsed() >= CPU_POLL_INTERVAL
        {
            last_cpu_check = Instant::now();
            match poll_cpu(cg, limit, &mut cpu_read_failures) {
                Ok(true) => {
                    return finish_killed(
                        pid,
                        KillOrigin::CpuLimit,
                        start,
                        &mut status,
                        &mut rusage,
                    );
                }
                Ok(false) => {}
                Err(e) => {
                    kill_tree(pid);
                    return Err(e);
                }
            }
        }
    }
}

/// Legacy wait loop for kernels without `pidfd_open`: `wait4(WNOHANG)` plus
/// a 2ms sleep. Functionally identical, but costs one wakeup per 2ms.
fn monitor_polling(
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
        if let (Some(cg), Some(limit)) = (cgroup, cpu_limit_ms)
            && last_cpu_check.elapsed() >= CPU_POLL_INTERVAL
        {
            last_cpu_check = Instant::now();
            match poll_cpu(cg, limit, &mut cpu_read_failures) {
                Ok(true) => {
                    return finish_killed(
                        pid,
                        KillOrigin::CpuLimit,
                        start,
                        &mut status,
                        &mut rusage,
                    );
                }
                Ok(false) => {}
                Err(e) => {
                    kill_tree(pid);
                    return Err(e);
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

/// Read `cpu.stat` once. `Ok(true)` means the CPU limit was exceeded.
/// Persistent read errors are returned as `Err` (fail closed: the caller
/// kills the tree and the run becomes `SE` instead of silently degrading to
/// the `RLIMIT_CPU` backstop, whose overshoot is a full second).
fn poll_cpu(cg: &Cgroup, limit_ms: u64, failures: &mut u32) -> io::Result<bool> {
    match cg.usage_usec() {
        Ok(usec) => {
            *failures = 0;
            Ok(usec / 1000 > limit_ms)
        }
        Err(e) => {
            *failures += 1;
            if *failures >= CPU_READ_FAILURE_LIMIT {
                Err(e)
            } else {
                Ok(false)
            }
        }
    }
}

/// Kill the child's whole process group (the supervisor called `setsid`, so
/// its pid is the pgid; the program and its descendants all inherit it).
/// Falls back to the single pid if the group does not exist yet (the kill
/// can race the supervisor's `setsid`).
fn kill_tree(pid: libc::pid_t) {
    let rc = unsafe { libc::kill(-pid, libc::SIGKILL) };
    if rc != 0 {
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
}

fn wait4_blocking(
    pid: libc::pid_t,
    status: &mut libc::c_int,
    rusage: &mut libc::rusage,
) -> io::Result<()> {
    loop {
        let got = unsafe { libc::wait4(pid, status, 0, rusage) };
        if got == pid {
            return Ok(());
        }
        if got < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        // `wait4` without WNOHANG cannot return 0; loop defensively.
    }
}

fn finish_killed(
    pid: libc::pid_t,
    kill: KillOrigin,
    start: Instant,
    status: &mut libc::c_int,
    rusage: &mut libc::rusage,
) -> io::Result<Outcome> {
    kill_tree(pid);
    wait4_blocking(pid, status, rusage)?;
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
    /// (removing the wait path must make this hang or fail).
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

    /// An overflow flag set *before* the monitor starts ends the run as an
    /// output kill (direct observation outranks the wall clock — contract
    /// classify priority 2).
    #[test]
    fn overflow_flag_kills_as_output_limit() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            std::thread::sleep(Duration::from_secs(30));
            unsafe { libc::_exit(0) };
        }
        let overflow = OverflowFlags::default();
        overflow.fire(0);
        let outcome = monitor(pid, Duration::from_secs(30), &overflow, None, None).unwrap();
        assert_eq!(outcome.kill, KillOrigin::OutputLimit);
    }

    /// The middleware that matters for the event-driven path: an overflow
    /// fired *while* the monitor is blocked in `poll` (not before it
    /// starts) must wake it immediately — the child would sleep for 30s.
    #[test]
    fn evented_monitor_wakes_on_overflow_while_polling() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            std::thread::sleep(Duration::from_secs(30));
            unsafe { libc::_exit(0) };
        }
        let overflow = std::sync::Arc::new(OverflowFlags::default());
        let fired = std::sync::Arc::clone(&overflow);
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            fired.fire(1);
        });
        let outcome = monitor(pid, Duration::from_secs(30), &overflow, None, None).unwrap();
        t.join().unwrap();
        assert_eq!(outcome.kill, KillOrigin::OutputLimit);
        assert!(
            outcome.wall_time_ms < 5_000,
            "overflow wakeup took {}ms",
            outcome.wall_time_ms
        );
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

    /// The atomics stay authoritative even when the eventfd was never
    /// written (reader crashed before the write, or the fd is unavailable):
    /// the monitor's wake-up path re-checks them.
    #[test]
    fn overflow_atomic_without_eventfd_wakeup_still_kills() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            std::thread::sleep(Duration::from_secs(30));
            unsafe { libc::_exit(0) };
        }
        let overflow = std::sync::Arc::new(OverflowFlags::default());
        let flag = std::sync::Arc::clone(&overflow);
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            // Set the atomic directly: simulates a wakeup that never came.
            flag.stdout.store(true, Ordering::Relaxed);
        });
        // The wall limit bounds the wait: the kill must still be attributed
        // to the output evidence, not the wall clock (the flag is checked
        // on every wake, including the wall timeout).
        let outcome = monitor(pid, Duration::from_millis(300), &overflow, None, None).unwrap();
        t.join().unwrap();
        assert_eq!(outcome.kill, KillOrigin::OutputLimit);
    }
}
