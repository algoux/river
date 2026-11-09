use std::io;
use std::time::{Duration, Instant};

use super::cgroup::Cgroup;
use super::stdio::OverflowFlags;
use crate::contract::verdict::KillOrigin;

pub(crate) struct Outcome {
    pub(crate) kill: KillOrigin,
    pub(crate) exit_code: u32,
    pub(crate) cpu_time_ms: u64,
    pub(crate) peak_memory_bytes: u64,
    pub(crate) wall_time_ms: u64,
}

const POLL_INTERVAL: Duration = Duration::from_millis(2);

const CPU_POLL_INTERVAL: Duration = Duration::from_millis(10);

const CPU_READ_FAILURE_LIMIT: u32 = 5;

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
            unsafe { libc::close(pidfd) };
            result
        }
        Err(e) => match e.raw_os_error() {
            Some(libc::ENOSYS) | Some(libc::EINVAL) => {
                monitor_polling(pid, wall_limit, overflow, cgroup, cpu_limit_ms)
            }
            _ => Err(e),
        },
    }
}

fn pidfd_open(pid: libc::pid_t) -> io::Result<libc::c_int> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd as libc::c_int)
    }
}

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

    loop {
        let rc = unsafe { libc::wait4(pid, &mut status, libc::WNOHANG, &mut rusage) };
        if rc == pid {
            break;
        }
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
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
        128 + libc::SIGKILL as u32
    }
}

fn rusage_cpu_ms(rusage: &libc::rusage) -> u64 {
    let secs = rusage.ru_utime.tv_sec + rusage.ru_stime.tv_sec;
    let usecs = rusage.ru_utime.tv_usec + rusage.ru_stime.tv_usec;
    (secs as u64 * 1000) + (usecs as u64 / 1000)
}

fn rusage_peak_bytes(rusage: &libc::rusage) -> u64 {
    rusage.ru_maxrss as u64 * 1024
}
