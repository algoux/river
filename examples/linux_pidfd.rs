//! Demonstration of Linux pidfd capabilities using rustix + minimal libc fallback.
//!
//! Features demonstrated:
//!   1. clone3(CLONE_PIDFD) — create child with pidfd atomically (no TOCTOU)
//!      → raw syscall (not yet in rustix 0.38)
//!   2. pidfd_send_signal   — send signals via pidfd (rustix native)
//!   3. waitid(P_PIDFD)     — wait on pidfd via rustix's WaitId::PidFd
//!   4. pidfd_open          — obtain pidfd for an existing pid (rustix native)
//!   5. sandbox handshake   — CLOEXEC status pipe: 4-byte errno on completion,
//!      EOF = child died during setup; the parent then re-checks /proc for
//!      Seccomp: 2 instead of trusting the child's own report
//!
//! Only clone3 is a raw syscall; seccomp filters are built by seccompiler.

#[cfg(target_os = "linux")]
mod imp {
    use rustix::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
    use rustix::pipe::{PipeFlags, pipe_with};
    use rustix::process::{
        Pid, PidfdFlags, Signal, WaitId, WaitidOptions, pidfd_open, pidfd_send_signal, waitid,
    };
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompFilter, SeccompRule, apply_filter_all_threads,
    };
    use std::collections::BTreeMap;
    use std::os::raw::c_int;

    // ========================================================================
    // Raw syscall wrapper for clone3 (not yet in rustix 0.38)
    // ========================================================================

    /// Kernel `struct clone_args` layout for clone3.
    #[repr(C)]
    #[derive(Default)]
    struct CloneArgs {
        flags: u64,
        pidfd: u64,       // output: pidfd when CLONE_PIDFD is set
        child_tid: u64,
        parent_tid: u64,
        exit_signal: u64,
        stack: u64,
        stack_size: u64,
        tls: u64,
        set_tid: u64,
        set_tid_size: u64,
        cgroup: u64,
    }

    const CLONE_PIDFD: u64 = 0x0000_1000;
    const SYS_CLONE3: libc::c_long = 435; // x86_64 syscall number

    /// Invoke `clone3(args, size)` — returns child pid in parent, 0 in child.
    unsafe fn clone3(args: &CloneArgs) -> i64 {
        unsafe {
            libc::syscall(
                SYS_CLONE3,
                args as *const CloneArgs,
                std::mem::size_of::<CloneArgs>(),
            )
        }
    }

    // ========================================================================
    // Demo stages
    // ========================================================================

    /// Stage 1: clone3 + CLONE_PIDFD — atomically obtain a pidfd at fork time,
    /// then use a CLOEXEC status pipe as the sandbox-ready handshake.
    ///
    /// Child: SIG_IGN → no_new_privs → rlimits → seccomp, then write a 4-byte
    /// errno (0 = armed) and close. EOF instead of data means the child died
    /// during setup. The parent sends nothing to the child before that ack, so
    /// the race the old 100ms sleep papered over cannot happen.
    ///
    /// Falls back to fork + pidfd_open if clone3(CLONE_PIDFD) is unavailable;
    /// the fork child runs the exact same setup + handshake.
    ///
    /// Returns (pidfd, child_pid). The child sleeps 3 seconds then exits with code 42.
    fn demo_clone3_pidfd() -> (OwnedFd, Pid) {
        println!("=== Stage 1: clone3(CLONE_PIDFD) + sandbox handshake ===");
        println!("  Attempting atomic pidfd acquisition via clone3...");

        // Created before spawn so the child inherits it; CLOEXEC keeps it out
        // of any payload the child might exec later.
        let (status_r, status_w) = pipe_with(PipeFlags::CLOEXEC).expect("pipe2(O_CLOEXEC)");

        // Output slot: with CLONE_PIDFD the kernel writes a 4-byte pidfd here,
        // so args.pidfd must point at writable memory. Leaving it at the
        // Default 0 makes clone3 fail with EFAULT, which is *not* evidence
        // that the kernel lacks clone3 support.
        let mut pidfd_raw: c_int = -1;
        let args = CloneArgs {
            flags: CLONE_PIDFD,
            pidfd: std::ptr::addr_of_mut!(pidfd_raw) as u64,
            exit_signal: libc::SIGCHLD as u64,
            ..Default::default()
        };

        let forced = std::env::var_os("RIVER_FORCE_FALLBACK").is_some();
        let pid_raw = if forced { -1 } else { unsafe { clone3(&args) } };

        if pid_raw == 0 {
            // ---- Child (clone3 path) ----
            drop(status_r);
            child_main(status_w);
        }

        if pid_raw > 0 {
            // ---- Parent (clone3 succeeded) ----
            assert!(
                pidfd_raw >= 0,
                "clone3 returned a child pid but wrote no pidfd into the output slot"
            );
            let child_pid = Pid::from_raw(pid_raw as i32).expect("invalid child pid from clone3");
            // SAFETY: the kernel just installed a fresh pidfd owned by this process
            let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd_raw) };

            drop(status_w); // only the child may hold the write end from here on
            await_sandbox_ready(&status_r, pid_raw as i32);

            println!(
                "  ✅ clone3(CLONE_PIDFD) succeeded: child pid={:?}, pidfd={}",
                child_pid,
                pidfd.as_raw_fd()
            );
            return (pidfd, child_pid);
        }

        // ---- clone3 unavailable: fall back to fork + pidfd_open ----
        if forced {
            println!("  ⚠️  clone3 skipped on purpose (RIVER_FORCE_FALLBACK is set)");
        } else {
            let err = std::io::Error::last_os_error();
            println!(
                "  ⚠️  clone3(CLONE_PIDFD) failed: {} (errno {})",
                err,
                err.raw_os_error().unwrap_or(0)
            );
        }
        println!("  Falling back to fork() + pidfd_open()...");

        let pid_raw = unsafe { libc::fork() };
        if pid_raw < 0 {
            panic!("fork failed: {}", std::io::Error::last_os_error());
        }
        if pid_raw == 0 {
            // ---- Child (fork path) ----
            drop(status_r);
            child_main(status_w);
        }

        let child_pid = Pid::from_raw(pid_raw).expect("invalid child pid from fork");
        let pidfd =
            pidfd_open(child_pid, PidfdFlags::empty()).expect("pidfd_open fallback failed");

        drop(status_w);
        await_sandbox_ready(&status_r, pid_raw);

        println!(
            "  ✅ fork + pidfd_open succeeded: child pid={:?}, pidfd={} (same handshake)",
            child_pid,
            pidfd.as_raw_fd()
        );

        (pidfd, child_pid)
    }

    /// Child side: arm the sandbox, report the outcome, then do "work".
    /// Diverges — the caller must never resume the parent path.
    fn child_main(status_w: OwnedFd) -> ! {
        let code = match apply_sandbox() {
            Ok(()) => 0,
            Err(errno) => errno,
        };

        let reported = rustix::io::write(&status_w, &code.to_ne_bytes()).is_ok();
        drop(status_w);

        if !reported {
            // A vanished ack must look like death (EOF), never like a child
            // that is still starting up.
            unsafe { libc::_exit(127) };
        }

        // "Work": stay alive long enough for Stage 2 to signal us, then exit 42.
        unsafe {
            libc::sleep(3);
            libc::_exit(42);
        }
    }

    /// Everything the parent cannot do on the child's behalf, in the order that
    /// keeps each step reachable. Returns the errno of the first failing step.
    fn apply_sandbox() -> Result<(), i32> {
        // Ignored from birth: Stage 2's SIGUSR1 can no longer race the setup.
        if unsafe { libc::signal(libc::SIGUSR1, libc::SIG_IGN) } == libc::SIG_ERR {
            return Err(last_errno());
        }

        // Prerequisite for loading a seccomp filter without CAP_SYS_ADMIN.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(last_errno());
        }

        // Anything else the parent cannot lower for us belongs here.
        let no_core = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core) } != 0 {
            return Err(last_errno());
        }

        // Seccomp last: from here on only the allowlist below works.
        let bpf = build_seccomp_filter()?;
        apply_filter_all_threads(&bpf).map_err(|_| libc::EPERM)?;
        Ok(())
    }

    /// Deny-by-default filter. An empty rule vec means "allow unconditionally";
    /// every entry is a syscall this child still needs after the filter lands,
    /// including the ones the handshake itself uses (write/close/exit_group).
    fn build_seccomp_filter() -> Result<BpfProgram, i32> {
        let allow: &[libc::c_long] = &[
            libc::SYS_write,           // readiness ack
            libc::SYS_close,           // dropping the status pipe
            libc::SYS_exit_group,      // _exit(42) / _exit(127)
            libc::SYS_exit,
            libc::SYS_clock_nanosleep, // glibc sleep()
            libc::SYS_nanosleep,
            libc::SYS_restart_syscall,
            libc::SYS_rt_sigreturn,    // return from a signal handler
            libc::SYS_futex,
            libc::SYS_sched_yield,
        ];
        let rules: BTreeMap<i64, Vec<SeccompRule>> =
            allow.iter().map(|&nr| (nr as i64, Vec::new())).collect();

        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Errno(libc::EPERM as u32),
            SeccompAction::Allow,
            std::env::consts::ARCH
                .try_into()
                .map_err(|_| libc::EINVAL)?,
        )
        .map_err(|_| libc::EINVAL)?;
        filter.try_into().map_err(|_| libc::EINVAL)
    }

    /// Parent side of the handshake: block for the status, then verify the
    /// sandbox from the kernel's point of view instead of trusting the child.
    fn await_sandbox_ready(status_r: &OwnedFd, pid: i32) {
        let mut buf = [0u8; 4];
        let n = loop {
            match rustix::io::read(status_r, &mut buf) {
                Ok(n) => break n,
                Err(rustix::io::Errno::INTR) => continue,
                Err(e) => panic!("reading sandbox status: {e}"),
            }
        };

        match n {
            0 => {
                eprintln!("  ❌ child died during sandbox setup (EOF on status pipe)");
                std::process::exit(1);
            }
            4 => {
                let errno = i32::from_ne_bytes(buf);
                if errno != 0 {
                    eprintln!(
                        "  ❌ sandbox setup failed: {}",
                        std::io::Error::from_raw_os_error(errno)
                    );
                    std::process::exit(1);
                }
                println!("  ✅ child reported sandbox armed (errno=0)");
            }
            _ => panic!("short read from status pipe: {n} of 4 bytes"),
        }

        match std::fs::read_to_string(format!("/proc/{pid}/status")) {
            Ok(status) => {
                let field = |name: &str| {
                    status
                        .lines()
                        .find(|line| line.starts_with(name))
                        .map(|line| line.trim().to_string())
                        .unwrap_or_else(|| format!("{name} <missing>"))
                };
                println!(
                    "  • kernel view: {} | {}",
                    field("Seccomp:"),
                    field("NoNewPrivs:")
                );
                if !field("Seccomp:").contains('2') {
                    eprintln!("  ❌ /proc does not report Seccomp: 2 — filter is not active");
                    std::process::exit(1);
                }
            }
            Err(e) => eprintln!("  ⚠️  cannot verify /proc/{pid}/status: {e}"),
        }
    }

    fn last_errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
    }

    /// Stage 2: pidfd_send_signal via rustix — send SIGUSR1 to the child.
    fn demo_pidfd_send_signal(pidfd: &impl AsFd, child_pid: Pid) {
        println!("\n=== Stage 2: pidfd_send_signal (rustix) ===");

        match pidfd_send_signal(pidfd, Signal::Usr1) {
            Ok(()) => println!(
                "  ✅ Sent SIGUSR1 to pid {:?} via pidfd (safe, no PID reuse risk)",
                child_pid
            ),
            Err(e) => eprintln!("  ❌ pidfd_send_signal(SIGUSR1) failed: {:?}", e),
        }

        // Brief pause so child is still alive for the next stage
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    /// Stage 3: waitid via rustix with WaitId::PidFd — reap through pidfd.
    fn demo_waitid_pidfd(pidfd: &impl AsFd, child_pid: Pid) {
        println!("\n=== Stage 3: waitid(WaitId::PidFd) via rustix ===");

        // Non-blocking poll first to check if child is still running
        let already_reaped = match waitid(
            WaitId::PidFd(pidfd.as_fd()),
            WaitidOptions::NOHANG | WaitidOptions::EXITED,
        ) {
            Ok(Some(status)) => {
                println!("  Non-blocking poll: child already exited");
                print_waitid_status(&status);
                true // already reaped by this call
            }
            Ok(None) => {
                println!("  Non-blocking poll: child still running");
                false
            }
            Err(e) => {
                eprintln!("  Non-blocking waitid error: {:?}", e);
                false
            }
        };

        if already_reaped {
            println!("  ℹ️  Child was already reaped by non-blocking waitid, skipping blocking wait");
            return;
        }

        // Blocking wait for exit
        println!("  Blocking wait for child to exit...");
        match waitid(
            WaitId::PidFd(pidfd.as_fd()),
            WaitidOptions::EXITED,
        ) {
            Ok(Some(status)) => {
                println!("  ✅ waitid(P_PIDFD) reaped pid {:?}:", child_pid);
                print_waitid_status(&status);
            }
            Ok(None) => {
                println!("  ⚠️  waitid returned None (unexpected for blocking call)");
            }
            Err(e) => {
                eprintln!("  ❌ waitid(P_PIDFD) failed: {:?}", e);
            }
        }
    }

    fn print_waitid_status(status: &rustix::process::WaitidStatus) {
        if status.exited() {
            println!(
                "     → exited normally with code {}",
                status.exit_status().unwrap_or(0)
            );
        } else if status.killed() {
            println!(
                "     → killed by signal {}",
                status.terminating_signal().unwrap_or(0)
            );
        } else if status.dumped() {
            println!(
                "     → dumped (core) by signal {}",
                status.terminating_signal().unwrap_or(0)
            );
        } else if status.stopped() {
            println!(
                "     → stopped by signal {}",
                status.stopping_signal().unwrap_or(0)
            );
        } else if status.continued() {
            println!("     → continued");
        } else {
            println!("     → unknown state");
        }
    }

    /// Bonus: pidfd_open (rustix) on a separately-forked child for comparison.
    fn demo_pidfd_open() {
        println!("\n=== Bonus: pidfd_open (rustix) ===");
        println!("  Forking a child and obtaining its pidfd post-hoc...");

        let pid_raw = unsafe { libc::fork() };
        if pid_raw < 0 {
            panic!("fork failed: {}", std::io::Error::last_os_error());
        }
        if pid_raw == 0 {
            // Child: sleep briefly then exit
            unsafe {
                libc::sleep(2);
                libc::_exit(99);
            }
        }

        let forked_pid = Pid::from_raw(pid_raw as i32).unwrap();
        println!("  Forked child pid={:?}", forked_pid);

        // Obtain pidfd via rustix
        match pidfd_open(forked_pid, PidfdFlags::empty()) {
            Ok(pidfd) => {
                println!(
                    "  ✅ pidfd_open returned fd={} for pid {:?}",
                    pidfd.as_raw_fd(),
                    forked_pid
                );

                // Send SIGTERM via pidfd
                match pidfd_send_signal(&pidfd, Signal::Term) {
                    Ok(()) => println!("  ✅ pidfd_send_signal(SIGTERM) succeeded"),
                    Err(e) => eprintln!("  ❌ pidfd_send_signal failed: {:?}", e),
                }

                // Reap via waitid(PidFd)
                match waitid(
                    WaitId::PidFd(pidfd.as_fd()),
                    WaitidOptions::EXITED,
                ) {
                    Ok(Some(status)) => {
                        print!("  ✅ Reaped via waitid(PidFd): ");
                        if status.killed() {
                            println!(
                                "killed by signal {}",
                                status.terminating_signal().unwrap_or(0)
                            );
                        } else if status.exited() {
                            println!(
                                "exited with code {}",
                                status.exit_status().unwrap_or(0)
                            );
                        } else {
                            println!("unknown state");
                        }
                    }
                    Ok(None) => println!("  ⚠️  waitid returned None"),
                    Err(e) => eprintln!("  ❌ waitid failed: {:?}", e),
                }
            }
            Err(e) => {
                eprintln!("  ❌ pidfd_open failed: {:?}", e);
                // Fallback reap
                unsafe {
                    libc::waitpid(pid_raw, std::ptr::null_mut(), 0);
                }
            }
        }
    }

    pub fn run() {
        println!("╔══════════════════════════════════════════════╗");
        println!("║     Linux pidfd Capability Demo              ║");
        println!("╚══════════════════════════════════════════════╝\n");
        println!("Kernel requirements:");
        println!("  • pidfd_open:           >= 5.3");
        println!("  • pidfd_send_signal:    >= 5.1");
        println!("  • clone3 + CLONE_PIDFD: >= 5.5");
        println!("  • waitid(P_PIDFD):      >= 5.4\n");
        println!("API coverage:");
        println!("  • rustix: pidfd_open, pidfd_send_signal, waitid(WaitId::PidFd)");
        println!("  • raw syscall: clone3 (not yet in rustix 0.38)");
        println!("  • seccompiler: seccomp filter (TSYNC) installed by the child\n");

        // Stage 1: clone3 + CLONE_PIDFD
        let (pidfd, child_pid) = demo_clone3_pidfd();

        // Stage 2: pidfd_send_signal
        demo_pidfd_send_signal(&pidfd, child_pid);

        // Stage 3: waitid(P_PIDFD) via rustix
        demo_waitid_pidfd(&pidfd, child_pid);

        // Bonus: pidfd_open comparison
        demo_pidfd_open();

        println!("\n=== All stages complete ===");
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    imp::run();

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("This example only runs on Linux.");
        eprintln!("pidfd is a Linux-specific feature (kernel >= 5.3).");
        std::process::exit(1);
    }
}
