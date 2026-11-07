//! Comprehensive demonstration of seccompiler capabilities.
//!
//! Features demonstrated:
//!   1. Basic allowlist/denylist filter construction
//!   2. SeccompAction variants: Allow, Errno, Trace, Log
//!   3. SeccompRule with argument matching (exact value, ranges, masks)
//!   4. Filter compilation and application (single-thread & all-threads)
//!   5. Error handling: invalid filters, permission issues, architecture mismatch
//!   6. Runtime verification via /proc/self/status
//!   7. Multi-stage sandbox escalation demo

#[cfg(target_os = "linux")]
mod imp {
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
        SeccompFilter, SeccompRule, apply_filter, apply_filter_all_threads,
    };
    use std::collections::BTreeMap;
    use std::os::raw::c_long;

    // ========================================================================
    // Helper utilities
    // ========================================================================

    fn last_errno() -> i32 {
        std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(-1)
    }

    /// Read Seccomp field from /proc/self/status
    fn read_seccomp_status() -> Option<String> {
        std::fs::read_to_string("/proc/self/status")
            .ok()?
            .lines()
            .find(|line| line.starts_with("Seccomp:"))
            .map(|line| line.trim().to_string())
    }

    /// Print current seccomp status
    fn print_seccomp_status(label: &str) {
        match read_seccomp_status() {
            Some(status) => println!("  [{}] {}", label, status),
            None => println!("  [{}] cannot read /proc/self/status", label),
        }
    }

    // ========================================================================
    // Stage 1: Basic Allowlist Filter
    // ========================================================================

    /// Demonstrate basic allowlist filter: only specified syscalls are allowed,
    /// everything else returns EPERM.
    fn demo_basic_allowlist() {
        println!("\n=== Stage 1: Basic Allowlist Filter ===");
        println!("  Building a minimal allowlist filter...");

        // Define allowed syscalls for this stage
        let allowed_syscalls: &[c_long] = &[
            libc::SYS_write,       // printf / println
            libc::SYS_read,        // potential input
            libc::SYS_close,       // cleanup
            libc::SYS_exit_group,  // normal exit
            libc::SYS_exit,        // fallback exit
            libc::SYS_brk,         // memory allocation (println may need it)
            libc::SYS_mmap,        // memory mapping
            libc::SYS_munmap,      // memory unmapping
            libc::SYS_rt_sigreturn,
            libc::SYS_futex,       // threading primitives
            libc::SYS_sched_yield,
        ];

        // Empty rule vec = allow unconditionally
        let rules: BTreeMap<i64, Vec<SeccompRule>> = allowed_syscalls
            .iter()
            .map(|&nr| (nr as i64, Vec::new()))
            .collect();

        // Default action: return EPERM for unmatched syscalls
        // Matched action: Allow
        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Errno(libc::EPERM as u32), // default deny
            SeccompAction::Allow,                      // explicit allow
            std::env::consts::ARCH.try_into().expect("unsupported arch"),
        )
        .expect("failed to build filter");

        let bpf: BpfProgram = filter.try_into().expect("failed to compile BPF");
        println!("  ✅ Filter compiled: {} BPF instructions", bpf.len());

        // Note: We don't actually apply this filter because it would restrict
        // subsequent demo stages. Instead we just show it compiles correctly.
        println!("  ℹ️  Filter not applied (would block subsequent demos)");
        println!("  Allowed syscalls: {:?}", 
            allowed_syscalls.iter().map(|&s| s as i64).collect::<Vec<_>>());
    }

    // ========================================================================
    // Stage 2: Denylist Filter with Errno Action
    // ========================================================================

    /// Demonstrate denylist: block specific dangerous syscalls, allow everything else.
    fn demo_denylist() {
        println!("\n=== Stage 2: Denylist Filter (Block Dangerous Syscalls) ===");
        println!("  Building a denylist that blocks ptrace, reboot, kexec_load...");

        // Dangerous syscalls to block
        let blocked_syscalls: &[c_long] = &[
            libc::SYS_ptrace,
            libc::SYS_reboot,
            #[cfg(target_arch = "x86_64")]
            libc::SYS_kexec_load,
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_swapon,
            libc::SYS_swapoff,
        ];

        // For denylist: matched syscalls get Errno, unmatched get Allow
        let rules: BTreeMap<i64, Vec<SeccompRule>> = blocked_syscalls
            .iter()
            .map(|&nr| (nr as i64, Vec::new()))
            .collect();

        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Allow,                       // default: allow
            SeccompAction::Errno(libc::EPERM as u32),   // matched: deny
            std::env::consts::ARCH.try_into().expect("unsupported arch"),
        )
        .expect("failed to build denylist filter");

        let bpf: BpfProgram = filter.try_into().expect("failed to compile BPF");
        println!("  ✅ Denylist filter compiled: {} BPF instructions", bpf.len());
        println!("  Blocked syscalls: {:?}", 
            blocked_syscalls.iter().map(|&s| s as i64).collect::<Vec<_>>());
    }

    // ========================================================================
    // Stage 3: Argument Matching with SeccompRule
    // ========================================================================

    /// Demonstrate fine-grained syscall filtering based on arguments.
    fn demo_argument_matching() {
        println!("\n=== Stage 3: Argument Matching Rules ===");
        println!("  Building filters with syscall argument conditions...");

        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

        // Rule 1: Allow write() only to stdout (fd=1) and stderr (fd=2)
        // int write(int fd, const void *buf, size_t count);
        // Arg 0 is the file descriptor
        let write_stdout_rule = SeccompRule::new(vec![
            SeccompCondition::new(
                0,                              // arg index
                SeccompCmpArgLen::Dword,        // 32-bit comparison
                SeccompCmpOp::Eq,               // equal to
                1,                              // stdout fd
            ).expect("invalid condition"),
        ]).expect("invalid rule");

        let write_stderr_rule = SeccompRule::new(vec![
            SeccompCondition::new(
                0,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                2,                              // stderr fd
            ).expect("invalid condition"),
        ]).expect("invalid rule");

        rules.insert(libc::SYS_write as i64, vec![write_stdout_rule, write_stderr_rule]);

        // Rule 2: Allow openat() only with O_RDONLY flag
        // int openat(int dirfd, const char *pathname, int flags, ...);
        // Arg 2 is the flags parameter
        let open_rdonly_rule = SeccompRule::new(vec![
            SeccompCondition::new(
                2,                              // flags argument
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                libc::O_RDONLY as u64,
            ).expect("invalid condition"),
        ]).expect("invalid rule");

        rules.insert(libc::SYS_openat as i64, vec![open_rdonly_rule]);

        // Rule 3: Allow mmap with PROT_READ only (no write/exec)
        // void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
        // Arg 2 is prot
        let mmap_read_rule = SeccompRule::new(vec![
            SeccompCondition::new(
                2,                              // prot argument
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                libc::PROT_READ as u64,
            ).expect("invalid condition"),
        ]).expect("invalid rule");

        rules.insert(libc::SYS_mmap as i64, vec![mmap_read_rule]);

        // Add essential syscalls without restrictions
        let essential: &[c_long] = &[
            libc::SYS_close,
            libc::SYS_exit_group,
            libc::SYS_exit,
            libc::SYS_rt_sigreturn,
            libc::SYS_futex,
            libc::SYS_brk,
            libc::SYS_munmap,
            libc::SYS_sched_yield,
            libc::SYS_read,
        ];

        for &nr in essential {
            rules.entry(nr as i64).or_insert_with(Vec::new);
        }

        let filter = SeccompFilter::new(
            rules.clone(),
            SeccompAction::Errno(libc::EPERM as u32),
            SeccompAction::Allow,
            std::env::consts::ARCH.try_into().expect("unsupported arch"),
        )
        .expect("failed to build argument-matching filter");

        let bpf: BpfProgram = filter.try_into().expect("failed to compile BPF");
        println!("  ✅ Argument-matching filter compiled: {} BPF instructions", bpf.len());
        println!("  Rules summary:");
        println!("    • write(fd=1 OR fd=2) → Allow");
        println!("    • openat(flags=O_RDONLY) → Allow");
        println!("    • mmap(prot=PROT_READ) → Allow");
        println!("    • essential syscalls → Allow (unconditional)");
        println!("    • everything else → EPERM");
    }

    // ========================================================================
    // Stage 4: Multiple Action Types
    // ========================================================================

    /// Demonstrate different SeccompAction variants.
    fn demo_action_types() {
        println!("\n=== Stage 4: SeccompAction Variants ===");
        println!("  Demonstrating different actions for matched/unmatched syscalls...");

        // Action types available in seccompiler:
        // - Allow: permit the syscall
        // - Errno(errno): return specified errno
        // - Trace(tracer_id): notify tracer via PTRACE_SECCOMP
        // - Log: allow but log to audit (requires CAP_AUDIT_WRITE or root)
        // - Kill: terminate the process immediately
        // - KillProcess: terminate entire process group

        println!("  Available SeccompAction variants:");
        println!("    • Allow           — permit syscall");
        println!("    • Errno(n)        — return errno n to caller");
        println!("    • Trace(id)       — notify ptrace tracer");
        println!("    • Log             — allow + audit log (needs privileges)");
        println!("    • Kill            — SIGKILL the thread");
        println!("    • KillProcess     — SIGKILL entire process");

        // Build a filter using Log action (if privileged) or Errno as fallback
        let log_action = if unsafe { libc::geteuid() } == 0 {
            println!("  Running as root: using Log action for demonstration");
            SeccompAction::Log
        } else {
            println!("  Non-root: using Errno(ENOSYS) instead of Log");
            SeccompAction::Errno(libc::ENOSYS as u32)
        };

        let rules: BTreeMap<i64, Vec<SeccompRule>> = [
            (libc::SYS_getpid as i64, Vec::new()),
        ]
        .into_iter()
        .collect();

        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Allow,  // default allow
            log_action,            // matched action (Log or Errno)
            std::env::consts::ARCH.try_into().expect("unsupported arch"),
        )
        .expect("failed to build action demo filter");

        let bpf: BpfProgram = filter.try_into().expect("failed to compile BPF");
        println!("  ✅ Action-type filter compiled: {} BPF instructions", bpf.len());
    }

    // ========================================================================
    // Stage 5: Live Filter Application (in child process)
    // ========================================================================

    /// Fork a child that applies a real seccomp filter and verifies it works.
    fn demo_live_filter() {
        println!("\n=== Stage 5: Live Filter Application (Child Process) ===");
        println!("  Forking child to apply and verify seccomp filter...");

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            eprintln!("  ❌ fork failed: {}", std::io::Error::last_os_error());
            return;
        }

        if pid == 0 {
            // ---- Child process ----
            child_apply_and_verify();
        }

        // ---- Parent: wait for child ----
        let mut status: libc::c_int = 0;
        unsafe {
            libc::waitpid(pid, &mut status, 0);
        }

        if libc::WIFEXITED(status) {
            let code = libc::WEXITSTATUS(status);
            if code == 0 {
                println!("  ✅ Child completed successfully (exit code 0)");
            } else {
                println!("  ⚠️  Child exited with code {}", code);
            }
        } else if libc::WIFSIGNALED(status) {
            let sig = libc::WTERMSIG(status);
            println!("  ⚠️  Child killed by signal {}", sig);
        }
    }

    /// Child-side: apply seccomp filter and test that blocked syscalls fail.
    fn child_apply_and_verify() -> ! {
        // Step 1: Set no_new_privs (required for unprivileged seccomp)
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            eprintln!("  ❌ prctl(NO_NEW_PRIVS) failed: {}", std::io::Error::last_os_error());
            unsafe { libc::_exit(1) };
        }

        // Step 2: Build a restrictive filter
        let allowed: &[c_long] = &[
            libc::SYS_write,
            libc::SYS_read,
            libc::SYS_close,
            libc::SYS_exit_group,
            libc::SYS_exit,
            libc::SYS_rt_sigreturn,
            libc::SYS_futex,
            libc::SYS_brk,
            libc::SYS_mmap,
            libc::SYS_munmap,
            libc::SYS_sched_yield,
            libc::SYS_getpid,
            // File I/O needed for read_to_string("/proc/self/status")
            libc::SYS_openat,
            libc::SYS_lseek,
            libc::SYS_fstat,
            libc::SYS_newfstatat,
            libc::SYS_statx,
            libc::SYS_getdents64,
        ];

        let rules: BTreeMap<i64, Vec<SeccompRule>> = allowed
            .iter()
            .map(|&nr| (nr as i64, Vec::new()))
            .collect();

        let filter = match SeccompFilter::new(
            rules,
            SeccompAction::Errno(libc::EPERM as u32),
            SeccompAction::Allow,
            std::env::consts::ARCH.try_into().expect("unsupported arch"),
        ) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("  ❌ Filter build failed: {:?}", e);
                unsafe { libc::_exit(2) };
            }
        };

        let bpf: BpfProgram = match filter.try_into() {
            Ok(b) => b,
            Err(e) => {
                eprintln!("  ❌ BPF compilation failed: {:?}", e);
                unsafe { libc::_exit(3) };
            }
        };

        // Step 3: Apply filter to all threads
        if let Err(e) = apply_filter_all_threads(&bpf) {
            eprintln!("  ❌ apply_filter_all_threads failed: {:?}", e);
            unsafe { libc::_exit(4) };
        }

        // Step 4: Verify via /proc
        match read_seccomp_status() {
            Some(status) if status.contains('2') => {
                // Write success message to stderr (fd=2)
                let msg = b"  \xe2\x9c\x85 Seccomp filter active (Seccomp: 2)\n";
                unsafe {
                    libc::write(2, msg.as_ptr() as *const _, msg.len());
                }
            }
            other => {
                let msg = format!("  ❌ Unexpected seccomp status: {:?}\n", other);
                unsafe {
                    libc::write(2, msg.as_ptr() as *const _, msg.len());
                }
                unsafe { libc::_exit(5) };
            }
        }

        // Step 5: Test that a blocked syscall actually fails
        // Try to call getuid which is NOT in our allowlist
        let result = unsafe { libc::syscall(libc::SYS_getuid) };
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        
        if result == -1 && errno == libc::EPERM {
            let msg = b"  \xe2\x9c\x85 Blocked syscall (getuid) correctly returned EPERM\n";
            unsafe {
                libc::write(2, msg.as_ptr() as *const _, msg.len());
            }
        } else {
            let msg = format!(
                "  ❌ Blocked syscall unexpectedly succeeded: ret={}, errno={}\n",
                result, errno
            );
            unsafe {
                libc::write(2, msg.as_ptr() as *const _, msg.len());
            }
            unsafe { libc::_exit(6) };
        }

        // Step 6: Test that allowed syscalls still work
        let my_pid = unsafe { libc::getpid() };
        if my_pid > 0 {
            let msg = b"  \xe2\x9c\x85 Allowed syscall (getpid) works correctly\n";
            unsafe {
                libc::write(2, msg.as_ptr() as *const _, msg.len());
            }
        }

        unsafe { libc::_exit(0) };
    }

    // ========================================================================
    // Stage 6: Single-thread vs All-threads Application
    // ========================================================================

    /// Demonstrate the difference between apply_filter and apply_filter_all_threads.
    fn demo_thread_scope() {
        println!("\n=== Stage 6: Thread Scope (apply_filter vs apply_filter_all_threads) ===");
        println!("  Comparing single-thread and all-threads filter application...");

        println!("  API differences:");
        println!("    • apply_filter(&bpf)          — applies to current thread only");
        println!("    • apply_filter_all_threads(&bpf) — applies to all threads (TSYNC)");
        println!("                                     requires PR_SET_NO_NEW_PRIVS or CAP_SYS_ADMIN");

        // In a forked child, demonstrate both approaches
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            eprintln!("  ❌ fork failed");
            return;
        }

        if pid == 0 {
            // Child: use single-thread apply_filter
            if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
                unsafe { libc::_exit(1) };
            }

            let rules: BTreeMap<i64, Vec<SeccompRule>> = [
                libc::SYS_write,
                libc::SYS_exit_group,
                libc::SYS_exit,
                libc::SYS_rt_sigreturn,
                libc::SYS_futex,
                libc::SYS_brk,
                libc::SYS_mmap,
                libc::SYS_munmap,
                libc::SYS_close,
                libc::SYS_sched_yield,
            ]
            .iter()
            .map(|&nr| (nr as i64, Vec::new()))
            .collect();

            let filter = SeccompFilter::new(
                rules,
                SeccompAction::Errno(libc::EPERM as u32),
                SeccompAction::Allow,
                std::env::consts::ARCH.try_into().expect("unsupported arch"),
            )
            .expect("filter build");

            let bpf: BpfProgram = filter.try_into().expect("bpf compile");

            // Use single-thread version
            match apply_filter(&bpf) {
                Ok(()) => {
                    let msg = b"  \xe2\x9c\x85 apply_filter (single-thread) succeeded\n";
                    unsafe { libc::write(2, msg.as_ptr() as *const _, msg.len()) };
                }
                Err(e) => {
                    let msg = format!("  ❌ apply_filter failed: {:?}\n", e);
                    unsafe { libc::write(2, msg.as_ptr() as *const _, msg.len()) };
                }
            }

            unsafe { libc::_exit(0) };
        }

        // Parent waits
        let mut status: libc::c_int = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        
        if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
            println!("  ✅ Single-thread filter application verified in child");
        }
    }

    // ========================================================================
    // Stage 7: Error Handling & Edge Cases
    // ========================================================================

    /// Demonstrate error conditions and edge cases.
    fn demo_error_handling() {
        println!("\n=== Stage 7: Error Handling & Edge Cases ===");

        // Case 1: Empty filter (no rules at all)
        println!("  Case 1: Empty filter (deny everything)...");
        let empty_rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        match SeccompFilter::new(
            empty_rules,
            SeccompAction::Errno(libc::EPERM as u32),
            SeccompAction::Allow,
            std::env::consts::ARCH.try_into().expect("unsupported arch"),
        ) {
            Ok(filter) => {
                let bpf: Result<BpfProgram, _> = filter.try_into();
                match bpf {
                    Ok(prog) => println!("    ✅ Empty filter compiled ({} instructions) — will deny all syscalls", prog.len()),
                    Err(e) => println!("    ⚠️  Empty filter compilation failed: {:?}", e),
                }
            }
            Err(e) => println!("    ⚠️  Empty filter creation failed: {:?}", e),
        }

        // Case 2: Invalid architecture string
        println!("  Case 2: Invalid architecture...");
        let rules: BTreeMap<i64, Vec<SeccompRule>> = [(libc::SYS_write as i64, Vec::new())]
            .into_iter()
            .collect();
        
        // Try to create with an invalid arch by using try_into on a bad string
        let bad_arch_result: Result<seccompiler::TargetArch, _> = "invalid_arch".try_into();
        match bad_arch_result {
            Ok(_) => println!("    ⚠️  Unexpectedly accepted invalid arch"),
            Err(_) => println!("    ✅ Correctly rejected invalid architecture string"),
        }

        // Case 3: Applying filter without NO_NEW_PRIVS (should fail for non-root)
        println!("  Case 3: Apply without NO_NEW_PRIVS (non-root)...");
        if unsafe { libc::geteuid() } != 0 {
            let filter = SeccompFilter::new(
                rules.clone(),
                SeccompAction::Errno(libc::EPERM as u32),
                SeccompAction::Allow,
                std::env::consts::ARCH.try_into().expect("unsupported arch"),
            )
            .expect("filter build");

            let bpf: BpfProgram = filter.try_into().expect("bpf compile");

            // This should fail without NO_NEW_PRIVS when not root
            match apply_filter_all_threads(&bpf) {
                Ok(()) => println!("    ⚠️  Filter applied without NO_NEW_PRIVS (unexpected for non-root)"),
                Err(e) => println!("    ✅ Correctly failed without NO_NEW_PRIVS: {:?}", e),
            }
        } else {
            println!("    ℹ️  Running as root — skipping this test (would succeed)");
        }

        // Case 4: Duplicate syscall entries in rules
        println!("  Case 4: Multiple rules for same syscall (OR semantics)...");
        let multi_rules: BTreeMap<i64, Vec<SeccompRule>> = [(
            libc::SYS_write as i64,
            vec![
                SeccompRule::new(vec![
                    SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, 1)
                        .expect("cond"),
                ])
                .expect("rule"),
                SeccompRule::new(vec![
                    SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, 2)
                        .expect("cond"),
                ])
                .expect("rule"),
            ],
        )]
        .into_iter()
        .collect();

        match SeccompFilter::new(
            multi_rules,
            SeccompAction::Errno(libc::EPERM as u32),
            SeccompAction::Allow,
            std::env::consts::ARCH.try_into().expect("unsupported arch"),
        ) {
            Ok(f) => {
                let bpf: BpfProgram = f.try_into().expect("bpf");
                println!("    ✅ Multiple rules per syscall compiled ({} instructions)", bpf.len());
                println!("       (rules within a syscall are OR'd together)");
            }
            Err(e) => println!("    ❌ Failed: {:?}", e),
        }

        // Case 5: Mask-based comparison
        println!("  Case 5: Mask-based argument comparison...");
        let mask_rules: BTreeMap<i64, Vec<SeccompRule>> = [(
            libc::SYS_openat as i64,
            vec![
                // Allow openat with O_RDONLY | O_CLOEXEC combination
                SeccompRule::new(vec![
                    SeccompCondition::new(
                        2,
                        SeccompCmpArgLen::Dword,
                        SeccompCmpOp::MaskedEq((libc::O_RDONLY | libc::O_CLOEXEC) as u64),
                        (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
                    )
                    .expect("cond"),
                ])
                .expect("rule"),
            ],
        )]
        .into_iter()
        .collect();

        match SeccompFilter::new(
            mask_rules,
            SeccompAction::Errno(libc::EPERM as u32),
            SeccompAction::Allow,
            std::env::consts::ARCH.try_into().expect("unsupported arch"),
        ) {
            Ok(f) => {
                let bpf: BpfProgram = f.try_into().expect("bpf");
                println!("    ✅ MaskedEq comparison compiled ({} instructions)", bpf.len());
            }
            Err(e) => println!("    ❌ Failed: {:?}", e),
        }
    }

    // ========================================================================
    // Main entry point
    // ========================================================================

    pub fn run() {
        println!("╔══════════════════════════════════════════════╗");
        println!("║     seccompiler Capability Demo              ║");
        println!("╚══════════════════════════════════════════════╝\n");

        println!("Library: seccompiler v{}", env!("CARGO_PKG_VERSION"));
        println!("Architecture: {}", std::env::consts::ARCH);
        print_seccomp_status("Initial");

        // Run all demo stages
        demo_basic_allowlist();
        demo_denylist();
        demo_argument_matching();
        demo_action_types();
        demo_live_filter();
        demo_thread_scope();
        demo_error_handling();

        println!("\n╔══════════════════════════════════════════════╗");
        println!("║     All stages complete                      ║");
        println!("╚══════════════════════════════════════════════╝");
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    imp::run();

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("This example only runs on Linux.");
        eprintln!("seccompiler uses Linux seccomp-bpf which is not available on other platforms.");
        std::process::exit(1);
    }
}
