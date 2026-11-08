//! seccomp-bpf allowlist (stage L8).
//!
//! The sandboxed program runs under a **default-deny** filter whose mismatch
//! action is `EPERM` (not `KILL`): ordinary programs keep running, denied
//! operations fail with a normal errno. The allowlist is compiled once per
//! judger process ([`filters`]) and applied by the child just before
//! `execve`; the compiled BPF programs are passed across the fork, so the
//! child itself never allocates.
//!
//! **`clone3` prefilter**: seccomp cannot dereference the `struct clone_args`
//! pointer `clone3` receives, so its `CLONE_NEW*` flags cannot be masked the
//! way `clone`'s are — and an unconditional allow lets
//! `clone3(CLONE_NEWUSER)` create a user namespace whose creator regains
//! `CAP_SYS_ADMIN` over it (verified live: `CapEff` all-ones inside the ns,
//! and the host's AppArmor userns restriction did not stop it). A tiny
//! second filter is therefore stacked **on top of** the allowlist that makes
//! `clone3` fail with `ENOSYS` unconditionally: glibc's `pthread_create`
//! falls back to `clone` on `ENOSYS` (but not on `EPERM`), so ordinary
//! threads keep working while the namespace-creation route closes. Programs
//! calling `clone3` directly (rare; container runtimes) get `ENOSYS`.
//!
//! What the allowlist closes on top of namespaces (the
//! "not isolated by namespaces" set):
//!
//! - `keyctl`/`add_key`/`request_key` — uid-scoped keyring persistence
//! - `AF_VSOCK` / any socket creation (`socket` denied; `socketpair` stays
//!   for local IPC)
//! - `io_uring_*` — bypasses socket address-family checks
//! - `flock` — shared-inode lock side channel on the read-only runtime trees
//! - `ptrace`, `process_vm_*`, `pidfd_*`, `kcmp`
//! - `mount*`, `pivot_root`, `chroot`, `unshare`, `setns`, `fsopen`,
//!   `open_tree`, `move_mount`, `mount_setattr` (defense in depth: no
//!   user-namespace creation either)
//! - `bpf`, `perf_event_open`, `userfaultfd`, `mknod*`, module loading,
//!   `reboot`, `kexec*`, `swapon/off`, `clock_settime`, `sethostname`
//!
//! Everything else — the syscalls CPython, the dynamic loader, shells and
//! ordinary compiled programs need — is allowed unconditionally.

use std::collections::BTreeMap;

/// Compiled filter for the current process's architecture.
pub(crate) type Program = seccompiler::BpfProgram;

/// The stacked filter set applied to every sandboxed program: the big
/// default-deny allowlist plus the `clone3`→`ENOSYS` prefilter and the
/// terminal-injection `ioctl` prefilter.
pub(crate) struct Filters {
    /// Default-deny allowlist (`EPERM` on mismatch).
    pub(crate) allowlist: Program,
    /// Forces `clone3` to `ENOSYS` (see the module docs).
    pub(crate) clone3_prefilter: Program,
    /// Denies the terminal-injection `ioctl` requests (`TIOCSTI`,
    /// `TIOCLINUX`) that the allowlist would otherwise pass.
    pub(crate) ioctl_prefilter: Program,
}

/// Compile the filter set once per process (the filters are immutable and
/// apply to the whole process tree, so one set is reused by every run).
pub(crate) fn filters() -> Result<&'static Filters, String> {
    static FILTERS: std::sync::OnceLock<Result<Filters, String>> = std::sync::OnceLock::new();
    FILTERS.get_or_init(build).as_ref().map_err(|e| e.clone())
}

#[cfg(target_arch = "x86_64")]
fn build() -> Result<Filters, String> {
    use seccompiler::{
        SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
        SeccompRule, TargetArch,
    };

    // SeccompRule requires at least one condition; a zero mask compares
    // `arg0 & 0 == 0`, i.e. "always true" — the unconditional allow rule.
    let always = SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::MaskedEq(0), 0)
        .map_err(|e| format!("seccomp condition: {e:?}"))?;
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for syscall in ALLOW {
        let rule =
            SeccompRule::new(vec![always.clone()]).map_err(|e| format!("seccomp rule: {e:?}"))?;
        rules.entry(*syscall).or_default().push(rule);
    }

    // `clone` is allowed only when **no** namespace-creation flag is set
    // (x86_64 passes the flags in arg0). Otherwise a program could do
    // `clone(CLONE_NEWUSER)` and get CAP_SYS_ADMIN inside a fresh user
    // namespace, re-opening kernel surface the allowlist deliberately
    // closed (`unshare` is denied outright, but clone was allowed
    // unconditionally — verified: the child landed in a distinct userns).
    //
    // `clone3` cannot be masked this way (seccomp cannot dereference the
    // `struct clone_args` pointer), so it is forced to `ENOSYS` by the
    // stacked prefilter instead — see the module docs. glibc >= 2.34 uses
    // clone3 for pthread_create but falls back to `clone` on ENOSYS, so
    // threads keep working.
    let namespace_flags = (libc::CLONE_NEWNS
        | libc::CLONE_NEWUSER
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWNET
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWUTS
        | libc::CLONE_NEWCGROUP) as u64;
    let no_new_namespace = SeccompCondition::new(
        0,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::MaskedEq(namespace_flags),
        0,
    )
    .map_err(|e| format!("seccomp clone condition: {e:?}"))?;
    let clone_rule = SeccompRule::new(vec![no_new_namespace])
        .map_err(|e| format!("seccomp clone rule: {e:?}"))?;
    rules.insert(libc::SYS_clone, vec![clone_rule]);

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        TargetArch::x86_64,
    )
    .map_err(|e| format!("seccomp filter: {e:?}"))?;
    let allowlist: Program = filter
        .try_into()
        .map_err(|e| format!("seccomp compile: {e:?}"))?;

    // The clone3 prefilter: `clone3` → ENOSYS, everything else allowed.
    // Stacked filters execute most-recent-first and a syscall only proceeds
    // when *every* filter allows it, so installing this after the allowlist
    // makes clone3 fail with ENOSYS no matter what the allowlist says.
    let mut deny_clone3: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    deny_clone3.insert(
        libc::SYS_clone3,
        vec![SeccompRule::new(vec![always]).map_err(|e| format!("seccomp rule: {e:?}"))?],
    );
    let pre = SeccompFilter::new(
        deny_clone3,
        // not in the map → allow (the allowlist still gets its say)
        SeccompAction::Allow,
        // matched (clone3) → ENOSYS: glibc pthread_create falls back to clone
        SeccompAction::Errno(libc::ENOSYS as u32),
        TargetArch::x86_64,
    )
    .map_err(|e| format!("seccomp prefilter: {e:?}"))?;
    let clone3_prefilter: Program = pre
        .try_into()
        .map_err(|e| format!("seccomp prefilter compile: {e:?}"))?;

    // The ioctl prefilter: `ioctl` is allowed (CPython's script mode, and
    // many runtimes, need it — without it `python3 <script>` fails with
    // EPERM), but the two *terminal-injection* requests are denied:
    //
    // - `TIOCSTI` pushes bytes into the terminal input queue of another
    //   process (the classic tty-injection primitive);
    // - `TIOCLINUX` can reprogram the console / selection buffer.
    //
    // The sandbox has no controlling terminal (`setsid` in the supervisor),
    // so neither is reachable today; denying them keeps the guarantee
    // independent of that. This mirrors Docker's default seccomp profile,
    // which also allows ioctl with a small denylist rather than blocking the
    // whole syscall.
    //
    // The request code is `ioctl`'s **arg1** (arg0 is the fd).
    let mut deny_tty_inject: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    let mut tty_rules = Vec::new();
    for request in [libc::TIOCSTI, libc::TIOCLINUX] {
        let cond = SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, request)
            .map_err(|e| format!("seccomp ioctl condition: {e:?}"))?;
        tty_rules
            .push(SeccompRule::new(vec![cond]).map_err(|e| format!("seccomp ioctl rule: {e:?}"))?);
    }
    deny_tty_inject.insert(libc::SYS_ioctl, tty_rules);
    let ioctl_pre = SeccompFilter::new(
        deny_tty_inject,
        // not matched (every other ioctl request) → allow
        SeccompAction::Allow,
        // matched (TIOCSTI / TIOCLINUX) → EPERM
        SeccompAction::Errno(libc::EPERM as u32),
        TargetArch::x86_64,
    )
    .map_err(|e| format!("seccomp ioctl prefilter: {e:?}"))?;
    let ioctl_prefilter: Program = ioctl_pre
        .try_into()
        .map_err(|e| format!("seccomp ioctl prefilter compile: {e:?}"))?;

    Ok(Filters {
        allowlist,
        clone3_prefilter,
        ioctl_prefilter,
    })
}

#[cfg(not(target_arch = "x86_64"))]
fn build() -> Result<Filters, String> {
    // Fail closed: an unimplemented allowlist must not silently mean "no
    // seccomp". The backend rejects construction instead.
    Err("river: the seccomp allowlist is implemented for x86_64 only".to_string())
}

/// Apply the compiled filter set to the calling process (and its future
/// children). The prefilters are installed *after* the allowlist so they run
/// first (filters execute most-recent-first; a syscall only proceeds when
/// every filter allows it).
///
/// Returns 0 on success, -1 on failure (errno set) — called between fork and
/// exec, so no allocation, no formatting.
pub(crate) fn apply(filters: &Filters) -> libc::c_int {
    match seccompiler::apply_filter(&filters.allowlist)
        .and_then(|_| seccompiler::apply_filter(&filters.clone3_prefilter))
        .and_then(|_| seccompiler::apply_filter(&filters.ioctl_prefilter))
    {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Syscalls the sandboxed program may call. Deliberately absent: everything
/// in the "closes" list of the module docs, plus socket/AF_VSOCK and the
/// network syscalls (network denial is unconditional: no interfaces in the
/// network namespace, and no way to create a socket).
#[cfg(target_arch = "x86_64")]
const ALLOW: &[libc::c_long] = &[
    // --- process / signals ------------------------------------------------
    // NOTE: neither `clone` nor `clone3` is in this list: `clone` is added
    // with an argument condition in `build()` (no CLONE_NEW* flags), and
    // `clone3` is forced to ENOSYS by the stacked prefilter (see the module
    // docs for the glibc fallback rationale).
    libc::SYS_fork,
    libc::SYS_vfork,
    libc::SYS_execve,
    // `execveat` is NOT here on purpose. It executes an image named by an
    // `fd` (+`AT_EMPTY_PATH`), which combined with `memfd_create` gives a
    // complete "run an arbitrary in-memory ELF" primitive (verified live:
    // a memfd holding a real ELF was exec'd and ran). That is not a sandbox
    // escape — the new image keeps the same namespaces, uid, seccomp filter
    // and `no_new_privs` — but the program can already run code it wrote to
    // its own cwd, so the fd-based route adds no capability the judge needs.
    // `fexecve` is `execveat` under the hood on modern glibc, so this also
    // closes the `fexecve` path.
    libc::SYS_exit,
    libc::SYS_exit_group,
    libc::SYS_wait4,
    libc::SYS_waitid,
    libc::SYS_kill,
    libc::SYS_tkill,
    libc::SYS_tgkill,
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_rt_sigpending,
    libc::SYS_rt_sigtimedwait,
    libc::SYS_rt_sigqueueinfo,
    libc::SYS_rt_tgsigqueueinfo,
    libc::SYS_rt_sigsuspend,
    libc::SYS_sigaltstack,
    libc::SYS_setsid,
    libc::SYS_setpgid,
    libc::SYS_getpgid,
    libc::SYS_getpgrp,
    libc::SYS_getsid,
    libc::SYS_getpid,
    libc::SYS_getppid,
    libc::SYS_gettid,
    libc::SYS_set_tid_address,
    libc::SYS_set_robust_list,
    libc::SYS_get_robust_list,
    libc::SYS_restart_syscall,
    libc::SYS_seccomp,
    // --- identity ---------------------------------------------------------
    libc::SYS_getuid,
    libc::SYS_geteuid,
    libc::SYS_getgid,
    libc::SYS_getegid,
    libc::SYS_getgroups,
    libc::SYS_setgroups,
    libc::SYS_setuid,
    libc::SYS_setgid,
    libc::SYS_setreuid,
    libc::SYS_setregid,
    libc::SYS_setresuid,
    libc::SYS_getresuid,
    libc::SYS_setresgid,
    libc::SYS_getresgid,
    libc::SYS_setfsuid,
    libc::SYS_setfsgid,
    libc::SYS_capget,
    libc::SYS_capset,
    libc::SYS_prctl,
    libc::SYS_arch_prctl,
    libc::SYS_getcpu,
    // --- memory -----------------------------------------------------------
    libc::SYS_brk,
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_mremap,
    libc::SYS_mprotect,
    libc::SYS_madvise,
    libc::SYS_msync,
    libc::SYS_mincore,
    libc::SYS_mlock,
    libc::SYS_munlock,
    libc::SYS_mlockall,
    libc::SYS_munlockall,
    libc::SYS_mlock2,
    libc::SYS_membarrier,
    libc::SYS_rseq,
    libc::SYS_pkey_mprotect,
    libc::SYS_pkey_alloc,
    libc::SYS_pkey_free,
    // --- files / directories ---------------------------------------------
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_readv,
    libc::SYS_writev,
    libc::SYS_pread64,
    libc::SYS_pwrite64,
    libc::SYS_preadv,
    libc::SYS_pwritev,
    libc::SYS_preadv2,
    libc::SYS_pwritev2,
    libc::SYS_openat,
    libc::SYS_openat2,
    libc::SYS_close,
    libc::SYS_close_range,
    libc::SYS_lseek,
    libc::SYS_fstat,
    libc::SYS_stat,
    libc::SYS_lstat,
    libc::SYS_newfstatat,
    libc::SYS_statx,
    libc::SYS_statfs,
    libc::SYS_fstatfs,
    libc::SYS_access,
    libc::SYS_faccessat,
    libc::SYS_faccessat2,
    libc::SYS_getcwd,
    libc::SYS_chdir,
    libc::SYS_fchdir,
    libc::SYS_getdents,
    libc::SYS_getdents64,
    libc::SYS_mkdir,
    libc::SYS_mkdirat,
    libc::SYS_rmdir,
    libc::SYS_rename,
    libc::SYS_renameat,
    libc::SYS_renameat2,
    libc::SYS_unlink,
    libc::SYS_unlinkat,
    libc::SYS_link,
    libc::SYS_linkat,
    libc::SYS_symlink,
    libc::SYS_symlinkat,
    libc::SYS_readlink,
    libc::SYS_readlinkat,
    libc::SYS_chmod,
    libc::SYS_fchmod,
    libc::SYS_fchmodat,
    libc::SYS_chown,
    libc::SYS_fchown,
    libc::SYS_lchown,
    libc::SYS_fchownat,
    libc::SYS_umask,
    libc::SYS_truncate,
    libc::SYS_ftruncate,
    libc::SYS_fallocate,
    libc::SYS_fsync,
    libc::SYS_fdatasync,
    libc::SYS_sync,
    libc::SYS_syncfs,
    libc::SYS_sync_file_range,
    libc::SYS_copy_file_range,
    libc::SYS_sendfile,
    libc::SYS_splice,
    libc::SYS_tee,
    libc::SYS_vmsplice,
    libc::SYS_fcntl,
    // `ioctl` is needed: CPython's **script mode** (`python3 <file>`) issues
    // it during startup, so without it every `python3 main.py` run fails with
    // EPERM ("can't open file ... Operation not permitted") — verified live.
    // `-c` mode happens not to use it, which is why the original allowlist
    // (built from `-c` probes) missed it.
    //
    // Allowing the syscall wholesale is a deliberate trade-off; the
    // dangerous terminal-injection requests are denied by the stacked
    // `ioctl_prefilter` (see `build()`), and the program has no controlling
    // terminal, no capabilities and no device nodes to drive.
    libc::SYS_ioctl,
    libc::SYS_utimensat,
    libc::SYS_utimes,
    libc::SYS_futimesat,
    libc::SYS_utime,
    libc::SYS_fadvise64,
    libc::SYS_readahead,
    libc::SYS_getxattr,
    libc::SYS_lgetxattr,
    libc::SYS_fgetxattr,
    libc::SYS_listxattr,
    libc::SYS_llistxattr,
    libc::SYS_flistxattr,
    libc::SYS_setxattr,
    libc::SYS_lsetxattr,
    libc::SYS_fsetxattr,
    libc::SYS_removexattr,
    libc::SYS_lremovexattr,
    libc::SYS_fremovexattr,
    // --- io multiplexing / timers / eventfd / inotify ---------------------
    libc::SYS_poll,
    libc::SYS_ppoll,
    libc::SYS_select,
    libc::SYS_pselect6,
    libc::SYS_epoll_create,
    libc::SYS_epoll_create1,
    libc::SYS_epoll_ctl,
    libc::SYS_epoll_wait,
    libc::SYS_epoll_pwait,
    libc::SYS_epoll_pwait2,
    libc::SYS_eventfd,
    libc::SYS_eventfd2,
    libc::SYS_timerfd_create,
    libc::SYS_timerfd_settime,
    libc::SYS_timerfd_gettime,
    libc::SYS_signalfd,
    libc::SYS_signalfd4,
    libc::SYS_inotify_init,
    libc::SYS_inotify_init1,
    libc::SYS_inotify_add_watch,
    libc::SYS_inotify_rm_watch,
    libc::SYS_timer_create,
    libc::SYS_timer_settime,
    libc::SYS_timer_gettime,
    libc::SYS_timer_getoverrun,
    libc::SYS_timer_delete,
    libc::SYS_clock_gettime,
    libc::SYS_clock_getres,
    libc::SYS_clock_nanosleep,
    libc::SYS_nanosleep,
    libc::SYS_getitimer,
    libc::SYS_setitimer,
    libc::SYS_alarm,
    libc::SYS_pause,
    libc::SYS_times,
    libc::SYS_gettimeofday,
    libc::SYS_time,
    // --- synchronisation --------------------------------------------------
    libc::SYS_futex,
    libc::SYS_futex_waitv,
    // --- filesystem file descriptors & pipes ------------------------------
    libc::SYS_dup,
    libc::SYS_dup2,
    libc::SYS_dup3,
    libc::SYS_pipe,
    libc::SYS_pipe2,
    libc::SYS_memfd_create,
    // --- system information ----------------------------------------------
    libc::SYS_uname,
    libc::SYS_sysinfo,
    libc::SYS_getrlimit,
    libc::SYS_prlimit64,
    libc::SYS_setrlimit,
    libc::SYS_getrusage,
    libc::SYS_sched_yield,
    libc::SYS_sched_getaffinity,
    libc::SYS_sched_setaffinity,
    libc::SYS_sched_getparam,
    libc::SYS_sched_getscheduler,
    libc::SYS_sched_get_priority_max,
    libc::SYS_sched_get_priority_min,
    libc::SYS_sched_rr_get_interval,
    libc::SYS_getpriority,
    libc::SYS_umask,
    // --- random / crypto helpers -----------------------------------------
    libc::SYS_getrandom,
    libc::SYS_adjtimex,
    // --- SysV IPC (the IPC namespace makes them private) ------------------
    libc::SYS_shmget,
    libc::SYS_shmat,
    libc::SYS_shmctl,
    libc::SYS_shmdt,
    libc::SYS_semget,
    libc::SYS_semop,
    libc::SYS_semctl,
    libc::SYS_semtimedop,
    libc::SYS_msgget,
    libc::SYS_msgsnd,
    libc::SYS_msgrcv,
    libc::SYS_msgctl,
    libc::SYS_mq_open,
    libc::SYS_mq_unlink,
    libc::SYS_mq_timedsend,
    libc::SYS_mq_timedreceive,
    libc::SYS_mq_notify,
    libc::SYS_mq_getsetattr,
    // --- local sockets only (no AF_INET creation) -------------------------
    libc::SYS_socketpair,
];
