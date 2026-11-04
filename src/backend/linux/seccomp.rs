//! seccomp-bpf allowlist (stage L8).
//!
//! The sandboxed program runs under a **default-deny** filter whose mismatch
//! action is `EPERM` (not `KILL`): ordinary programs keep running, denied
//! operations fail with a normal errno. The allowlist is compiled once per
//! judger process ([`program`]) and applied by the child just before
//! `execve`; the compiled BPF program is passed across the fork, so the
//! child itself never allocates.
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

/// Compile the allowlist once per process (the filter is immutable and
/// applies to the whole process tree, so one program is reused by every run).
pub(crate) fn program() -> Result<&'static Program, String> {
    static PROGRAM: std::sync::OnceLock<Result<Program, String>> = std::sync::OnceLock::new();
    PROGRAM.get_or_init(build).as_ref().map_err(|e| e.clone())
}

#[cfg(target_arch = "x86_64")]
fn build() -> Result<Program, String> {
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
        rules.entry(*syscall as i64).or_default().push(rule);
    }
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        TargetArch::x86_64,
    )
    .map_err(|e| format!("seccomp filter: {e:?}"))?;
    let program: Program = filter
        .try_into()
        .map_err(|e| format!("seccomp compile: {e:?}"))?;
    Ok(program)
}

#[cfg(not(target_arch = "x86_64"))]
fn build() -> Result<Program, String> {
    // Fail closed: an unimplemented allowlist must not silently mean "no
    // seccomp". The backend rejects construction instead.
    Err("river: the seccomp allowlist is implemented for x86_64 only".to_string())
}

/// Apply a compiled filter to the calling process (and its future children).
///
/// Returns 0 on success, -1 on failure (errno set) — called between fork and
/// exec, so no allocation, no formatting.
pub(crate) fn apply(program: &Program) -> libc::c_int {
    match seccompiler::apply_filter(program) {
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
    libc::SYS_clone,
    libc::SYS_clone3,
    libc::SYS_fork,
    libc::SYS_vfork,
    libc::SYS_execve,
    libc::SYS_execveat,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The filter compiles for the running architecture (removing a needed
    /// rule would make the Python smoke test die with SIGSYS instead).
    #[test]
    fn filter_compiles() {
        match program() {
            Ok(program) => assert!(!program.is_empty(), "empty BPF program"),
            Err(e) => {
                // Non-x86_64 targets fail closed by design.
                assert!(!cfg!(target_arch = "x86_64"), "{e}");
            }
        }
    }
}
