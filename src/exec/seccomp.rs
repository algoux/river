//! seccomp allowlist (`child.seccomp`).
//!
//! Two BPF programs, both generated with `seccompiler` and installed back
//! to back by the child right after `no_new_privs`. The kernel runs every
//! stacked filter and keeps the most restrictive verdict
//! (`seccomp_run_filters`: the lowest action value wins, compared signed
//! with the errno data masked out — so `KILL_PROCESS` beats everything
//! and `ERRNO` beats `ALLOW`).
//!
//! 1. the allowlist answers `Allow` to every syscall in `ALLOWED` and
//!    `EPERM` to everything else: the numbers the kernel adds after this
//!    table was written, x32 numbers, and every syscall that is not
//!    listed. `clone` matches only without a namespace flag, `socket`
//!    only for the four families below; any other arguments fall through
//!    to the same `EPERM`. One thing no filter can refuse: the kernel
//!    exempts `uretprobe`/`uprobe` (335/336 on x86_64) from seccomp
//!    altogether (`seccomp_uprobe_exception`) — they are probe
//!    bookkeeping, not attack surface.
//! 2. `clone3` answers `ENOSYS`, so glibc's `fork`/`vfork`/`pthread_create`
//!    fall back to `clone`. This program is installed *last* on purpose:
//!    `ENOSYS` and the allowlist's `EPERM` are both `ERRNO` actions of the
//!    same rank, and a tie keeps the verdict of the most recently installed
//!    filter. A hand-written prologue kills every x32 syscall first (see
//!    `guard_x32`): the allowlist already answers `EPERM` there, the guard
//!    turns that into a kill.
//!
//! `seccompiler` keys rules by syscall *number* and has one on-match
//! action per filter, hence two programs; the table names `libc::SYS_*`
//! constants instead of raw numbers (libc resolves them per architecture).
//! Every unconditional entry compiles to a constant path, which the kernel
//! caches per syscall number when the filter is installed
//! (`seccomp_cache_prepare`): an allowed call skips the BPF run entirely.
//! `RIVER_HARDENING=off` installs neither.

use std::collections::BTreeMap;

use seccompiler::{
    sock_filter, BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
    SeccompFilter, SeccompRule, TargetArch,
};

/// `(name, number)` pairs for the syscall table: the name is the `libc`
/// constant's own, for the diagnostic table and the tests.
macro_rules! syscalls {
    ($($name:ident),* $(,)?) => { &[ $( (stringify!($name), libc::$name) ),* ] };
}

/// Everything the sandbox may call, by the group that needs it. Anything
/// not named here answers `EPERM` (`clone` and `socket` are listed in
/// `table()` as well: they match under argument rules).
///
/// The table is deliberately as wide as a container runtime's: the
/// sandbox runs arbitrary programs over an arbitrary rootfs, and an
/// omitted syscall turns a legitimate submission into `RE`. What it must
/// contain beyond the obvious are the syscalls glibc and the common
/// runtimes *probe* with a fallback on `ENOSYS` only (`statx`,
/// `faccessat2`, `fchmodat2`, `rseq`, `membarrier`, `getrandom`,
/// `prlimit64`, `set_robust_list`, `set_tid_address`, `openat2`): a
/// `EPERM` from this filter never triggers those fallbacks. `ioctl`,
/// `prctl` and `arch_prctl` are unconditional — the devices are the five
/// bound nodes plus a private devpts, and every privileged `prctl`
/// needs a capability the child has dropped.
#[rustfmt::skip]
pub const ALLOWED: &[(&str, libc::c_long)] = syscalls![
    // process & identity
    SYS_exit, SYS_exit_group, SYS_execve, SYS_execveat,
    SYS_fork, SYS_vfork,
    SYS_wait4, SYS_waitid,
    SYS_getpid, SYS_getppid, SYS_gettid, SYS_getpgrp, SYS_getpgid,
    SYS_setpgid, SYS_getsid, SYS_setsid,
    SYS_kill, SYS_tgkill, SYS_tkill, SYS_pidfd_open, SYS_pidfd_send_signal,
    SYS_rt_sigqueueinfo, SYS_rt_tgsigqueueinfo,
    SYS_getuid, SYS_geteuid, SYS_getgid, SYS_getegid, SYS_getgroups,
    SYS_setgroups, SYS_setuid, SYS_setgid, SYS_setreuid, SYS_setregid,
    SYS_setresuid, SYS_setresgid, SYS_getresuid, SYS_getresgid,
    SYS_setfsuid, SYS_setfsgid,
    SYS_capget, SYS_capset, SYS_prctl, SYS_arch_prctl, SYS_personality,
    SYS_set_tid_address, SYS_set_robust_list, SYS_get_robust_list, SYS_rseq,
    SYS_umask,
    // signals
    SYS_rt_sigaction, SYS_rt_sigprocmask, SYS_rt_sigpending, SYS_rt_sigsuspend,
    SYS_rt_sigtimedwait, SYS_rt_sigreturn, SYS_sigaltstack, SYS_signalfd4,
    SYS_pause, SYS_restart_syscall, SYS_alarm, SYS_getitimer, SYS_setitimer,
    // memory
    SYS_brk, SYS_mmap, SYS_munmap, SYS_mprotect, SYS_mremap, SYS_madvise,
    SYS_msync, SYS_mincore, SYS_mlock, SYS_mlock2, SYS_munlock,
    SYS_mlockall, SYS_munlockall, SYS_membarrier, SYS_memfd_create,
    // files
    SYS_open, SYS_openat, SYS_openat2, SYS_creat, SYS_close, SYS_close_range,
    SYS_read, SYS_write, SYS_readv, SYS_writev, SYS_pread64, SYS_pwrite64,
    SYS_preadv, SYS_pwritev, SYS_preadv2, SYS_pwritev2, SYS_lseek,
    SYS_dup, SYS_dup2, SYS_dup3, SYS_fcntl, SYS_flock, SYS_ioctl,
    SYS_stat, SYS_fstat, SYS_lstat, SYS_newfstatat, SYS_statx,
    SYS_statfs, SYS_fstatfs, SYS_readlink, SYS_readlinkat,
    SYS_getdents, SYS_getdents64,
    SYS_access, SYS_faccessat, SYS_faccessat2,
    SYS_chdir, SYS_fchdir, SYS_getcwd,
    SYS_mkdir, SYS_mkdirat, SYS_rmdir, SYS_unlink, SYS_unlinkat,
    SYS_rename, SYS_renameat, SYS_renameat2,
    SYS_link, SYS_linkat, SYS_symlink, SYS_symlinkat,
    SYS_chmod, SYS_fchmod, SYS_fchmodat, SYS_fchmodat2,
    SYS_chown, SYS_fchown, SYS_lchown, SYS_fchownat,
    SYS_truncate, SYS_ftruncate, SYS_fallocate, SYS_fadvise64,
    SYS_sync_file_range, SYS_readahead,
    SYS_utime, SYS_utimes, SYS_utimensat, SYS_futimesat,
    SYS_fsync, SYS_fdatasync, SYS_sendfile, SYS_copy_file_range,
    SYS_splice, SYS_tee, SYS_vmsplice,
    // the capability check still refuses device nodes in /work
    SYS_mknod, SYS_mknodat,
    // shutil.copystat lists and copies them
    SYS_getxattr, SYS_lgetxattr, SYS_fgetxattr,
    SYS_setxattr, SYS_lsetxattr, SYS_fsetxattr,
    SYS_listxattr, SYS_llistxattr, SYS_flistxattr,
    SYS_removexattr, SYS_lremovexattr, SYS_fremovexattr,
    // pipes & readiness
    SYS_pipe, SYS_pipe2, SYS_eventfd, SYS_eventfd2,
    SYS_poll, SYS_ppoll, SYS_select, SYS_pselect6,
    SYS_epoll_create, SYS_epoll_create1, SYS_epoll_ctl, SYS_epoll_wait,
    SYS_epoll_pwait, SYS_epoll_pwait2,
    SYS_inotify_init, SYS_inotify_init1, SYS_inotify_add_watch, SYS_inotify_rm_watch,
    // time & accounting
    SYS_time, SYS_gettimeofday, SYS_clock_gettime, SYS_clock_getres,
    SYS_nanosleep, SYS_clock_nanosleep,
    SYS_timer_create, SYS_timer_settime, SYS_timer_gettime, SYS_timer_getoverrun,
    SYS_timer_delete,
    SYS_timerfd_create, SYS_timerfd_settime, SYS_timerfd_gettime,
    SYS_times, SYS_getrusage, SYS_uname, SYS_sysinfo, SYS_getcpu, SYS_getrandom,
    SYS_futex, SYS_futex_waitv,
    // limits & scheduler
    SYS_getrlimit, SYS_setrlimit, SYS_prlimit64,
    SYS_getpriority, SYS_setpriority, SYS_ioprio_get, SYS_ioprio_set,
    SYS_sched_yield, SYS_sched_getaffinity, SYS_sched_setaffinity,
    SYS_sched_getparam, SYS_sched_setparam, SYS_sched_getscheduler,
    SYS_sched_setscheduler, SYS_sched_get_priority_max, SYS_sched_get_priority_min,
    SYS_sched_rr_get_interval, SYS_sched_getattr, SYS_sched_setattr,
    // sockets; the family rule is on `socket` itself
    SYS_socket, SYS_socketpair, SYS_bind, SYS_listen, SYS_accept, SYS_accept4,
    SYS_connect, SYS_sendto, SYS_recvfrom, SYS_sendmsg, SYS_recvmsg,
    SYS_sendmmsg, SYS_recvmmsg, SYS_shutdown, SYS_getsockname, SYS_getpeername,
    SYS_setsockopt, SYS_getsockopt,
    // newer kernels, harmless: sealing one's own mappings
    SYS_mseal,
];

/// `map_shadow_stack` (<asm/unistd.h>, 6.6): harmless (a shadow-stack
/// mapping in the caller's own address space), and glibc on CET hardware
/// needs it for every thread. libc 0.2 has no constant yet.
const MAP_SHADOW_STACK: libc::c_long = 453;

/// `clone` flags that create or join a namespace.
const CLONE_NS_FLAGS: [u64; 9] = [
    libc::CLONE_NEWTIME as u64,
    libc::CLONE_NEWNS as u64,
    libc::CLONE_NEWCGROUP as u64,
    libc::CLONE_NEWUTS as u64,
    libc::CLONE_NEWIPC as u64,
    libc::CLONE_NEWUSER as u64,
    libc::CLONE_NEWPID as u64,
    libc::CLONE_NEWNET as u64,
    // CLONE_INTO_CGROUP from <linux/sched.h>; libc's gnu binding does not fit c_int.
    0x2000_0000_0000,
];

/// Compiles the child's BPF programs in install order (see the module
/// docs). Runs in the parent; the result travels in `ChildSpec`.
pub fn build_programs() -> Result<Vec<BpfProgram>, String> {
    let arch = TargetArch::try_from(std::env::consts::ARCH)
        .map_err(|e| format!("seccompiler does not support this architecture: {e}"))?;
    let compile = |rules: BTreeMap<i64, Vec<SeccompRule>>,
                   mismatch: SeccompAction,
                   on_match: SeccompAction|
     -> Result<BpfProgram, String> {
        SeccompFilter::new(rules, mismatch, on_match, arch)
            .map_err(|e| format!("cannot build the seccomp filter: {e}"))?
            .try_into()
            .map_err(|e| format!("cannot compile the seccomp filter: {e}"))
    };

    // 1. the allowlist: listed -> Allow, anything else -> EPERM.
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> =
        ALLOWED.iter().map(|&(_, nr)| (nr, Vec::new())).collect();
    rules.insert(MAP_SHADOW_STACK, Vec::new());
    rules.insert(libc::SYS_clone, vec![clone_rule()?]);
    rules.insert(libc::SYS_socket, socket_rules()?);
    let allowlist = compile(
        rules,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
    )?;

    // 2. clone3 -> ENOSYS behind the x32 guard, installed last so that its
    //    same-rank action wins the tie against the allowlist's EPERM.
    let clone3 = compile(
        BTreeMap::from([(libc::SYS_clone3, Vec::new())]),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS as u32),
    )?;

    Ok(vec![allowlist, guard_x32(clone3)])
}

/// The syscalls seccomp lets through as `(name, number)`: `ALLOWED` plus
/// the entries with argument rules. For the test-suite's whole-table
/// probe (`river._river._seccomp_table`).
pub fn table() -> Vec<(String, i64)> {
    let bare = |name: &str| name.strip_prefix("SYS_").unwrap_or(name).to_string();
    ALLOWED
        .iter()
        .map(|&(name, nr)| (bare(name), nr))
        .chain([
            (bare("map_shadow_stack"), MAP_SHADOW_STACK),
            (bare("clone"), libc::SYS_clone),
            (bare("socket"), libc::SYS_socket),
        ])
        .collect()
}

/// `clone`: one rule — the nine namespace flags all clear. A rule's
/// conditions are AND-ed and `seccompiler` only offers masked *equality*,
/// so "no flag set" is spelled as `(flags & flag) == 0` nine times.
fn clone_rule() -> Result<SeccompRule, String> {
    let conditions = CLONE_NS_FLAGS
        .iter()
        .map(|&flag| {
            SeccompCondition::new(0, SeccompCmpArgLen::Qword, SeccompCmpOp::MaskedEq(flag), 0)
                .map_err(|e| format!("cannot build the clone rule: {e}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    SeccompRule::new(conditions).map_err(|e| format!("cannot build the clone rule: {e}"))
}

/// `socket(2)` families the sandbox may create: `AF_UNSPEC`, `AF_UNIX`,
/// `AF_INET`, `AF_INET6` — one rule each (the rules of a syscall are
/// OR-ed); every other family falls through to the filter's `EPERM`.
fn socket_rules() -> Result<Vec<SeccompRule>, String> {
    [
        libc::AF_UNSPEC,
        libc::AF_UNIX,
        libc::AF_INET,
        libc::AF_INET6,
    ]
    .into_iter()
    .map(|family| {
        SeccompRule::new(vec![cond(SeccompCmpOp::Eq, family as u64)?])
            .map_err(|e| format!("cannot build the socket rules: {e}"))
    })
    .collect()
}

/// One comparison on `socket`'s `family` (argument 0): an `int`, of which
/// the kernel reads the low 32 bits — so does `Dword`.
fn cond(op: SeccompCmpOp, value: u64) -> Result<SeccompCondition, String> {
    SeccompCondition::new(0, SeccompCmpArgLen::Dword, op, value)
        .map_err(|e| format!("cannot build the socket rules: {e}"))
}

/// `__X32_SYSCALL_BIT` (<asm/unistd.h>): x32 syscalls arrive with the
/// x86_64 audit arch and only this bit in `nr` telling them apart, so
/// both programs below see a number that matches no rule. `seccompiler`
/// matches `nr` exactly and cannot test bits of it, so the first program
/// gets a hand-written prologue that kills every x32 syscall outright —
/// the allowlist answers `EPERM` there anyway; the guard makes it a kill,
/// which is also what libseccomp does for an ABI it was not asked about.
#[cfg(target_arch = "x86_64")]
fn guard_x32(program: BpfProgram) -> BpfProgram {
    // The cBPF opcodes for four instructions (<linux/bpf_common.h>);
    // seccompiler's are private.
    const LD_W_ABS: u16 = 0x00 | 0x00 | 0x20; // BPF_LD | BPF_W | BPF_ABS
    const ALU_AND_K: u16 = 0x04 | 0x50 | 0x00; // BPF_ALU | BPF_AND | BPF_K
    const JMP_JEQ_K: u16 = 0x05 | 0x10 | 0x00; // BPF_JMP | BPF_JEQ | BPF_K
    const RET_K: u16 = 0x06 | 0x00; // BPF_RET | BPF_K
    const X32_SYSCALL_BIT: u32 = 0x4000_0000;
    let mut out = vec![
        sock_filter {
            code: LD_W_ABS,
            jt: 0,
            jf: 0,
            k: 0, // offsetof(struct seccomp_data, nr)
        },
        sock_filter {
            code: ALU_AND_K,
            jt: 0,
            jf: 0,
            k: X32_SYSCALL_BIT,
        },
        sock_filter {
            code: JMP_JEQ_K,
            jt: 1, // a native syscall: skip the kill
            jf: 0,
            k: 0,
        },
        sock_filter {
            code: RET_K,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_KILL_PROCESS,
        },
    ];
    out.extend(program);
    out
}

#[cfg(not(target_arch = "x86_64"))]
fn guard_x32(program: BpfProgram) -> BpfProgram {
    program
}

/// <linux/seccomp.h>, hand-declared so the child does not depend on libc
/// exposing `sock_fprog` (the element type comes from seccompiler).
#[repr(C)]
struct SockFprog {
    len: libc::c_ushort,
    filter: *mut sock_filter,
}

/// `PR_SET_SECCOMP` with `SECCOMP_MODE_FILTER` for one program; 0 on
/// success, errno otherwise. Calling it again stacks the next program on
/// top of the previous one.
///
/// # Safety
/// Child-only: `program` must be backed by `ChildSpec` memory and must not
/// be mutated concurrently.
pub unsafe fn install(program: &[sock_filter]) -> i32 {
    let mut fprog = SockFprog {
        len: program.len() as libc::c_ushort,
        filter: program.as_ptr() as *mut sock_filter,
    };
    // SAFETY: `fprog` outlives the prctl call; no other locks are taken.
    let r = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER as libc::c_ulong,
            &mut fprog as *mut SockFprog as libc::c_ulong,
            0,
            0,
        )
    };
    if r < 0 {
        // SAFETY: reads the thread-local errno cell.
        unsafe { *libc::__errno_location() }
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// `AUDIT_ARCH_X86_64` (<linux/audit.h>): the arch the programs are
    /// compiled for; seccompiler's copy is private.
    const AUDIT_ARCH_X86_64: u32 = 62 | 0x8000_0000 | 0x4000_0000;

    const ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
    const KILL_PROCESS: u32 = libc::SECCOMP_RET_KILL_PROCESS;

    const fn errno(value: i32) -> u32 {
        libc::SECCOMP_RET_ERRNO | value as u32
    }

    /// Syscalls that must stay outside the allowlist whatever happens to
    /// the table: the former denylist, plus the attack surface it missed
    /// (legacy AIO, `modify_ldt`, the NUMA calls, `pkey_*`, the newer
    /// mount-API and process syscalls).
    #[rustfmt::skip]
    const NEVER_ALLOWED: &[libc::c_long] = &[
        // mount family
        libc::SYS_mount, libc::SYS_umount2, libc::SYS_pivot_root, libc::SYS_chroot,
        libc::SYS_fsopen, libc::SYS_fsconfig, libc::SYS_fsmount, libc::SYS_fspick,
        libc::SYS_move_mount, libc::SYS_open_tree, libc::SYS_mount_setattr,
        // kernel attack surface
        libc::SYS_ptrace, libc::SYS_process_vm_readv, libc::SYS_process_vm_writev,
        libc::SYS_bpf, libc::SYS_perf_event_open,
        libc::SYS_keyctl, libc::SYS_add_key, libc::SYS_request_key,
        libc::SYS_userfaultfd, libc::SYS_io_uring_setup, libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register, libc::SYS_kcmp, libc::SYS_pidfd_getfd,
        libc::SYS_name_to_handle_at, libc::SYS_open_by_handle_at, libc::SYS_memfd_secret,
        libc::SYS_lookup_dcookie, libc::SYS_modify_ldt,
        libc::SYS_io_setup, libc::SYS_io_destroy, libc::SYS_io_getevents,
        libc::SYS_io_submit, libc::SYS_io_cancel,
        libc::SYS_mbind, libc::SYS_set_mempolicy, libc::SYS_get_mempolicy,
        libc::SYS_migrate_pages, libc::SYS_move_pages,
        libc::SYS_pkey_alloc, libc::SYS_pkey_free, libc::SYS_pkey_mprotect,
        libc::SYS_process_madvise, libc::SYS_process_mrelease,
        // system level
        libc::SYS_reboot, libc::SYS_kexec_load, libc::SYS_kexec_file_load,
        libc::SYS_init_module, libc::SYS_finit_module, libc::SYS_delete_module,
        libc::SYS_swapon, libc::SYS_swapoff,
        libc::SYS_settimeofday, libc::SYS_clock_settime, libc::SYS_clock_adjtime,
        libc::SYS_adjtimex, libc::SYS_sethostname, libc::SYS_setdomainname,
        libc::SYS_acct, libc::SYS_quotactl, libc::SYS_quotactl_fd, libc::SYS_nfsservctl,
        libc::SYS_ioperm, libc::SYS_iopl, libc::SYS_syslog, libc::SYS_sysfs,
        libc::SYS__sysctl, libc::SYS_uselib, libc::SYS_vhangup,
        // fanotify, namespaces, self-restriction nobody needs
        libc::SYS_fanotify_init, libc::SYS_fanotify_mark,
        libc::SYS_unshare, libc::SYS_setns,
        libc::SYS_seccomp, libc::SYS_landlock_create_ruleset,
        libc::SYS_landlock_add_rule, libc::SYS_landlock_restrict_self,
    ];

    /// `struct seccomp_data` as the programs read it: `nr` at 0, `arch`
    /// at 4, `args` from 16, one `u64` each.
    #[derive(Clone, Copy)]
    struct Data {
        nr: u32,
        arch: u32,
        args: [u64; 6],
    }

    fn call(nr: libc::c_long, args: [u64; 6]) -> Data {
        Data {
            nr: nr as u32,
            arch: AUDIT_ARCH_X86_64,
            args,
        }
    }

    impl Data {
        /// The 32-bit word at `offset`, little-endian like the kernel's copy.
        fn word(&self, offset: u32) -> u32 {
            match offset {
                0 => self.nr,
                4 => self.arch,
                16..=63 => {
                    let byte = offset - 16;
                    (self.args[(byte / 8) as usize] >> (8 * (byte % 8))) as u32
                }
                _ => panic!("load from an unexpected seccomp_data offset: {offset}"),
            }
        }
    }

    // The cBPF opcodes seccompiler emits (<linux/bpf_common.h>).
    const LD_W_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
    const ALU_AND_K: u16 = 0x54; // BPF_ALU | BPF_AND | BPF_K
    const JMP_JA: u16 = 0x05; // BPF_JMP | BPF_JA
    const JMP_JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
    const JMP_JGT_K: u16 = 0x25; // BPF_JMP | BPF_JGT | BPF_K
    const JMP_JGE_K: u16 = 0x35; // BPF_JMP | BPF_JGE | BPF_K
    const RET_K: u16 = 0x06; // BPF_RET | BPF_K

    /// Runs one program the way the kernel does; panics on an opcode the
    /// interpreter does not know, so a seccompiler that starts emitting
    /// something else fails loudly here instead of silently passing.
    fn run(program: &[sock_filter], data: &Data) -> u32 {
        let mut a: u32 = 0;
        let mut pc = 0usize;
        for _ in 0..10_000 {
            let insn = &program[pc];
            let jump = match insn.code {
                LD_W_ABS => {
                    a = data.word(insn.k);
                    0
                }
                ALU_AND_K => {
                    a &= insn.k;
                    0
                }
                JMP_JA => insn.k as usize,
                JMP_JEQ_K => (if a == insn.k { insn.jt } else { insn.jf }) as usize,
                JMP_JGT_K => (if a > insn.k { insn.jt } else { insn.jf }) as usize,
                JMP_JGE_K => (if a >= insn.k { insn.jt } else { insn.jf }) as usize,
                RET_K => return insn.k,
                other => panic!("unknown cBPF opcode {other:#06x}"),
            };
            pc += jump + 1;
        }
        panic!("the program does not terminate");
    }

    /// `seccomp_run_filters`: every program runs, the most recently
    /// installed first; the lowest action (signed, the errno masked out)
    /// wins, and a tie keeps the earlier verdict.
    fn stack(programs: &[BpfProgram], data: &Data) -> u32 {
        let rank = |ret: u32| (ret & 0xffff_0000) as i32;
        let mut ret = ALLOW;
        for program in programs.iter().rev() {
            let cur = run(program, data);
            if rank(cur) < rank(ret) {
                ret = cur;
            }
        }
        ret
    }

    fn programs() -> Vec<BpfProgram> {
        build_programs().expect("the seccomp programs compile")
    }

    fn listed() -> BTreeSet<libc::c_long> {
        table().into_iter().map(|(_, nr)| nr).collect()
    }

    #[test]
    fn every_listed_syscall_is_allowed() {
        let programs = programs();
        for (name, nr) in table() {
            assert_eq!(
                stack(&programs, &call(nr, [0; 6])),
                ALLOW,
                "{name} is listed but not allowed"
            );
        }
    }

    #[test]
    fn everything_else_answers_eperm() {
        let programs = programs();
        let listed = listed();
        // 0..=1024 covers the x86_64 table with room for later additions
        // (-1 carries the x32 bit and is killed, see the test below).
        for nr in 0..=1024 {
            let got = stack(&programs, &call(nr, [0; 6]));
            if nr == libc::SYS_clone3 {
                // not listed, yet ENOSYS: its own program answers first.
                assert_eq!(got, errno(libc::ENOSYS));
            } else if !listed.contains(&nr) {
                assert_eq!(got, errno(libc::EPERM), "{nr} is not listed");
            }
        }
    }

    #[test]
    fn x32_numbers_are_killed() {
        let programs = programs();
        // -1 is "no syscall" (0xffffffff): the bit is set, so it dies too.
        for nr in [1, libc::SYS_socket, libc::SYS_clone3, -1] {
            let data = call(0x4000_0000 | nr, [0; 6]);
            assert_eq!(stack(&programs, &data), KILL_PROCESS, "x32 nr {nr}");
        }
    }

    #[test]
    fn clone3_answers_enosys_because_its_program_is_installed_last() {
        let programs = programs();
        let clone3 = call(libc::SYS_clone3, [0; 6]);
        assert_eq!(stack(&programs, &clone3), errno(libc::ENOSYS));
        // A tie between same-rank actions keeps the newest filter's verdict:
        // installed first, the ENOSYS program would lose to the allowlist's
        // EPERM and glibc could not fall back from clone3 to clone.
        let reversed: Vec<BpfProgram> = programs.iter().rev().cloned().collect();
        assert_eq!(stack(&reversed, &clone3), errno(libc::EPERM));
    }

    #[test]
    fn clone_is_allowed_without_namespace_flags_only() {
        let programs = programs();
        const SIGCHLD: u64 = 0x11;
        let thread = SIGCHLD
            | (libc::CLONE_VM
                | libc::CLONE_FS
                | libc::CLONE_FILES
                | libc::CLONE_SIGHAND
                | libc::CLONE_THREAD
                | libc::CLONE_SYSVSEM) as u64;
        let decide = |flags: u64| stack(&programs, &call(libc::SYS_clone, [flags, 0, 0, 0, 0, 0]));
        for flags in [0, SIGCHLD, thread, libc::CLONE_PIDFD as u64 | SIGCHLD] {
            assert_eq!(decide(flags), ALLOW, "flags {flags:#x}");
        }
        for flag in CLONE_NS_FLAGS {
            for flags in [flag, flag | SIGCHLD, flag | thread] {
                assert_eq!(decide(flags), errno(libc::EPERM), "flags {flags:#x}");
            }
        }
    }

    #[test]
    fn socket_is_allowed_for_four_families_only() {
        let programs = programs();
        let decide = |family: i32| {
            let data = call(libc::SYS_socket, [family as u32 as u64, 0, 0, 0, 0, 0]);
            stack(&programs, &data)
        };
        for family in [
            libc::AF_UNSPEC,
            libc::AF_UNIX,
            libc::AF_INET,
            libc::AF_INET6,
        ] {
            assert_eq!(decide(family), ALLOW, "family {family}");
        }
        for family in [16, 17, 38, 40, 44, 45, -1, i32::MIN] {
            assert_eq!(decide(family), errno(libc::EPERM), "family {family}");
        }
    }

    #[test]
    fn the_programs_fit_the_kernel_limit() {
        let sizes: Vec<String> = programs().iter().map(|p| p.len().to_string()).collect();
        eprintln!("seccomp programs: {} instructions", sizes.join(" + "));
        for program in programs() {
            assert!(program.len() < 4096, "{} instructions", program.len());
        }
    }

    #[test]
    fn the_attack_surface_stays_outside_the_allowlist() {
        let listed = listed();
        let leaked: Vec<_> = NEVER_ALLOWED
            .iter()
            .filter(|nr| listed.contains(nr))
            .collect();
        assert!(leaked.is_empty(), "in the allowlist: {leaked:?}");
    }

    #[test]
    fn every_number_is_a_native_syscall_number() {
        // libc uses -1 for a constant an architecture lacks; the x32 bit
        // would be a typo'd number. Both would silently match nothing.
        // `read` is number 0, so the range starts there.
        for (name, nr) in table() {
            assert!((0..0x4000_0000).contains(&nr), "{name} = {nr}");
        }
    }
}
