//! seccomp denylist (design.md §5 `child.seccomp`, §9).
//!
//! Two BPF programs, both generated with `seccompiler` and installed back
//! to back by the child right after `no_new_privs` (seccomp stacks filters
//! and keeps the most restrictive verdict; the two never overlap):
//!
//! 1. `clone3` answers `ENOSYS`, so glibc's `fork`/`vfork`/`pthread_create`
//!    fall back to `clone` — which the second program filters by flags. A
//!    hand-written prologue kills every x32 syscall first (see `guard_x32`).
//! 2. the denylist answers `EPERM`: every syscall in `DENIED`, `clone` when
//!    any namespace flag is set, `socket` for every family outside the
//!    allowlist.
//!
//! `seccompiler` keys rules by syscall *number* and has one on-match
//! action per filter, hence two programs; the table names `libc::SYS_*`
//! constants instead of raw numbers (libc resolves them per architecture).
//! Everything without a rule is allowed: this is a denylist, and the
//! namespaces, the dropped caps, the read-only rootfs and Landlock carry
//! the rest (design.md §9). `RIVER_HARDENING=off` installs neither.

use std::collections::BTreeMap;

use seccompiler::{
    sock_filter, BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
    SeccompFilter, SeccompRule, TargetArch,
};

/// Syscalls that answer `EPERM` whatever their arguments (design.md §9):
/// the mount family, the kernel attack surface, the system-level group,
/// fanotify, and the two namespace syscalls denied outright (`clone` and
/// `clone3` get the flag-sensitive rules below). `adjtime` and `umount`
/// have no 64-bit entry point (glibc uses `adjtimex` / `umount2` there),
/// so the table covers them as well.
const DENIED: &[libc::c_long] = &[
    // mount family
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_chroot,
    libc::SYS_fsopen,
    libc::SYS_fsconfig,
    libc::SYS_fsmount,
    libc::SYS_move_mount,
    libc::SYS_open_tree,
    libc::SYS_mount_setattr,
    // kernel attack surface
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_bpf,
    libc::SYS_perf_event_open,
    libc::SYS_keyctl,
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_userfaultfd,
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    libc::SYS_kcmp,
    libc::SYS_pidfd_getfd,
    libc::SYS_name_to_handle_at,
    libc::SYS_open_by_handle_at,
    libc::SYS_memfd_secret,
    // system level
    libc::SYS_reboot,
    libc::SYS_kexec_load,
    libc::SYS_kexec_file_load,
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    libc::SYS_swapon,
    libc::SYS_swapoff,
    libc::SYS_settimeofday,
    libc::SYS_clock_settime,
    libc::SYS_clock_adjtime,
    libc::SYS_adjtimex,
    libc::SYS_sethostname,
    libc::SYS_setdomainname,
    libc::SYS_acct,
    libc::SYS_quotactl,
    libc::SYS_nfsservctl,
    libc::SYS_ioperm,
    libc::SYS_iopl,
    libc::SYS_syslog,
    libc::SYS_sysfs,
    libc::SYS__sysctl,
    libc::SYS_uselib,
    libc::SYS_vhangup,
    // fanotify
    libc::SYS_fanotify_init,
    libc::SYS_fanotify_mark,
    // namespaces
    libc::SYS_unshare,
    libc::SYS_setns,
];

/// `clone` flags that create or join a namespace (design.md §9).
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
                   on_match: SeccompAction|
     -> Result<BpfProgram, String> {
        SeccompFilter::new(rules, SeccompAction::Allow, on_match, arch)
            .map_err(|e| format!("cannot build the seccomp filter: {e}"))?
            .try_into()
            .map_err(|e| format!("cannot compile the seccomp filter: {e}"))
    };

    // 1. clone3 -> ENOSYS, behind the x32 guard.
    let clone3 = compile(
        BTreeMap::from([(libc::SYS_clone3, Vec::new())]),
        SeccompAction::Errno(libc::ENOSYS as u32),
    )?;

    // 2. the denylist -> EPERM.
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> =
        DENIED.iter().map(|&nr| (nr, Vec::new())).collect();
    rules.insert(libc::SYS_clone, clone_rules()?);
    rules.insert(libc::SYS_socket, socket_rules()?);
    let denylist = compile(rules, SeccompAction::Errno(libc::EPERM as u32))?;

    Ok(vec![guard_x32(clone3), denylist])
}

/// `clone`: one rule per namespace flag — the rules of a syscall are
/// OR-ed, and `seccompiler` only offers masked *equality*, so "any flag
/// set" is spelled as "this flag set" nine times.
fn clone_rules() -> Result<Vec<SeccompRule>, String> {
    CLONE_NS_FLAGS
        .iter()
        .map(|&flag| {
            let condition = SeccompCondition::new(
                0,
                SeccompCmpArgLen::Qword,
                SeccompCmpOp::MaskedEq(flag),
                flag,
            )
            .map_err(|e| format!("cannot build the clone rules: {e}"))?;
            SeccompRule::new(vec![condition])
                .map_err(|e| format!("cannot build the clone rules: {e}"))
        })
        .collect()
}

/// `socket(2)` families the sandbox may create (design.md §9):
/// `AF_UNSPEC`, `AF_UNIX`, `AF_INET`, `AF_INET6`. A denylist cannot name
/// "everything else", but the allowlist is two gaps wide: the families
/// between `AF_INET` and `AF_INET6`, and everything above `AF_INET6`
/// (compared unsigned, so negative values land there too).
fn socket_rules() -> Result<Vec<SeccompRule>, String> {
    let inet6 = libc::AF_INET6 as u64;
    let between = SeccompRule::new(vec![
        cond(SeccompCmpOp::Ge, libc::AF_INET as u64 + 1)?,
        cond(SeccompCmpOp::Le, inet6 - 1)?,
    ])
    .map_err(|e| format!("cannot build the socket rules: {e}"))?;
    let above = SeccompRule::new(vec![cond(SeccompCmpOp::Ge, inet6 + 1)?])
        .map_err(|e| format!("cannot build the socket rules: {e}"))?;
    Ok(vec![between, above])
}

/// One comparison on `socket`'s `family` (argument 0): an `int`, of which
/// the kernel reads the low 32 bits — so does `Dword`.
fn cond(op: SeccompCmpOp, value: u64) -> Result<SeccompCondition, String> {
    SeccompCondition::new(0, SeccompCmpArgLen::Dword, op, value)
        .map_err(|e| format!("cannot build the socket rules: {e}"))
}

/// `__X32_SYSCALL_BIT` (<asm/unistd.h>): x32 syscalls arrive with the
/// x86_64 audit arch and only this bit in `nr` telling them apart, so the
/// arch check lets them through to the Allow default — the classic x32
/// bypass of a denylist. `seccompiler` matches `nr` exactly and cannot
/// test bits of it, so the first program gets a hand-written prologue that
/// kills every x32 syscall outright, which is also what libseccomp does
/// for an ABI it was not asked about.
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
