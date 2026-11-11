//! seccomp: a denylist filter that blocks kernel attack surface the sandbox
//! never needs (mounting, tracing, module loading, ...). Everything else is
//! allowed: unlike an allowlist this cannot break a legitimate payload, at
//! the cost of not restricting plain file access — that is the mount
//! namespace's job in this design.

use std::collections::BTreeMap;

use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule};

/// Syscalls the sandboxed payload must never reach.
const DENIED: &[libc::c_long] = &[
    // filesystem/root manipulation (the mount namespace is already built)
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_swapon,
    libc::SYS_swapoff,
    // kernel
    libc::SYS_reboot,
    libc::SYS_kexec_load,
    libc::SYS_kexec_file_load,
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    libc::SYS_bpf,
    libc::SYS_perf_event_open,
    libc::SYS_acct,
    libc::SYS_uselib,
    libc::SYS_iopl,
    libc::SYS_ioperm,
    // escaping into other namespaces / processes
    libc::SYS_setns,
    libc::SYS_unshare,
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_open_by_handle_at,
    libc::SYS_userfaultfd,
    // kernel keyring
    libc::SYS_keyctl,
    libc::SYS_add_key,
    libc::SYS_request_key,
];

/// Builds and compiles the denylist filter; matched syscalls return `EPERM`.
pub(super) fn build_filter() -> Result<BpfProgram, i32> {
    let rules: BTreeMap<i64, Vec<SeccompRule>> =
        DENIED.iter().map(|&nr| (nr, Vec::new())).collect();
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,          // not in the list: allowed
        SeccompAction::Errno(libc::EPERM as u32), // in the list: EPERM
        std::env::consts::ARCH
            .try_into()
            .map_err(|_| libc::EINVAL)?,
    )
    .map_err(|_| libc::EINVAL)?;
    filter.try_into().map_err(|_| libc::EINVAL)
}

/// Applies the filter to the calling thread. The child is single-threaded
/// here, so one apply covers the payload. `no_new_privs` is a prerequisite
/// for loading a filter without CAP_SYS_ADMIN, and it also stops the payload
/// from regaining privileges via setuid binaries.
pub(super) fn apply(program: &BpfProgram) -> Result<(), i32> {
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1));
    }
    seccompiler::apply_filter(program).map_err(|_| libc::EPERM)
}
