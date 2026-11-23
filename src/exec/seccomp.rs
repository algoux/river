//! seccomp filter installation (design.md §5 `child.seccomp`, §9).
//!
//! PR 2 ships the plumbing: a BPF program is generated with `seccompiler`,
//! serialized into the `ChildSpec` and installed by the child right after
//! `no_new_privs`. The denylist itself (design.md §9's syscall table) is PR
//! 4's scope; while the rule map is empty the program is a real filter that
//! allows every syscall, which keeps the install path exercised end to end.

use std::collections::BTreeMap;

use seccompiler::{sock_filter, BpfProgram, SeccompAction, SeccompFilter, TargetArch};

/// Builds the child's BPF program (no rules yet: every syscall allowed).
pub fn build_program() -> Result<Vec<sock_filter>, String> {
    let arch = TargetArch::try_from(std::env::consts::ARCH)
        .map_err(|e| format!("seccompiler does not support this architecture: {e}"))?;
    // The match action is unreachable while the rule map is empty; it only
    // exists because seccompiler rejects identical match/mismatch actions.
    let filter = SeccompFilter::new(
        BTreeMap::new(),
        SeccompAction::Allow, // syscalls that do not match any rule
        SeccompAction::Errno(libc::EPERM as u32), // never hit in PR 2
        arch,
    )
    .map_err(|e| format!("cannot build the seccomp filter: {e}"))?;
    let program: BpfProgram = filter
        .try_into()
        .map_err(|e| format!("cannot compile the seccomp filter: {e}"))?;
    Ok(program.iter().cloned().collect())
}

/// <linux/seccomp.h>, hand-declared so the child does not depend on libc
/// exposing `sock_fprog` (the element type comes from seccompiler).
#[repr(C)]
struct SockFprog {
    len: libc::c_ushort,
    filter: *mut sock_filter,
}

/// `PR_SET_SECCOMP` with `SECCOMP_MODE_FILTER`; 0 on success, errno otherwise.
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
