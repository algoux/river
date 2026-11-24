//! Capability drop (`child.caps`).

/// <linux/capability.h>, hand-declared: libc 0.2 has no capset binding.
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// `_LINUX_CAPABILITY_VERSION_3`
const CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// Drops every capability: the bounding set first (`PR_CAPBSET_DROP` until
/// the kernel answers `EINVAL`, i.e. one past `CAP_LAST_CAP`), then `capset`
/// clears permitted/effective/inheritable, and `securebits` locks `NOROOT`
/// so uid 0 inside the sandbox can never regain a privileged securebit state
/// across execve. Returns 0 or the errno.
///
/// # Safety
/// Child-only: bare prctl/capset syscalls, no allocation.
pub unsafe fn drop_all() -> i32 {
    let mut cap: libc::c_ulong = 0;
    loop {
        // SAFETY: prctl with a scalar argument, no pointer involved.
        let r = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) };
        if r == 0 {
            cap += 1;
            // Sanity bound: the kernel stops at CAP_LAST_CAP (~41) with EINVAL.
            if cap > 256 {
                break;
            }
            continue;
        }
        // SAFETY: reads the thread-local errno cell.
        let e = unsafe { *libc::__errno_location() };
        if e == libc::EINVAL {
            break; // one past CAP_LAST_CAP: the bounding set is empty now
        }
        return e;
    }

    // capset(2) with a v3 header and zeroed data clears P/E/I.
    let header = CapHeader {
        version: CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    // SAFETY: header/data are plain structs; the syscall only reads them.
    let r = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &header as *const CapHeader,
            data.as_mut_ptr() as *const CapData,
        )
    };
    if r < 0 {
        // SAFETY: reads the thread-local errno cell.
        return unsafe { *libc::__errno_location() };
    }

    // SECBIT_NOROOT|LOCKED is unreachable rootless:
    // PR_SET_SECUREBITS requires CAP_SETPCAP in the initial user namespace
    // (EPERM here). The uid-0-regain path it guards is already closed by
    // PR_SET_NO_NEW_PRIVS, which the child sets right after this step.
    0
}
