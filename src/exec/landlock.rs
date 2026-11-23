//! Landlock filesystem rules (design.md §9).
//!
//! The parent computes the ABI-gated access masks (using the `landlock`
//! crate's `AccessFs` flag values, which mirror the kernel UAPI bits); the
//! child creates the ruleset and adds every rule with bare syscalls —
//! nothing may allocate after clone3.

use std::ffi::CStr;
use std::io;
use std::os::fd::RawFd;

use landlock::{Access, ABI, AccessFs, BitFlags};

/// Access rights river handles, each paired with the ABI that introduced it
/// (design.md §9). Read/execute rights are never handled: the rootfs is
/// mounted read-only and `/proc` is a fresh instance.
const HANDLED: [(AccessFs, u32); 11] = [
    (AccessFs::WriteFile, 1),
    (AccessFs::RemoveDir, 1),
    (AccessFs::RemoveFile, 1),
    (AccessFs::MakeChar, 1),
    (AccessFs::MakeDir, 1),
    (AccessFs::MakeReg, 1),
    (AccessFs::MakeSock, 1),
    (AccessFs::MakeSym, 1),
    (AccessFs::MakeFifo, 2),
    (AccessFs::Truncate, 3),
    (AccessFs::IoctlDev, 4),
];

/// Per-run masks handed to the child through `ChildSpec`.
#[derive(Clone, Copy, Debug)]
pub struct Masks {
    /// `handled_access_fs` of the ruleset.
    pub handled: u64,
    /// Allowed set for `/work`, `/tmp` and `/dev/shm`: everything handled.
    pub full: u64,
    /// Allowed set for `/dev/pts` and the bound device nodes: `WRITE_FILE`.
    pub write_only: u64,
}

/// Raw `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`.
/// Shared with the preflight's `landlock_abi` check.
pub fn probe_abi() -> io::Result<u32> {
    // LANDLOCK_CREATE_RULESET_VERSION from <linux/landlock.h>; libc does not
    // export it.
    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
    // SAFETY: plain syscall; the only pointer argument is NULL.
    let r = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r as u32)
    }
}

/// Masks for the running kernel; `None` when Landlock is unavailable (ABI 0,
/// `ENOSYS` or `EOPNOTSUPP`) and the hardening layer is skipped with a debug
/// warning (design.md §9).
pub fn compute_masks() -> Option<Masks> {
    let abi = probe_abi().ok()?;
    if abi == 0 {
        return None;
    }
    // The crate clamps newer kernels to the latest ABI it knows; Landlock
    // only ever adds rights between ABIs, so the intersection below stays
    // valid either way.
    let kernel_known: u64 = AccessFs::from_all(ABI::from(abi as i32)).bits();
    let mut handled = 0;
    for &(right, min_abi) in &HANDLED {
        if abi >= min_abi {
            handled |= bits(right);
        }
    }
    handled &= kernel_known;
    if handled == 0 {
        return None;
    }
    // The pseudo devices and /dev/pts also need IOCTL_DEV (ABI ≥ 4): a pty
    // allocates through ioctls on /dev/ptmx, and Landlock denies device
    // ioctls unless the right is granted alongside WRITE_FILE.
    let device = bits(AccessFs::WriteFile) | (bits(AccessFs::IoctlDev) & kernel_known);
    Some(Masks {
        handled,
        full: handled,
        write_only: device & handled,
    })
}

fn bits(right: AccessFs) -> u64 {
    let flags: BitFlags<AccessFs> = right.into();
    flags.bits()
}

// ------------------------------------------------------------- child side

/// Fixed rule targets inside every sandbox (design.md §9): the full handled
/// set for the writable mounts, `WRITE_FILE` only for the pseudo-terminal
/// and the bound device nodes.
const RULES: [(&CStr, bool); 10] = [
    (c"/work", true),
    (c"/tmp", true),
    (c"/dev/shm", true),
    (c"/dev/pts", false),
    (c"/dev/null", false),
    (c"/dev/zero", false),
    (c"/dev/full", false),
    (c"/dev/random", false),
    (c"/dev/urandom", false),
    (c"/dev/ptmx", false),
];

/// <linux/landlock.h>, hand-declared: the crate's `uapi` module is private
/// and the child must not depend on anything that allocates. Only the first
/// field is passed (size 8), which every Landlock kernel accepts.
#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
}

#[repr(C)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// `LANDLOCK_RULE_PATH_BENEATH`
const RULE_PATH_BENEATH: libc::c_int = 1;

/// Creates the ruleset, adds every rule, then restricts self. Runs in the
/// child after `no_new_privs` (design.md §5); returns 0 or the errno.
///
/// # Safety
/// Must run in the child after clone3, with `masks` backed by `ChildSpec`
/// memory: only raw syscalls are issued, so the caller must not hold locks.
pub unsafe fn child_apply(masks: &Masks) -> i32 {
    let attr = RulesetAttr {
        handled_access_fs: masks.handled,
    };
    // SAFETY: `attr` outlives the syscall; flags 0 create a real ruleset.
    let ruleset_fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr as *const RulesetAttr,
            std::mem::size_of::<RulesetAttr>(),
            0u32,
        )
    };
    if ruleset_fd < 0 {
        return errno();
    }
    for &(path, full) in &RULES {
        let allowed = if full { masks.full } else { masks.write_only };
        if allowed == 0 {
            continue;
        }
        // SAFETY: fixed sandbox paths, opened as read-only rule anchors.
        let parent_fd = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if parent_fd < 0 {
            unsafe { libc::close(ruleset_fd as RawFd) };
            return errno();
        }
        let rule = PathBeneathAttr {
            allowed_access: allowed,
            parent_fd,
        };
        // SAFETY: `rule` outlives the syscall.
        let r = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                ruleset_fd,
                RULE_PATH_BENEATH,
                &rule as *const PathBeneathAttr,
                0u32,
            )
        };
        unsafe { libc::close(parent_fd) };
        if r < 0 {
            unsafe { libc::close(ruleset_fd as RawFd) };
            return errno();
        }
    }
    // SAFETY: plain syscall on a ruleset fd we own.
    let r = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd, 0u32) };
    unsafe { libc::close(ruleset_fd as RawFd) };
    if r < 0 {
        errno()
    } else {
        0
    }
}

fn errno() -> i32 {
    // SAFETY: reads the thread-local errno cell.
    unsafe { *libc::__errno_location() }
}
