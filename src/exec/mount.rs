//! Mount helpers for the child sequence (design.md §5 `child.mount.*`).
//!
//! Everything here is a bare syscall: no `io::Result` construction that
//! could allocate, no locks. Paths come pre-serialized as `&CStr` (either
//! fixed literals or `ChildSpec` memory).

use std::ffi::CStr;
use std::os::fd::RawFd;

// mount_attr flags from <linux/mount.h>; the low bits deliberately mirror
// the MS_* values.
pub const MOUNT_ATTR_RDONLY: u64 = 0x1;
pub const MOUNT_ATTR_NOSUID: u64 = 0x2;
pub const MOUNT_ATTR_NODEV: u64 = 0x4;

/// <linux/mount.h> `AT_RECURSIVE`, not exposed by libc.
const AT_RECURSIVE: libc::c_int = 0x8000;

/// <linux/mount.h> `OPEN_TREE_CLONE`.
const OPEN_TREE_CLONE: libc::c_uint = 1;

/// <linux/move_mount.h> `MOVE_MOUNT_F_EMPTY_PATH`.
const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 4;

/// `struct mount_attr`, hand-declared: rustix 0.38 does not expose
/// `mount_setattr` (development-plan.md §5, V5), so this goes through
/// `libc::syscall`.
#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

/// `mount(2)`; 0 on success, errno otherwise.
///
/// # Safety
/// Child-only: the `&CStr` arguments must outlive the call (they are fixed
/// literals or `ChildSpec` memory).
pub unsafe fn mount(
    src: &CStr,
    dst: &CStr,
    fstype: Option<&CStr>,
    flags: libc::c_ulong,
    data: Option<&CStr>,
) -> i32 {
    // SAFETY: mount(2) with C-string pointers borrowed for the call.
    let r = unsafe {
        libc::mount(
            src.as_ptr(),
            dst.as_ptr(),
            fstype.map_or_else(std::ptr::null, |t| t.as_ptr()),
            flags,
            data.map_or_else(std::ptr::null, |d| d.as_ptr()) as *const libc::c_void,
        )
    };
    if r < 0 {
        // SAFETY: reads the thread-local errno cell.
        unsafe { *libc::__errno_location() }
    } else {
        0
    }
}

/// `mount("none", "/", NULL, MS_REC|MS_PRIVATE, NULL)`: stop every mount
/// event from propagating to or from the host (design.md §5
/// `child.mount.private`). 0 on success, errno otherwise.
///
/// # Safety
/// Child-only, same contract as [`mount`].
pub unsafe fn mount_rec_private() -> i32 {
    unsafe { mount(c"none", c"/", None, libc::MS_REC | libc::MS_PRIVATE, None) }
}

/// `mount(src, dst, NULL, MS_BIND, NULL)`: a plain bind without attribute
/// changes (used for the ptmx node, whose devpts instance linkage is the
/// whole point). 0 on success, errno otherwise.
///
/// # Safety
/// Child-only, same contract as [`mount`].
pub unsafe fn bind(src: &CStr, dst: &CStr) -> i32 {
    unsafe { mount(src, dst, None, libc::MS_BIND, None) }
}

/// `mount_setattr(2)` on the mount containing `fd` (`AT_EMPTY_PATH`),
/// setting `attr_set` and optionally recursing into submounts. On the
/// mounts river cares about this only works while they are *detached*
/// (`mount_setattr` on an attached bind clone of a host-owned tree answers
/// EINVAL), which is why every bind goes through [`open_tree_clone`] +
/// [`move_mount_fd`]. 0 on success, errno otherwise.
///
/// # Safety
/// Child-only: `fd` must be a valid open fd (an `O_PATH` fd of the mount
/// root to reconfigure).
pub unsafe fn mount_setattr(fd: RawFd, attr_set: u64, recursive: bool) -> i32 {
    let mut attr = MountAttr {
        attr_set,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    let flags = libc::AT_EMPTY_PATH | if recursive { AT_RECURSIVE } else { 0 };
    // SAFETY: `attr` outlives the call; the path is "" (the fd's own mount).
    let r = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            fd as libc::c_int,
            c"".as_ptr(),
            flags,
            &mut attr as *mut MountAttr,
            std::mem::size_of::<MountAttr>(),
        )
    };
    if r < 0 {
        // SAFETY: reads the thread-local errno cell.
        unsafe { *libc::__errno_location() }
    } else {
        0
    }
}

/// `open_tree(dfd, path, OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC[|AT_RECURSIVE])`:
/// clones the mount at `path` as a *detached* mount. Returns the fd, or
/// `-errno`.
///
/// # Safety
/// Child-only: plain open_tree(2) on a fixed or `ChildSpec` path.
pub unsafe fn open_tree_clone(path: &CStr, recursive: bool) -> RawFd {
    let flags = OPEN_TREE_CLONE
        | libc::O_CLOEXEC as libc::c_uint
        | if recursive { AT_RECURSIVE as libc::c_uint } else { 0 };
    // SAFETY: plain open_tree(2) with a borrowed path.
    let r =
        unsafe { libc::syscall(libc::SYS_open_tree, libc::AT_FDCWD, path.as_ptr(), flags) };
    if r < 0 {
        // SAFETY: reads the thread-local errno cell.
        -unsafe { *libc::__errno_location() }
    } else {
        r as RawFd
    }
}

/// `move_mount(fd, "", AT_FDCWD, dst, MOVE_MOUNT_F_EMPTY_PATH)`: attaches a
/// detached mount cloned by [`open_tree_clone`]. 0 on success, errno
/// otherwise.
///
/// # Safety
/// Child-only: `fd` must be a detached mount fd; `dst` a valid path.
pub unsafe fn move_mount_fd(fd: RawFd, dst: &CStr) -> i32 {
    // SAFETY: plain move_mount(2) with borrowed arguments.
    let r = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            fd as libc::c_int,
            c"".as_ptr(),
            libc::AT_FDCWD,
            dst.as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH,
        )
    };
    if r < 0 {
        // SAFETY: reads the thread-local errno cell.
        unsafe { *libc::__errno_location() }
    } else {
        0
    }
}

/// `pivot_root(".", ".")`; 0 on success, errno otherwise.
///
/// # Safety
/// Child-only: the cwd must be the new root at this point.
pub unsafe fn pivot_root_dot() -> i32 {
    // SAFETY: pivot_root(2) with fixed "." arguments.
    let r = unsafe { libc::syscall(libc::SYS_pivot_root, c".".as_ptr(), c".".as_ptr()) };
    if r < 0 {
        // SAFETY: reads the thread-local errno cell.
        unsafe { *libc::__errno_location() }
    } else {
        0
    }
}

/// `umount2(".", MNT_DETACH)`; 0 on success, errno otherwise.
///
/// # Safety
/// Child-only: the cwd must be the (covered) root at this point.
pub unsafe fn umount2_dot_detach() -> i32 {
    // SAFETY: umount2(2) on a fixed path with a fixed flag.
    let r = unsafe { libc::umount2(c".".as_ptr(), libc::MNT_DETACH) };
    if r < 0 {
        // SAFETY: reads the thread-local errno cell.
        unsafe { *libc::__errno_location() }
    } else {
        0
    }
}
