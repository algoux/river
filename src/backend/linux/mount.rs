//! Mount-namespace construction primitives. Everything here runs **in the
//! forked supervisor, between fork and
//! exec** — so it must be allocation-free and only use raw syscalls: all
//! paths arrive pre-built as `CString`s from the parent (see `MountPlan` in
//! `ns.rs`).
//!
//! Layout built inside the per-run tmpfs root:
//!
//! ```text
//! <root>            tmpfs (mode 755)
//! ├── cwd/          bind mount of the host per-run workdir (rw)
//! ├── tmp/           (TMPDIR, inside the same bind)
//! ├── proc/         B mounts a fresh procfs after its pid-namespace fork
//! ├── dev/          tmpfs + null/zero/random/urandom nodes
//! ├── runtimes/N/   caller runtimes, bind-mounted read-only
//! └── usr, lib, lib64, bin, sbin, etc
//!                   system dirs, bind-mounted read-only (mirror of the
//!                   Windows "System32 is always readable" rule)
//! ```
//!
//! Every function here is an `unsafe fn` talking to the kernel directly; the
//! extra `unsafe {}` blocks are intentionally omitted.
#![allow(unsafe_op_in_unsafe_fn)]

use std::ffi::CStr;

/// Minimal device set every libc program expects. Names are C string
/// literals so the child side never allocates one.
pub(crate) const DEV_NODES: &[(&CStr, libc::c_uint, libc::c_uint, libc::mode_t)] = &[
    // name, major, minor, mode
    (c"null", 1, 3, 0o666),
    (c"zero", 1, 5, 0o666),
    (c"random", 1, 8, 0o666),
    (c"urandom", 1, 9, 0o666),
    (c"tty", 5, 0, 0o666),
];

/// `mkdir -p` for a path that is relative to the new root (`dst` itself is
/// a full path inside the sandbox tree). Allocation-free: the path is
/// walked with a stack buffer.
pub(crate) unsafe fn mkdir_p(path: &CStr) -> libc::c_int {
    // Walk the path, creating each prefix. The buffer is a copy of the path
    // so components can be NUL-terminated one at a time.
    let bytes = path.to_bytes();
    if bytes.len() >= 4096 {
        return libc::ENAMETOOLONG;
    }
    let mut buf = [0u8; 4096];
    buf[..bytes.len()].copy_from_slice(bytes);

    let mut i = 1;
    while i <= bytes.len() {
        if i == bytes.len() || buf[i] == b'/' {
            let saved = buf[i];
            buf[i] = 0;
            let rc = libc::mkdir(buf.as_ptr().cast(), 0o755);
            if rc != 0 {
                let errno = *libc::__errno_location();
                if errno != libc::EEXIST {
                    return errno;
                }
            }
            buf[i] = saved;
        }
        i += 1;
    }
    0
}

/// Create an empty file (mode `mode`, subject to umask) — the target of a
/// file bind mount. Returns 0 or errno.
pub(crate) unsafe fn create_file(path: &CStr, mode: libc::mode_t) -> libc::c_int {
    let fd = libc::open(
        path.as_ptr(),
        libc::O_CREAT | libc::O_WRONLY | libc::O_CLOEXEC,
        mode,
    );
    if fd < 0 {
        return *libc::__errno_location();
    }
    libc::close(fd);
    0
}

/// Mount a tmpfs at `dst`, with `flags` (e.g. `MS_NOSUID`).
pub(crate) unsafe fn mount_tmpfs(dst: &CStr, options: &CStr, flags: libc::c_ulong) -> libc::c_int {
    let rc = libc::mount(
        c"tmpfs".as_ptr(),
        dst.as_ptr(),
        c"tmpfs".as_ptr(),
        flags,
        options.as_ptr().cast(),
    );
    errno_or_zero(rc)
}

/// Bind-mount `src` onto `dst`, then remount read-only with `nosuid,nodev`.
///
/// `MS_NOSUID` matters: `/usr` (and caller runtimes) may contain setuid-root
/// helpers; without it the sandboxed program could start an euid-0 process
/// from the initial user namespace. `MS_NODEV` removes raw-device access.
pub(crate) unsafe fn bind_ro(src: &CStr, dst: &CStr) -> libc::c_int {
    let rc = libc::mount(
        src.as_ptr(),
        dst.as_ptr(),
        std::ptr::null(),
        libc::MS_BIND | libc::MS_REC,
        std::ptr::null(),
    );
    if rc != 0 {
        return *libc::__errno_location();
    }
    let rc = libc::mount(
        std::ptr::null(),
        dst.as_ptr(),
        std::ptr::null(),
        libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
        std::ptr::null(),
    );
    errno_or_zero(rc)
}

/// Create a device node inside the sandbox dev tmpfs.
pub(crate) unsafe fn make_device(
    dir: &CStr,
    name: &CStr,
    major: libc::c_uint,
    minor: libc::c_uint,
    mode: libc::mode_t,
) -> libc::c_int {
    // dev_t encoding for mknod: makedev(3) equivalent.
    let dev = ((major & 0xfff) as libc::c_ulong) << 8
        | (minor & 0xff) as libc::c_ulong
        | ((minor & !0xff) as libc::c_ulong) << 12
        | ((major & !0xfff) as libc::c_ulong) << 32;
    let mut path = [0u8; 4096];
    let dir_b = dir.to_bytes();
    let name_b = name.to_bytes();
    if dir_b.len() + 1 + name_b.len() + 1 > path.len() {
        return libc::ENAMETOOLONG;
    }
    path[..dir_b.len()].copy_from_slice(dir_b);
    path[dir_b.len()] = b'/';
    path[dir_b.len() + 1..dir_b.len() + 1 + name_b.len()].copy_from_slice(name_b);
    let rc = libc::mknod(
        path.as_ptr().cast(),
        libc::S_IFCHR | mode as libc::mode_t,
        dev as libc::dev_t,
    );
    if rc != 0 {
        let errno = *libc::__errno_location();
        // An existing node (rerun into the same tmpfs) is fine.
        if errno != libc::EEXIST {
            return errno;
        }
    }
    // mknod applies the process umask (022 in a normal judger) — the nodes
    // must be world-writable for the unprivileged program, so chmod after.
    if libc::chmod(path.as_ptr().cast(), mode as libc::mode_t) != 0 {
        return *libc::__errno_location();
    }
    0
}

fn errno_or_zero(rc: libc::c_int) -> libc::c_int {
    if rc == 0 {
        0
    } else {
        unsafe { *libc::__errno_location() }
    }
}
