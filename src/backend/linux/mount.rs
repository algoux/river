#![allow(unsafe_op_in_unsafe_fn)]

use std::ffi::CStr;

pub(crate) const DEV_NODES: &[(&CStr, libc::c_uint, libc::c_uint, libc::mode_t)] = &[
    (c"null", 1, 3, 0o666),
    (c"zero", 1, 5, 0o666),
    (c"random", 1, 8, 0o666),
    (c"urandom", 1, 9, 0o666),
    (c"tty", 5, 0, 0o666),
];

pub(crate) unsafe fn mkdir_p(path: &CStr) -> libc::c_int {
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

pub(crate) unsafe fn bind_rw_nosuid(src: &CStr, dst: &CStr) -> libc::c_int {
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
        libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NODEV,
        std::ptr::null(),
    );
    errno_or_zero(rc)
}

pub(crate) unsafe fn make_device(
    dir: &CStr,
    name: &CStr,
    major: libc::c_uint,
    minor: libc::c_uint,
    mode: libc::mode_t,
) -> libc::c_int {
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
        if errno != libc::EEXIST {
            return errno;
        }
    }
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
