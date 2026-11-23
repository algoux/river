//! uid/gid mapping (design.md §5 `child.idmap`, §9).
//!
//! The child is the user-namespace creator and holds CAP_SETUID/SETGID
//! inside it, so it writes its own maps without parent involvement. The
//! parent pre-formats the map lines; the child only opens, writes and closes.

use std::ffi::CStr;

/// `/proc/self/uid_map` and `gid_map` contents, pre-formatted by the parent
/// (`"0 <euid> 1"` and `"0 <egid> 1"`).
pub struct Idmap {
    pub uid_line: Vec<u8>,
    pub gid_line: Vec<u8>,
}

/// Writes `/proc/self/setgroups`=deny, then `uid_map`, then `gid_map`
/// (design.md §5). Returns 0 on success, otherwise the failed step's errno.
///
/// # Safety
/// Child-only: open/write/close on fixed `/proc/self` paths; no allocation.
pub unsafe fn write_maps(map: &Idmap) -> i32 {
    // SAFETY: all callees only issue raw syscalls on fixed paths.
    unsafe {
        let e = write_proc_file(c"/proc/self/setgroups", b"deny\n");
        if e != 0 {
            return e;
        }
        let e = write_proc_file(c"/proc/self/uid_map", &map.uid_line);
        if e != 0 {
            return e;
        }
        write_proc_file(c"/proc/self/gid_map", &map.gid_line)
    }
}

/// Opens `path` (`O_WRONLY|O_CLOEXEC`), writes all of `data`, closes the fd.
unsafe fn write_proc_file(path: &CStr, data: &[u8]) -> i32 {
    // SAFETY: fixed /proc paths; the fd is closed before returning.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        // SAFETY: reads the thread-local errno cell.
        return unsafe { *libc::__errno_location() };
    }
    // SAFETY: writes into /proc files only; no locks involved.
    let r = unsafe { write_all(fd, data) };
    unsafe { libc::close(fd) };
    r
}

/// write(2) loop with EINTR retry; 0 on success, otherwise the errno.
unsafe fn write_all(fd: libc::c_int, data: &[u8]) -> i32 {
    let mut done = 0;
    while done < data.len() {
        // SAFETY: plain write(2) on a private buffer slice.
        let r = unsafe {
            libc::write(
                fd,
                data[done..].as_ptr() as *const libc::c_void,
                data.len() - done,
            )
        };
        if r < 0 {
            // SAFETY: reads the thread-local errno cell.
            let e = unsafe { *libc::__errno_location() };
            if e == libc::EINTR {
                continue;
            }
            return e;
        }
        done += r as usize;
    }
    0
}
