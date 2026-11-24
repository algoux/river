//! The child sequence after clone3 (design.md §5) — bare syscalls only.
//!
//! The calling process is multi-threaded; at clone time another thread may
//! hold any lock, so between clone3 and execve this code must not allocate,
//! lock, or otherwise touch Rust/Python runtime state. Every string is
//! pre-serialized in `ChildSpec` (or a fixed literal), every fd is inherited.

use std::ffi::CStr;

use super::{caps, idmap, landlock, mount, seccomp, ChildSpec, Step, SyncMsg};

/// Host device nodes bound into every sandbox (design.md §5
/// `child.mount.dev_*`): userns-created `mknod` nodes are unusable, so the
/// host ones are bind-mounted and only then get `NOSUID`.
const DEV_BINDS: [(&CStr, &CStr); 5] = [
    (c"/dev/null", c"./dev/null"),
    (c"/dev/zero", c"./dev/zero"),
    (c"/dev/full", c"./dev/full"),
    (c"/dev/random", c"./dev/random"),
    (c"/dev/urandom", c"./dev/urandom"),
];

/// Entry point in the freshly cloned child; never returns.
///
/// # Safety
/// Must be called only from the child side of a raw `SYS_clone3` (return
/// value 0) with `spec` pointing at `ChildSpec` memory owned by the parent
/// stack frame that performed the clone.
pub unsafe fn entry(spec: &ChildSpec) -> ! {
    // SAFETY: the whole function is child-only bare syscalls.
    unsafe { run(spec) }
}

unsafe fn run(spec: &ChildSpec) -> ! {
    // a: PDEATHSIG first (design.md §5 `child.pdeathsig`).
    // SAFETY: prctl with a scalar argument.
    let r = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong, 0, 0, 0) };
    if r < 0 {
        // SAFETY: reports (step, errno) on the sync socket and exits.
        unsafe { fail(spec, Step::Pdeathsig, errno()) };
    }
    // SAFETY: getppid(2) has no preconditions.
    if !unsafe { parent_is_alive(spec) } {
        // The parent died between clone3 and the prctl; nobody would read
        // the sync socket anyway.
        // SAFETY: exits without flushing anything.
        unsafe { libc::_exit(42) };
    }

    // b: idmap — setgroups deny, then uid_map/gid_map (design.md §5).
    // SAFETY: bare open/write/close on fixed /proc paths.
    let e = unsafe { idmap::write_maps(&spec.idmap) };
    if e != 0 {
        // SAFETY: reports (step, errno) on the sync socket and exits.
        unsafe { fail(spec, Step::Idmap, e) };
    }

    // c: wait for "go" — the parent parks us in the run cgroup (design.md
    //    §3 step 6) before handing control over.
    let mut go = [0u8; 1];
    // SAFETY: plain read(2) on the inherited sync socket.
    let n = unsafe {
        libc::read(spec.sync_fd, go.as_mut_ptr() as *mut libc::c_void, go.len())
    };
    if n != 1 {
        // Parent gone or sync closed: there is nobody to report to.
        // SAFETY: exits without flushing anything.
        unsafe { libc::_exit(42) };
    }

    unsafe { debug(spec, c"[river child] idmap done, go received\n") };

    // d: mount sequence -> pivot_root (design.md §5).
    // SAFETY: every call below is a bare mount-related syscall.
    unsafe {
        // child.mount.private: no propagation to or from the host.
        let e = mount::mount_rec_private();
        if e != 0 {
            fail(spec, Step::MountPrivate, e);
        }
        debug(spec, c"[river child] private ok\n");
        // child.mount.bind_root (design.md §5 `bind_root` + `root_attr`,
        // merged): clone the rootfs as a *detached* mount, set
        // RDONLY|NOSUID|NODEV while it is still detached — mount_setattr on
        // an attached bind clone of a host-owned tree answers EINVAL, and
        // old-style bind+remount silently ignores the flags on this kernel —
        // then attach it over itself. This also makes the rootfs a mount
        // point, which pivot_root requires.
        let mfd = mount::open_tree_clone(&spec.rootfs_path, true);
        if mfd < 0 {
            fail(spec, Step::MountBindRoot, -mfd);
        }
        let e = mount::mount_setattr(
            mfd,
            mount::MOUNT_ATTR_RDONLY | mount::MOUNT_ATTR_NOSUID | mount::MOUNT_ATTR_NODEV,
            true,
        );
        if e != 0 {
            libc::close(mfd);
            fail(spec, Step::MountBindRoot, e);
        }
        let e = mount::move_mount_fd(mfd, &spec.rootfs_path);
        libc::close(mfd);
        if e != 0 {
            fail(spec, Step::MountBindRoot, e);
        }
        // Re-enter by absolute path: walking INTO the dir crosses into the
        // new mount; a chdir(".") would stay on the old one.
        let e = libc::chdir(spec.rootfs_path.as_ptr());
        if e < 0 {
            fail(spec, Step::MountBindRoot, errno());
        }
        debug(spec, c"[river child] root bind + rdonly done\n");

        // child.mount.proc: fresh procfs for the new pid namespace (the
        // child is pid 1 of that namespace, so a userns may mount it).
        let e = mount::mount(
            c"proc",
            c"./proc",
            Some(c"proc"),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            None,
        );
        if e != 0 {
            fail(spec, Step::MountProc, e);
        }
        // child.mount.devpts: a private instance, then /dev/ptmx bound from
        // *that instance's* ptmx node (ptmxmode=0666 created it): binding the
        // host's ptmx would link /dev/ptmx to the host devpts, and openpty
        // could never reach the slave.
        let e = mount::mount(
            c"devpts",
            c"./dev/pts",
            Some(c"devpts"),
            libc::MS_NOSUID,
            Some(c"newinstance,ptmxmode=0666,mode=0620"),
        );
        if e != 0 {
            fail(spec, Step::MountDevpts, e);
        }
        let e = mount::bind(c"./dev/pts/ptmx", c"./dev/ptmx");
        if e != 0 {
            fail(spec, Step::MountDevpts, e);
        }
        // child.mount.shm / mqueue / tmp.
        let e = mount::mount(c"tmpfs", c"./dev/shm", Some(c"tmpfs"), 0, Some(c"mode=1777"));
        if e != 0 {
            fail(spec, Step::MountShm, e);
        }
        let e = mount::mount(c"mqueue", c"./dev/mqueue", Some(c"mqueue"), 0, None);
        if e != 0 {
            fail(spec, Step::MountMqueue, e);
        }
        let e = mount::mount(c"tmpfs", c"./tmp", Some(c"tmpfs"), 0, Some(c"mode=1777"));
        if e != 0 {
            fail(spec, Step::MountTmp, e);
        }
        // child.mount.dev_*: bind each host device node through the same
        // detached-clone dance, with NOSUID (NODEV would make the devices
        // unusable, design.md §5).
        for &(src, dst) in &DEV_BINDS {
            let fd = mount::open_tree_clone(src, false);
            if fd < 0 {
                fail(spec, Step::MountDev, -fd);
            }
            let e = mount::mount_setattr(fd, mount::MOUNT_ATTR_NOSUID, false);
            if e != 0 {
                libc::close(fd);
                fail(spec, Step::MountDev, e);
            }
            let e = mount::move_mount_fd(fd, dst);
            libc::close(fd);
            if e != 0 {
                fail(spec, Step::MountDev, e);
            }
        }
        // child.mount.work: the host /work bind, writable, NOSUID|NODEV
        // (executables built in /work must stay runnable).
        let fd = mount::open_tree_clone(&spec.work_src, false);
        if fd < 0 {
            fail(spec, Step::MountWork, -fd);
        }
        let e = mount::mount_setattr(fd, mount::MOUNT_ATTR_NOSUID | mount::MOUNT_ATTR_NODEV, false);
        if e != 0 {
            libc::close(fd);
            fail(spec, Step::MountWork, e);
        }
        let e = mount::move_mount_fd(fd, c"./work");
        libc::close(fd);
        if e != 0 {
            fail(spec, Step::MountWork, e);
        }
        debug(spec, c"[river child] proc/devpts/dev/work mounts done\n");

        // child.mount.sys: fresh sysfs, read-only. The user namespace owns
        // the new network namespace, so mounting sysfs is allowed; failure
        // is a setup failure (design.md §5). Kernels ≥ 6.6 auto-mount
        // cgroup2 at /sys/fs/cgroup when sysfs is mounted in a user
        // namespace, and that view would leak the caller's cgroup subtree —
        // a read-only tmpfs over ./sys/fs covers it.
        let e = mount::mount(
            c"sysfs",
            c"./sys",
            Some(c"sysfs"),
            libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            None,
        );
        if e != 0 {
            fail(spec, Step::MountSys, e);
        }
        let e = mount::mount(
            c"tmpfs",
            c"./sys/fs",
            Some(c"tmpfs"),
            libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            Some(c"mode=755"),
        );
        if e != 0 {
            fail(spec, Step::MountSys, e);
        }

        // child.mount.pivot: swap the roots, then drop the old one. The old
        // root ends up stacked on the new root at "."; `umount2(".", MNT_DETACH)`
        // reveals the new root (design.md §5).
        let e = mount::pivot_root_dot();
        if e != 0 {
            fail(spec, Step::MountPivot, e);
        }
        let e = libc::chdir(c"/".as_ptr());
        if e < 0 {
            fail(spec, Step::MountPivot, errno());
        }
        let e = mount::umount2_dot_detach();
        if e != 0 {
            fail(spec, Step::MountPivot, e);
        }
        debug(spec, c"[river child] pivot done\n");
    }

    // e: lo up (design.md §5 `child.net.lo`) — before the caps drop.
    // SAFETY: socket(2) + ioctl(2) with a stack `ifreq`.
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if sock < 0 {
            fail(spec, Step::NetLo, errno());
        }
        let mut ifr: libc::ifreq = std::mem::zeroed();
        for (dst, src) in ifr.ifr_name.iter_mut().zip(b"lo\0".iter()) {
            *dst = *src as libc::c_char;
        }
        let r = libc::ioctl(sock, libc::SIOCGIFFLAGS as libc::c_ulong, &mut ifr);
        if r < 0 {
            let e = errno();
            libc::close(sock);
            fail(spec, Step::NetLo, e);
        }
        ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
        let r = libc::ioctl(sock, libc::SIOCSIFFLAGS as libc::c_ulong, &ifr);
        libc::close(sock);
        if r < 0 {
            fail(spec, Step::NetLo, errno());
        }
    }

    // f: rlimits (design.md §5 `child.rlimit.*`, §6) — only the limits the
    //    caller passed; RLIMIT_CPU carries the (soft, hard) pair, every
    //    other touched limit is soft=hard.
    // SAFETY: bare setrlimit(2) on precomputed `ChildSpec` values.
    unsafe {
        if let Some((soft, hard)) = spec.rlimits.cpu {
            let rl = libc::rlimit {
                rlim_cur: soft,
                rlim_max: hard,
            };
            if libc::setrlimit(libc::RLIMIT_CPU, &rl) != 0 {
                fail(spec, Step::RlimitCpu, errno());
            }
        }
        if let Some(v) = spec.rlimits.fsize {
            let rl = libc::rlimit { rlim_cur: v, rlim_max: v };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &rl) != 0 {
                fail(spec, Step::RlimitFsize, errno());
            }
        }
        if let Some(v) = spec.rlimits.nproc {
            let rl = libc::rlimit { rlim_cur: v, rlim_max: v };
            if libc::setrlimit(libc::RLIMIT_NPROC, &rl) != 0 {
                fail(spec, Step::RlimitNproc, errno());
            }
        }
        if let Some(v) = spec.rlimits.nofile {
            let rl = libc::rlimit { rlim_cur: v, rlim_max: v };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &rl) != 0 {
                fail(spec, Step::RlimitNofile, errno());
            }
        }
        if let Some(v) = spec.rlimits.stack {
            let rl = libc::rlimit { rlim_cur: v, rlim_max: v };
            if libc::setrlimit(libc::RLIMIT_STACK, &rl) != 0 {
                fail(spec, Step::RlimitStack, errno());
            }
        }
        if let Some(v) = spec.rlimits.as_bytes {
            let rl = libc::rlimit { rlim_cur: v, rlim_max: v };
            if libc::setrlimit(libc::RLIMIT_AS, &rl) != 0 {
                fail(spec, Step::RlimitAs, errno());
            }
        }
        debug(spec, c"[river child] rlimits done\n");
    }

    // g: caps -> no_new_privs -> Landlock -> seccomp (design.md §5).
    // SAFETY: bare prctl/capset and the allocation-free landlock/seccomp steps.
    unsafe {
        let e = caps::drop_all();
        if e != 0 {
            fail(spec, Step::Caps, e);
        }
        let r = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1 as libc::c_ulong, 0, 0, 0);
        if r < 0 {
            fail(spec, Step::Nnp, errno());
        }
        debug(spec, c"[river child] caps + nnp done\n");

        if let Some(masks) = &spec.landlock_masks {
            let e = landlock::child_apply(masks);
            if e != 0 {
                fail(spec, Step::Landlock, e);
            }
        }
        for program in &spec.seccomp_programs {
            let e = seccomp::install(program);
            if e != 0 {
                fail(spec, Step::Seccomp, e);
            }
        }
        debug(spec, c"[river child] landlock + seccomp done\n");
    }

    // h: chdir(cwd) — the only directory that can be missing at this point.
    // SAFETY: chdir(2) on `ChildSpec` memory.
    let e = unsafe { libc::chdir(spec.cwd.as_ptr()) };
    if e < 0 {
        // SAFETY: reports (step, errno) on the sync socket and exits.
        unsafe { fail(spec, Step::Chdir, errno()) };
    }

    // i: stdio (design.md §5 `child.stdio`).
    // SAFETY: open/dup2 on `ChildSpec` paths and fds.
    let e = unsafe { set_up_stdio(spec) };
    if e != 0 {
        // SAFETY: reports (step, errno) on the sync socket and exits.
        unsafe { fail(spec, Step::Stdio, e) };
    }

    // j: execve. A successful execve never returns; the CLOEXEC sync socket
    // closes and the parent reads EOF as "exec'd". Any return is a failure.
    // SAFETY: execve(2) with the pre-serialized argv/envp arrays.
    unsafe {
        let mut last_errno = libc::ENOENT;
        for candidate in &spec.exec_candidates {
            libc::execve(
                candidate.as_ptr(),
                spec.argv_ptrs.as_ptr() as *const *const libc::c_char,
                spec.envp_ptrs.as_ptr() as *const *const libc::c_char,
            );
            last_errno = errno();
        }
        fail(spec, Step::Execve, last_errno);
    }
}

/// stdin/stdout/stderr (design.md §5 `child.stdio`): `stdin_file` is opened
/// relative to the (already chdir'd) cwd; outputs go to `*_file` or to the
/// inherited pipe write ends; a missing input defaults to /dev/null.
///
/// # Safety
/// Child-only: open(2)/dup2(2) on `ChildSpec` memory.
unsafe fn set_up_stdio(spec: &ChildSpec) -> i32 {
    // SAFETY: all branches only use open(2)/dup2(2) on spec values.
    unsafe {
        // stdin
        if let Some(file) = &spec.stdin_file {
            let fd = libc::open(file.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
            if fd < 0 {
                return errno();
            }
            let r = libc::dup2(fd, 0);
            libc::close(fd);
            if r < 0 {
                return errno();
            }
        } else if spec.stdin_pipe_r >= 0 {
            if libc::dup2(spec.stdin_pipe_r, 0) < 0 {
                return errno();
            }
        } else {
            let fd = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
            if fd < 0 {
                return errno();
            }
            let r = libc::dup2(fd, 0);
            libc::close(fd);
            if r < 0 {
                return errno();
            }
        }
        // stdout
        if let Some(file) = &spec.stdout_file {
            let fd = libc::open(
                file.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC,
                0o644,
            );
            if fd < 0 {
                return errno();
            }
            let r = libc::dup2(fd, 1);
            libc::close(fd);
            if r < 0 {
                return errno();
            }
        } else if spec.stdout_pipe_w >= 0 {
            if libc::dup2(spec.stdout_pipe_w, 1) < 0 {
                return errno();
            }
        } else {
            let fd = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
            if fd < 0 {
                return errno();
            }
            let r = libc::dup2(fd, 1);
            libc::close(fd);
            if r < 0 {
                return errno();
            }
        }
        // stderr
        if let Some(file) = &spec.stderr_file {
            let fd = libc::open(
                file.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC,
                0o644,
            );
            if fd < 0 {
                return errno();
            }
            let r = libc::dup2(fd, 2);
            libc::close(fd);
            if r < 0 {
                return errno();
            }
        } else if spec.stderr_pipe_w >= 0 {
            if libc::dup2(spec.stderr_pipe_w, 2) < 0 {
                return errno();
            }
        } else {
            let fd = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
            if fd < 0 {
                return errno();
            }
            let r = libc::dup2(fd, 2);
            libc::close(fd);
            if r < 0 {
                return errno();
            }
        }
        0
    }
}

/// The design's "getppid() ≠ expected parent → exit" check, made usable under
/// `CLONE_NEWPID`: the caller lives outside the new pid namespace, so
/// `getppid()` always reads 0 there. The host-side `/proc` (still mounted at
/// this point, pre-pivot) reports the real `PPid:`.
///
/// # Safety
/// Child-only: open/read/close on a fixed path with a stack buffer.
unsafe fn parent_is_alive(spec: &ChildSpec) -> bool {
    const STATUS: &CStr = c"/proc/self/status";
    // SAFETY: plain open(2) on a fixed /proc path.
    let fd = unsafe { libc::open(STATUS.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return true; // cannot tell; the go-EOF handshake still guards this window
    }
    let mut buf = [0u8; 2048];
    let mut len = 0usize;
    while len < buf.len() {
        // SAFETY: read(2) into the remainder of a private stack buffer.
        let n = unsafe {
            libc::read(
                fd,
                buf[len..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - len,
            )
        };
        if n <= 0 {
            break;
        }
        len += n as usize;
    }
    // SAFETY: the fd was only read.
    unsafe { libc::close(fd) };

    // status starts with "Name:", so the needle always has its newline.
    let needle = b"\nPPid:\t";
    let Some(mut i) = buf[..len]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|i| i + needle.len())
    else {
        return true; // odd status file: assume the parent lives
    };
    let mut value: libc::pid_t = 0;
    let mut any = false;
    while i < len && buf[i].is_ascii_digit() {
        any = true;
        value = value.wrapping_mul(10).wrapping_add((buf[i] - b'0') as libc::pid_t);
        i += 1;
    }
    any && value == spec.expected_ppid
}

/// Reports the failed step on the sync socket and exits the child; the
/// parent turns the pair into `ExecSetupError` (design.md §5).
///
/// # Safety
/// Child-only, and it never returns.
unsafe fn fail(spec: &ChildSpec, step: Step, errno: i32) -> ! {
    let msg = SyncMsg {
        step: step as u32,
        errno,
    };
    // SAFETY: one write(2) on the inherited socket, then _exit(2).
    unsafe {
        let _ = libc::write(
            spec.sync_fd,
            &msg as *const SyncMsg as *const libc::c_void,
            std::mem::size_of::<SyncMsg>(),
        );
        libc::_exit(42);
    }
}

/// `RIVER_LOG=debug` breadcrumb on the inherited stderr.
///
/// # Safety
/// Child-only: one write(2) of a fixed literal.
unsafe fn debug(spec: &ChildSpec, msg: &CStr) {
    if spec.debug {
        // SAFETY: write(2) on fd 2 with a fixed literal.
        unsafe {
            let _ = libc::write(2, msg.as_ptr() as *const libc::c_void, msg.to_bytes().len());
        }
    }
}

fn errno() -> i32 {
    // SAFETY: reads the thread-local errno cell.
    unsafe { *libc::__errno_location() }
}
