#![allow(unsafe_op_in_unsafe_fn)]

use std::ffi::{CStr, CString};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::path::{Path, PathBuf};

use super::mount;
use super::stdio::StdioSet;

const SYSTEM_DIRS: &[&str] = &["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"];

pub(crate) struct Child {
    pub(crate) pid: libc::pid_t,
    watchdog: libc::pid_t,
    _loop: Option<LoopGuard>,
}

impl Child {
    pub(crate) fn disarm(mut self) {
        if self.watchdog > 0 {
            unsafe { libc::kill(self.watchdog, libc::SIGKILL) };
            let mut status = 0;
            unsafe { libc::waitpid(self.watchdog, &mut status, 0) };
        }
        self.watchdog = 0;
        self._loop = None;
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        if self.watchdog > 0 {
            unsafe { abort_spawn(self.pid, self.watchdog) };
            self.watchdog = 0;
        }
    }
}

unsafe fn abort_spawn(supervisor: libc::pid_t, watchdog: libc::pid_t) {
    libc::kill(-supervisor, libc::SIGKILL);
    let mut status = 0;
    loop {
        let rc = libc::waitpid(supervisor, &mut status, 0);
        if rc == supervisor {
            break;
        }
        if errno() == libc::EINTR {
            continue;
        }
        break;
    }
    if watchdog > 0 {
        libc::kill(watchdog, libc::SIGKILL);
        let mut wstatus = 0;
        libc::waitpid(watchdog, &mut wstatus, 0);
    }
}

struct LoopGuard {
    loop_fd: libc::c_int,
    mount_point: PathBuf,
}

impl Drop for LoopGuard {
    fn drop(&mut self) {
        let point = std::ffi::CString::new(
            self.mount_point
                .as_os_str()
                .to_str()
                .map(|s| s.to_string())
                .unwrap_or_default(),
        )
        .ok();
        if let Some(point) = point {
            unsafe {
                libc::umount2(point.as_ptr(), libc::MNT_DETACH);
            }
        }
        if self.loop_fd >= 0 {
            unsafe {
                libc::ioctl(self.loop_fd, LOOP_CLR_FD, 0);
                libc::close(self.loop_fd);
            }
        }
    }
}

const LOOP_SET_FD: libc::c_ulong = 0x4C00;
const LOOP_CLR_FD: libc::c_ulong = 0x4C01;
const LOOP_CTL_GET_FREE: libc::c_ulong = 0x4C82;

const SQUASHFS_MAGIC: [u8; 4] = *b"hsqs";

fn setup_loop_mount(image: &Path, mount_point: &Path) -> io::Result<LoopGuard> {
    let cstr = |p: &Path| -> io::Result<std::ffi::CString> {
        std::ffi::CString::new(
            p.as_os_str()
                .to_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "non-UTF8 path"))?,
        )
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))
    };
    let ctl = unsafe {
        libc::open(
            c"/dev/loop-control".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if ctl < 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no /dev/loop-control: squashfs rootfs needs loop device support",
        ));
    }
    let idx = unsafe { libc::ioctl(ctl, LOOP_CTL_GET_FREE, 0) };
    unsafe { libc::close(ctl) };
    if idx < 0 {
        return Err(io::Error::last_os_error());
    }
    let loop_path = format!("/dev/loop{idx}");
    let loop_c = std::ffi::CString::new(loop_path.clone()).unwrap();
    let loop_fd = unsafe { libc::open(loop_c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if loop_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let img_c = cstr(image)?;
    let img_fd = unsafe { libc::open(img_c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if img_fd < 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(loop_fd) };
        return Err(err);
    }
    let rc = unsafe { libc::ioctl(loop_fd, LOOP_SET_FD, img_fd as libc::c_ulong) };
    unsafe { libc::close(img_fd) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(loop_fd) };
        return Err(err);
    }
    let point_c = cstr(mount_point)?;
    std::fs::create_dir_all(mount_point)?;
    let rc = unsafe {
        libc::mount(
            loop_c.as_ptr(),
            point_c.as_ptr(),
            c"squashfs".as_ptr(),
            libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::ioctl(loop_fd, LOOP_CLR_FD, 0);
            libc::close(loop_fd);
        }
        return Err(err);
    }
    Ok(LoopGuard {
        loop_fd,
        mount_point: mount_point.to_path_buf(),
    })
}

struct MountPlan {
    root: CString,
    oldroot: CString,
    proc_dir: CString,
    dev_dir: CString,
    cwd_dir: CString,
    workdir: CString,
    rootfs_overlay: Option<CString>,
    binds: Vec<(CString, CString)>,
    file_binds: Vec<(CString, CString, CString)>,
    exec_path: CString,
    cwd_preferred: CString,
    cwd_fallback: CString,
}

impl MountPlan {
    fn build(
        workdir: &Path,
        rootfs: Option<&Path>,
        runtimes: &[PathBuf],
        executable: &Path,
        cwd_rel: Option<&str>,
    ) -> io::Result<(Self, Option<LoopGuard>)> {
        let cstr = |p: &Path| {
            CString::new(p.as_os_str().to_str().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "non-UTF8 sandbox path")
            })?)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in sandbox path"))
        };
        let root_path = workdir.join("root");
        let root = cstr(&root_path)?;
        let oldroot = cstr(&root_path.join(".oldroot"))?;
        let proc_dir = cstr(&root_path.join("proc"))?;
        let dev_dir = cstr(&root_path.join("dev"))?;
        let cwd_dir = cstr(&root_path.join("cwd"))?;
        let workdir_c = cstr(workdir)?;

        let mut loop_guard: Option<LoopGuard> = None;
        let rootfs_overlay = match rootfs {
            Some(fs) => {
                let bad = |p: &Path, what: &str| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "rootfs {what} must not contain commas or colons: {}",
                            p.display()
                        ),
                    )
                };
                let fs_str = fs.to_str().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "non-UTF8 rootfs path")
                })?;
                let md = std::fs::symlink_metadata(fs)?;
                let lower: String = if md.is_file() {
                    let mut magic = [0u8; 4];
                    std::fs::File::open(fs)?.read_exact(&mut magic)?;
                    if magic != SQUASHFS_MAGIC {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!(
                                "rootfs image is not a squashfs image (bad magic): {}",
                                fs.display()
                            ),
                        ));
                    }
                    let mount_point = workdir.join("sqfs");
                    let guard = setup_loop_mount(fs, &mount_point)?;
                    let lower = mount_point
                        .to_str()
                        .ok_or_else(|| bad(&mount_point, "workdir path"))?
                        .to_string();
                    loop_guard = Some(guard);
                    lower
                } else {
                    if fs_str.contains(',') || fs_str.contains(':') {
                        return Err(bad(fs, "path"));
                    }
                    fs_str.to_string()
                };
                let upper = workdir.join("upper");
                let work = workdir.join("ovl-work");
                if upper.to_str().map(|s| s.contains(',') || s.contains(':')) == Some(true)
                    || work.to_str().map(|s| s.contains(',') || s.contains(':')) == Some(true)
                {
                    return Err(bad(&upper, "workdir path"));
                }
                std::fs::create_dir_all(&upper)?;
                std::fs::create_dir_all(&work)?;
                Some(CString::new(format!(
                    "lowerdir={lower},upperdir={},workdir={}",
                    upper.display(),
                    work.display()
                ))?)
            }
            None => None,
        };

        let mut binds: Vec<(CString, CString)> = Vec::new();
        let mut seen: Vec<String> = Vec::new();
        let mut push_bind = |src: &Path, abs: &str| -> io::Result<()> {
            if seen.iter().any(|s| s == abs) {
                return Ok(());
            }
            let src_c = cstr(src)?;
            let dst = format!("{}{}", root.to_str().unwrap(), abs);
            binds.push((src_c, CString::new(dst).unwrap()));
            seen.push(abs.to_string());
            Ok(())
        };
        if rootfs.is_none() {
            for dir in SYSTEM_DIRS {
                let p = Path::new(dir);
                if p.exists() {
                    push_bind(p, dir)?;
                }
            }
        }
        for rt in runtimes {
            let abs = rt.to_str().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "non-UTF8 runtime path")
            })?;
            if !abs.starts_with('/') {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("runtime path must be absolute: {abs}"),
                ));
            }
            if abs == "/" {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "runtime \"/\" is refused: it would expose the whole host",
                ));
            }
            push_bind(rt, abs)?;
        }

        let (file_binds, exec_path) = if rootfs.is_some() {
            if !executable.is_absolute() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "executable must be an absolute path inside the rootfs: {}",
                        executable.display()
                    ),
                ));
            }
            (Vec::new(), cstr(executable)?)
        } else {
            if executable.is_absolute() && !executable.exists() {
                return Err(io::Error::from_raw_os_error(libc::ENOENT));
            }
            let visible =
                !executable.is_absolute() || seen.iter().any(|abs| executable.starts_with(abs));
            if visible {
                (Vec::new(), cstr(executable)?)
            } else {
                let name = executable
                    .file_name()
                    .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))?;
                let sandbox = format!(
                    "/cwd/.river/{}",
                    name.to_str().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "non-UTF8 executable name")
                    })?
                );
                let host_dst = format!("{}{}", root.to_str().unwrap(), sandbox);
                let dir = format!("{}{}", root.to_str().unwrap(), "/cwd/.river");
                (
                    vec![(
                        cstr(executable)?,
                        CString::new(dir).unwrap(),
                        CString::new(host_dst).unwrap(),
                    )],
                    CString::new(sandbox).unwrap(),
                )
            }
        };

        let preferred = match cwd_rel {
            Some(rel) => format!("/cwd/{}", rel.trim_start_matches('/')),
            None => "/cwd".to_string(),
        };
        Ok((
            MountPlan {
                root,
                oldroot,
                proc_dir,
                dev_dir,
                cwd_dir,
                workdir: workdir_c,
                rootfs_overlay,
                binds,
                file_binds,
                exec_path,
                cwd_preferred: CString::new(preferred).unwrap(),
                cwd_fallback: CString::new("/cwd").unwrap(),
            },
            loop_guard,
        ))
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn(
    executable: &Path,
    args: &[String],
    workdir: &Path,
    rootfs: Option<&Path>,
    runtimes: &[PathBuf],
    cwd_rel: Option<&str>,
    env_vars: &[(String, String)],
    cgroup_procs: Option<&CStr>,
    limits: ChildLimits,
    seccomp: Option<&crate::backend::linux::seccomp::Filters>,
    stdio: &mut StdioSet,
) -> io::Result<Child> {
    let (plan, loop_guard) = MountPlan::build(workdir, rootfs, runtimes, executable, cwd_rel)?;

    let mut argv_c = Vec::with_capacity(args.len() + 1);
    argv_c.push(plan.exec_path.clone());
    for a in args {
        argv_c.push(CString::new(a.as_str())?);
    }
    let envp_c: Vec<CString> = env_vars
        .iter()
        .map(|(k, v)| CString::new(format!("{k}={v}")))
        .collect::<Result<_, _>>()?;
    let mut argv_ptrs: Vec<*const libc::c_char> = argv_c.iter().map(|s| s.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let mut envp_ptrs: Vec<*const libc::c_char> = envp_c.iter().map(|s| s.as_ptr()).collect();
    envp_ptrs.push(std::ptr::null());

    let (ready_read, ready_write) = ready_pipe()?;
    let (child_in, child_out, child_err) = stdio.child_fds();

    let fork_rc = unsafe { libc::fork() };
    if fork_rc < 0 {
        return Err(io::Error::last_os_error());
    }

    if fork_rc == 0 {
        unsafe {
            supervise(
                &plan,
                (child_in, child_out, child_err),
                ready_write.as_raw_fd(),
                &argv_ptrs,
                &envp_ptrs,
                cgroup_procs,
                limits,
                seccomp,
            );
        }
    }

    let watchdog = unsafe { libc::fork() };
    if watchdog < 0 {
        let err = io::Error::last_os_error();
        unsafe { abort_spawn(fork_rc, -1) };
        return Err(err);
    }
    if watchdog == 0 {
        unsafe { watchdog_loop(fork_rc) };
    }

    if let Err(e) = stdio.after_fork() {
        unsafe { abort_spawn(fork_rc, watchdog) };
        return Err(e);
    }
    drop(ready_write);
    let mut reader = unsafe { std::fs::File::from_raw_fd(ready_read.into_raw_fd()) };
    let mut report = Vec::new();
    if let Err(e) = reader.read_to_end(&mut report) {
        unsafe { abort_spawn(fork_rc, watchdog) };
        return Err(e);
    }
    drop(reader);
    if !report.starts_with(b"ok\n") || report.len() > 3 {
        let code = if report.starts_with(b"ok\n") {
            String::from_utf8_lossy(&report[3..]).trim().parse::<i32>()
        } else {
            String::from_utf8_lossy(&report).trim().parse::<i32>()
        }
        .unwrap_or(libc::EIO);
        unsafe { abort_spawn(fork_rc, watchdog) };
        return Err(io::Error::from_raw_os_error(code));
    }

    Ok(Child {
        pid: fork_rc,
        watchdog,
        _loop: loop_guard,
    })
}

fn ready_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((unsafe { OwnedFd::from_raw_fd(fds[0]) }, unsafe {
        OwnedFd::from_raw_fd(fds[1])
    }))
}

#[derive(Clone, Copy)]
pub(crate) struct ChildLimits {
    pub(crate) fsize_bytes: u64,
    pub(crate) nofile: u64,
    pub(crate) cpu_secs: Option<u64>,
    pub(crate) uid: libc::uid_t,
    pub(crate) gid: libc::gid_t,
}

unsafe fn clear_capabilities() -> libc::c_int {
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let mut header = CapHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let zero = CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    };
    let data = [zero, zero];
    let rc = libc::syscall(
        libc::SYS_capset,
        &mut header as *mut CapHeader,
        data.as_ptr(),
    );
    if rc != 0 { errno() } else { 0 }
}

unsafe fn apply_rlimits(limits: &ChildLimits) -> libc::c_int {
    let mut failed = 0;
    let mut set = |resource: libc::__rlimit_resource_t, cur: libc::rlim_t, max: libc::rlim_t| {
        let rl = libc::rlimit {
            rlim_cur: cur,
            rlim_max: max,
        };
        if libc::setrlimit(resource, &rl) != 0 && failed == 0 {
            failed = errno();
        }
    };
    set(libc::RLIMIT_CORE, 0, 0);
    set(libc::RLIMIT_NOFILE, limits.nofile, limits.nofile);
    set(libc::RLIMIT_FSIZE, limits.fsize_bytes, limits.fsize_bytes);
    if let Some(secs) = limits.cpu_secs {
        set(libc::RLIMIT_CPU, secs, secs.saturating_add(1));
    }
    failed
}

#[allow(clippy::too_many_arguments)]
unsafe fn supervise(
    plan: &MountPlan,
    stdio_fds: (libc::c_int, libc::c_int, libc::c_int),
    ready_write: libc::c_int,
    argv_ptrs: &[*const libc::c_char],
    envp_ptrs: &[*const libc::c_char],
    cgroup_procs: Option<&CStr>,
    limits: ChildLimits,
    seccomp: Option<&crate::backend::linux::seccomp::Filters>,
) -> ! {
    let (fd_in, fd_out, fd_err) = stdio_fds;
    libc::dup2(fd_in, libc::STDIN_FILENO);
    libc::dup2(fd_out, libc::STDOUT_FILENO);
    libc::dup2(fd_err, libc::STDERR_FILENO);
    if ready_write != 3 {
        libc::dup2(ready_write, 3);
    }
    libc::fcntl(3, libc::F_SETFD, libc::FD_CLOEXEC);
    if libc::close_range(4, libc::c_uint::MAX, 0) != 0 {
        fail(3, errno());
    }

    if libc::setsid() < 0 {
        fail(3, errno());
    }
    libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
    libc::signal(libc::SIGPIPE, libc::SIG_DFL);

    if let Some(procs) = cgroup_procs {
        let fd = libc::open(procs.as_ptr(), libc::O_WRONLY);
        if fd < 0 {
            fail(3, errno());
        }
        let mut buf = [0u8; 16];
        let mut n = buf.len();
        let mut v = libc::getpid() as u64;
        loop {
            n -= 1;
            buf[n] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        let wrote = libc::write(fd, buf[n..].as_ptr().cast(), buf.len() - n);
        if wrote != (buf.len() - n) as isize {
            let err = errno();
            libc::close(fd);
            fail(3, err);
        }
        libc::close(fd);
    }

    let flags = libc::CLONE_NEWNS
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWNET
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWUTS
        | libc::CLONE_NEWCGROUP;
    if libc::unshare(flags) != 0 {
        fail(3, errno());
    }
    if libc::sethostname(c"river".as_ptr(), 5) != 0 {
        fail(3, errno());
    }
    if libc::mount(
        std::ptr::null(),
        c"/".as_ptr(),
        std::ptr::null(),
        libc::MS_REC | libc::MS_PRIVATE,
        std::ptr::null(),
    ) != 0
    {
        fail(3, errno());
    }

    let err = mount::mkdir_p(&plan.root);
    if err != 0 {
        fail(3, err);
    }
    let err = mount::mount_tmpfs(&plan.root, c"mode=755", libc::MS_NOSUID | libc::MS_NODEV);
    if err != 0 {
        fail(3, err);
    }

    if let Some(options) = &plan.rootfs_overlay {
        if libc::mount(
            c"overlay".as_ptr(),
            plan.root.as_ptr(),
            c"overlay".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV,
            options.as_ptr().cast(),
        ) != 0
        {
            fail(3, errno());
        }
        for dir in [&plan.cwd_dir, &plan.proc_dir, &plan.dev_dir, &plan.oldroot] {
            let err = mount::mkdir_p(dir);
            if err != 0 {
                fail(3, err);
            }
        }
        for (_, dst) in &plan.binds {
            let err = mount::mkdir_p(dst);
            if err != 0 {
                fail(3, err);
            }
        }
        for (_, dir, _) in &plan.file_binds {
            let err = mount::mkdir_p(dir);
            if err != 0 {
                fail(3, err);
            }
        }
        if libc::mount(
            std::ptr::null(),
            plan.root.as_ptr(),
            std::ptr::null(),
            libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
            std::ptr::null(),
        ) != 0
        {
            fail(3, errno());
        }
    }

    let err = mount::mkdir_p(&plan.cwd_dir);
    if err != 0 {
        fail(3, err);
    }
    let err = mount::bind_rw_nosuid(&plan.workdir, &plan.cwd_dir);
    if err != 0 {
        fail(3, err);
    }
    if mount::mkdir_p(&plan.proc_dir) != 0 || mount::mkdir_p(&plan.dev_dir) != 0 {
        fail(3, errno());
    }
    for (src, dst) in &plan.binds {
        let err = mount::mkdir_p(dst);
        if err != 0 {
            fail(3, err);
        }
        let err = mount::bind_ro(src, dst);
        if err != 0 {
            fail(3, err);
        }
    }
    for (src, dir, dst) in &plan.file_binds {
        let err = mount::mkdir_p(dir);
        if err != 0 {
            fail(3, err);
        }
        let err = mount::create_file(dst, 0o755);
        if err != 0 {
            fail(3, err);
        }
        let err = mount::bind_ro(src, dst);
        if err != 0 {
            fail(3, err);
        }
    }
    let err = mount::mount_tmpfs(&plan.dev_dir, c"mode=755,size=1m", libc::MS_NOSUID);
    if err != 0 {
        fail(3, err);
    }
    for (name, major, minor, mode) in mount::DEV_NODES {
        let err = mount::make_device(&plan.dev_dir, name, *major, *minor, *mode);
        if err != 0 {
            fail(3, err);
        }
    }

    if mount::mkdir_p(&plan.oldroot) != 0 {
        fail(3, errno());
    }
    if libc::syscall(
        libc::SYS_pivot_root,
        plan.root.as_ptr(),
        plan.oldroot.as_ptr(),
    ) != 0
    {
        fail(3, errno());
    }
    if libc::chdir(c"/".as_ptr()) != 0 {
        fail(3, errno());
    }
    if libc::umount2(c"/.oldroot".as_ptr(), libc::MNT_DETACH) != 0 {
        fail(3, errno());
    }
    libc::rmdir(c"/.oldroot".as_ptr());

    if libc::write(3, b"ok\n".as_ptr().cast(), 3) != 3 {
        libc::_exit(127);
    }

    let pid = libc::fork();
    if pid < 0 {
        fail(3, errno());
    }
    if pid == 0 {
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
        if libc::mount(
            c"proc".as_ptr(),
            c"/proc".as_ptr(),
            c"proc".as_ptr(),
            0,
            std::ptr::null(),
        ) != 0
        {
            fail(3, errno());
        }
        if libc::setgroups(0, std::ptr::null()) != 0
            || libc::setgid(limits.gid) != 0
            || libc::setuid(limits.uid) != 0
        {
            fail(3, errno());
        }
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            fail(3, errno());
        }
        let cap_err = clear_capabilities();
        if cap_err != 0 {
            fail(3, cap_err);
        }
        let rlimit_err = apply_rlimits(&limits);
        if rlimit_err != 0 {
            fail(3, rlimit_err);
        }
        if let Some(prog) = seccomp
            && crate::backend::linux::seccomp::apply(prog) != 0
        {
            fail(3, errno());
        }
        if libc::chdir(plan.cwd_preferred.as_ptr()) != 0
            && libc::chdir(plan.cwd_fallback.as_ptr()) != 0
        {
            fail(3, errno());
        }
        libc::execvpe(argv_ptrs[0], argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
        fail(3, errno());
    }

    libc::close(3);
    let mut status: libc::c_int = 0;
    let mut rusage: libc::rusage = std::mem::zeroed();
    loop {
        let rc = libc::wait4(pid, &mut status, 0, &mut rusage);
        if rc == pid {
            break;
        }
        if rc < 0 && errno() == libc::EINTR {
            continue;
        }
        libc::_exit(125);
    }
    if libc::WIFEXITED(status) {
        libc::_exit(libc::WEXITSTATUS(status));
    }
    if libc::WIFSIGNALED(status) {
        libc::_exit(libc::WTERMSIG(status) + 128);
    }
    libc::_exit(125);
}

unsafe fn fail(ready_write: libc::c_int, err: libc::c_int) -> ! {
    let mut buf = [0u8; 16];
    let mut n = buf.len();
    let mut v = err;
    loop {
        n -= 1;
        buf[n] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    let _ = libc::write(ready_write, buf[n..].as_ptr().cast(), buf.len() - n);
    libc::_exit(127);
}

unsafe fn errno() -> libc::c_int {
    *libc::__errno_location()
}

unsafe fn watchdog_loop(supervisor_pid: libc::pid_t) -> ! {
    libc::close_range(3, libc::c_uint::MAX, 0);
    libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    let judger = libc::getppid();
    let tick = libc::timespec {
        tv_sec: 0,
        tv_nsec: 20_000_000,
    };
    loop {
        if libc::getppid() != judger {
            libc::kill(-supervisor_pid, libc::SIGKILL);
            libc::_exit(0);
        }
        libc::nanosleep(&tick, std::ptr::null_mut());
    }
}
