//! Process spawning (stage L3): two-level fork with namespaces and mounts.
//!
//! ```text
//! judger (python) --fork--> A (supervisor, still root)
//!                            ├─ setsid            (own process group = kill domain)
//!                            ├─ unshare(NEWNS|NEWPID|NEWNET|NEWIPC|NEWUTS)
//!                            ├─ build tmpfs root (+rootfs overlay) + bind
//!                            │   mounts, pivot_root
//!                            ├─ report "ok" on the ready pipe
//!                            └─ fork B, close ready pipe, wait4(B), _exit(code)
//!                                B: PDEATHSIG, fresh /proc, uid drop to leased uid,
//!                                   chdir, execvpe
//! ```
//!
//! Why two levels: `unshare(CLONE_NEWPID)` only affects **children**, so the
//! process that gets PID 1 in the new namespace is B. A stays outside that
//! namespace and reaps B, which lets the judger keep a single child (A) to
//! monitor — its `wait4` rusage aggregates the whole tree (A's waited
//! descendants included), and killing A kills the process group.
//!
//! Fork-safety rules, enforced by construction:
//! - every path/string the child side needs is built **before** the fork
//!   (`MountPlan`, `CString`s, NULL-terminated pointer arrays);
//! - A and B do only raw syscalls between fork and exec — no allocation, no
//!   std I/O, no panics;
//! - all stdio threads are started **after** the fork, in the judger only.
//!
//! The child-side functions are `unsafe fn` by design and call raw libc
//! entry points directly; wrapping every call in a second `unsafe {}` would
//! add noise without adding a safety boundary.
#![allow(unsafe_op_in_unsafe_fn)]

use std::ffi::{CStr, CString};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::path::{Path, PathBuf};

use super::mount;
use super::stdio::StdioSet;

/// System directories always exposed read-only inside the sandbox **when no
/// rootfs is given**: the dynamic loader, libc and a shell must be reachable
/// for ordinary programs to start at all. This mirrors the Windows backend's
/// "System32 is always readable" rule (DESIGN §4). With a caller-supplied
/// rootfs these are *not* mounted — the rootfs must be self-contained.
const SYSTEM_DIRS: &[&str] = &["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"];

/// A spawned child whose exec has been confirmed by the ready protocol.
pub(crate) struct Child {
    /// Supervisor pid (= its session/process-group id after `setsid`).
    pub(crate) pid: libc::pid_t,
    /// Judger-death watchdog pid (see `watchdog_loop`).
    watchdog: libc::pid_t,
    /// Loop-device guard for a squashfs-image rootfs: keeps the image
    /// attached and its squashfs mount alive for the run's duration; the
    /// mount is detached and the loop freed on drop (after the last
    /// collection/observation in the caller).
    _loop: Option<LoopGuard>,
}

impl Child {
    /// Normal end of a run: stop the watchdog, then reap it.
    pub(crate) fn disarm(mut self) {
        if self.watchdog > 0 {
            unsafe { libc::kill(self.watchdog, libc::SIGKILL) };
            let mut status = 0;
            unsafe { libc::waitpid(self.watchdog, &mut status, 0) };
        }
        // The supervisor itself was already reaped by the monitor; make the
        // watchdog a no-op from here on.
        self.watchdog = 0;
        // Dropping `_loop` here releases the squashfs mount + loop device.
        self._loop = None;
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        // Error path in the caller: the monitor never reaped the supervisor,
        // so its process group (the program tree) is still alive and no
        // watchdog will enforce limits any more. Kill it, reap it, then stop
        // the watchdog.
        if self.watchdog > 0 {
            unsafe { abort_spawn(self.pid, self.watchdog) };
            self.watchdog = 0;
        }
    }
}

/// Kill the supervisor's process group, reap it, and stop the watchdog.
///
/// Shared by **every** error path out of [`spawn`]: the supervisor (and the
/// program tree it leads) must not outlive a failed spawn, and the watchdog
/// must not keep polling a run that no longer exists.
///
/// Why it matters: an error that skips this leaves the supervisor
/// unreaped (a zombie that only the judge process' exit would clear) and
/// the watchdog alive. The program itself does not survive either way — the
/// pid namespace kills it when the supervisor exits — but the leaked
/// supervisor and watchdog are real, and they accumulate over a long-lived
/// judge.
///
/// A blocking waitpid is safe after SIGKILL (and returns ECHILD immediately
/// when the monitor already reaped the child).
///
/// # Safety
/// `supervisor` must be the pid of a child of the calling process (or an
/// already-reaped one, in which case waitpid reports ECHILD), and
/// `watchdog` must be a pid of a child of the calling process or <= 0.
unsafe fn abort_spawn(supervisor: libc::pid_t, watchdog: libc::pid_t) {
    // The supervisor leads its own process group: kill(-pgid) takes the
    // whole program tree with it.
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
        break; // ECHILD: already reaped by the monitor
    }
    if watchdog > 0 {
        libc::kill(watchdog, libc::SIGKILL);
        let mut wstatus = 0;
        libc::waitpid(watchdog, &mut wstatus, 0);
    }
}

/// Keeps one squashfs image attached to a loop device and mounted
/// read-only for a single run (host namespace, cleaned up on drop — the
/// sandbox's *own* mount tree is built privately in the supervisor and
/// inherits this mount through the fork).
struct LoopGuard {
    /// Open fd of the bound loop device (`LOOP_CLR_FD` needs it).
    loop_fd: libc::c_int,
    /// Squashfs mountpoint (detached on drop).
    mount_point: PathBuf,
}

impl Drop for LoopGuard {
    fn drop(&mut self) {
        // Best effort: detach the mount first (the overlay in the (by now
        // dead) private namespace held its own reference), then free the
        // loop. Any failure is recovered from — loop devices and mounts
        // leak nothing permanent once the fd closes.
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

/// `LOOP_SET_FD` / `LOOP_CLR_FD` / `LOOP_CTL_GET_FREE` ioctls (libc does
/// not export the loop constants on every target).
const LOOP_SET_FD: libc::c_ulong = 0x4C00;
const LOOP_CLR_FD: libc::c_ulong = 0x4C01;
const LOOP_CTL_GET_FREE: libc::c_ulong = 0x4C82;

/// Squashfs magic ("hsqs", little-endian superblock).
const SQUASHFS_MAGIC: [u8; 4] = *b"hsqs";

/// Attach a squashfs image to a free loop device and mount it read-only at
/// `mount_point` (host namespace; the supervisor's private copy inherits it
/// across the fork). Cleanup is `LoopGuard`'s job.
fn setup_loop_mount(image: &Path, mount_point: &Path) -> io::Result<LoopGuard> {
    let cstr = |p: &Path| -> io::Result<std::ffi::CString> {
        std::ffi::CString::new(
            p.as_os_str()
                .to_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "non-UTF8 path"))?,
        )
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))
    };
    // Pick a free loop device through loop-control (no scanning).
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
    // Mount the bound loop device read-only (squashfs is read-only by
    // design; the flags double as the usual hardening). The mountpoint is
    // a plain workdir-local directory, created here.
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

/// Everything the child side needs, built by the parent before the fork.
struct MountPlan {
    root: CString,
    oldroot: CString,
    proc_dir: CString,
    dev_dir: CString,
    cwd_dir: CString,
    workdir: CString,
    /// Overlayfs setup for a caller-supplied rootfs (`rootfs=`): the mount
    /// options string `lowerdir=<rootfs>,upperdir=<tmpfs>,workdir=<tmpfs>`.
    /// The host rootfs is the read-only lower layer — it is *never* written
    /// (no mountpoint dirs have to be created inside it); everything else
    /// (missing mountpoints like `/cwd`, `/proc`, `/dev`, runtime bind
    /// targets) is provisioned into the per-run upper layer. `None` when no
    /// rootfs was given (plain tmpfs root + system-dir binds).
    rootfs_overlay: Option<CString>,
    /// (host source, absolute path inside the sandbox) read-only directory
    /// binds.
    binds: Vec<(CString, CString)>,
    /// Read-only **file** binds: (host source, parent dir inside the sandbox,
    /// target path inside the sandbox). Used to inject an executable that is
    /// not already visible through a directory bind.
    file_binds: Vec<(CString, CString, CString)>,
    /// The path to `execve` (inside the sandbox): the caller's path when it
    /// is already visible, else the injected `/cwd/.river/<name>`.
    exec_path: CString,
    /// Program cwd candidates, in sandbox coordinates: preferred, fallback.
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

        // Caller-supplied rootfs: overlayfs with the host tree (or a
        // squashfs image bound to a loop device) as the read-only lower
        // layer and per-run tmpfs upper/work dirs. Overlayfs (rather than a
        // plain bind) means the sandbox never has to create mountpoint
        // directories *inside* the caller's tree — with a plain read-only
        // bind, a rootfs lacking `/cwd` or `/proc` could not be used at
        // all. The overlay is remounted read-only after the mountpoints
        // exist (supervise); the upper layer is per-run and discarded with
        // the workdir, so the host rootfs stays untouched.
        let mut loop_guard: Option<LoopGuard> = None;
        let rootfs_overlay = match rootfs {
            Some(fs) => {
                // Paths are embedded in a comma-separated mount(8)-style
                // options string; refuse the characters that would break it.
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
                // A regular file is treated as a squashfs image: verify the
                // magic, attach it to a free loop device and mount it
                // read-only — the *mountpoint* becomes the overlay lowerdir
                // (so commas in the image path are fine; the lowerdir is
                // the workdir-local mountpoint below).
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

        // Binds: system dirs first (no rootfs), then caller runtimes,
        // deduped by the sandbox path. A runtime that is a prefix of another
        // is fine — the deeper mount lands on top.
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
        // Run the caller runtimes last so they can shadow a system path (or
        // a rootfs path) if a deployment deliberately supplies its own tree
        // at the same path.
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
                // Binding the host root would erase the whole isolation
                // model; refuse it instead of silently trusting the caller.
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "runtime \"/\" is refused: it would expose the whole host",
                ));
            }
            push_bind(rt, abs)?;
        }

        // Executable coordinate systems: without a rootfs the contract says
        // `executable` is a host path — if it is not visible through a
        // directory bind it is bind-mounted (read-only) at `/cwd/.river/<name>`
        // and exec'd from there. With a rootfs, `executable` is a path inside
        // the rootfs (e.g. `/usr/bin/python3`) and is exec'd as-is; a missing
        // binary surfaces as the exec failure (ENOENT → run error), and no
        // host injection is attempted.
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

/// Fork the supervisor and wait for the child exec to be confirmed.
///
/// `env_vars` is the complete environment (whitelist base + caller
/// overrides — no host environment leaks through).
// The parameters are the complete spawn input (paths, argv, env, limits,
// stdio, seccomp); grouping them would only move the list one level down,
// and this is called from exactly one place.
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

    // argv[0] is the path the program is actually exec'd from (the injected
    // `/cwd/.river/<name>` when the host path was not visible).
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
        // ---- supervisor: async-signal-safe code only --------------------
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
        // supervise never returns.
    }

    // ---- parent: start the watchdog alongside the supervisor -----------
    // The watchdog detects the judger's death by polling its own parent pid
    // (no inherited pipe: with concurrent runs, a pipe write end would be
    // duplicated into *other* runs' children, so its EOF would never
    // arrive). On judger death it SIGKILLs the supervisor's process group.
    let watchdog = unsafe { libc::fork() };
    if watchdog < 0 {
        let err = io::Error::last_os_error();
        // No watchdog yet, so it is killed with the supervisor's group only.
        unsafe { abort_spawn(fork_rc, -1) };
        return Err(err);
    }
    if watchdog == 0 {
        unsafe { watchdog_loop(fork_rc) };
    }

    // ---- parent ---------------------------------------------------------
    // Starting the stdio threads can fail (fd/memory pressure). The error
    // must abort the spawn like any other: the supervisor is already
    // running, so leaving it behind would leak it unreaped and keep the
    // watchdog polling a run that will never be monitored.
    if let Err(e) = stdio.after_fork() {
        unsafe { abort_spawn(fork_rc, watchdog) };
        return Err(e);
    }
    // Confirm setup + exec: "ok\n" = both succeeded; any other bytes are the
    // failing errno (setup failure in A, or exec failure in B).
    drop(ready_write);
    let mut reader = unsafe { std::fs::File::from_raw_fd(ready_read.into_raw_fd()) };
    let mut report = Vec::new();
    if let Err(e) = reader.read_to_end(&mut report) {
        // The `?` would skip the teardown below: the supervisor would stay
        // unreaped (a zombie) and the watchdog would keep polling. Abort
        // explicitly.
        unsafe { abort_spawn(fork_rc, watchdog) };
        return Err(e);
    }
    drop(reader);
    if !report.starts_with(b"ok\n") || report.len() > 3 {
        let code = if report.starts_with(b"ok\n") {
            // "ok\n" + errno: the supervisor's setup worked, the program's
            // own setup (proc mount / uid drop / chdir / exec) failed.
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

/// Per-run resource limits and identity applied by the child just before
/// exec. Plain-old-data on purpose: it crosses the fork unchanged.
#[derive(Clone, Copy)]
pub(crate) struct ChildLimits {
    /// `RLIMIT_FSIZE`: a single file the program writes cannot exceed this
    /// (a 10GB write dies on `SIGXFSZ` instead of filling the host disk).
    pub(crate) fsize_bytes: u64,
    /// `RLIMIT_NOFILE`: open descriptors.
    pub(crate) nofile: u64,
    /// `RLIMIT_CPU` hard backstop (seconds); the judger's CPU polling is the
    /// primary enforcement.
    pub(crate) cpu_secs: Option<u64>,
    /// Per-run identity (leased from the uid pool): a run must not share a
    /// uid with another run or a host account (the old fixed `nobody` let
    /// any same-uid process read/write a live run's workdir — verified).
    pub(crate) uid: libc::uid_t,
    pub(crate) gid: libc::gid_t,
}

/// Zero every capability set (permitted/effective/inheritable). `setuid`
/// already clears them, but the program must not depend on that implicit
/// behaviour (and bounding/ambient sets must not be inherited either).
///
/// Returns the `errno` of a failed `capset` (0 on success): a program whose
/// capabilities could not be dropped must not run.
unsafe fn clear_capabilities() -> libc::c_int {
    // Kernel uapi layout (`include/uapi/linux/capability.h`); libc does not
    // export these on every version.
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
        version: 0x2008_0522, // _LINUX_CAPABILITY_VERSION_3
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

/// Set the rlimits that bound a single file write, descriptor count, core
/// dump and CPU backstop.
///
/// These are part of the sandbox guarantee, so a refused limit is fatal for
/// the run: RLIMIT_CORE=0 must hold (a core dump into the writable cwd would
/// bypass the product model), and RLIMIT_FSIZE is the only per-file disk
/// bound. The cgroup limits stay authoritative for memory/processes, but
/// "best effort" would silently weaken the mechanism (fail-closed rule).
///
/// Returns the `errno` of the first failed `setrlimit` (0 on success).
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

/// The supervisor half of spawn. **Never returns.**
///
/// # Fork safety
/// Raw libc calls only: no allocation, no std I/O, no panic paths. All
/// paths and pointer arrays are pre-built by the parent.
// The limits/seccomp/stdio inputs must cross the fork as plain values, so
// they stay separate parameters rather than a heap-allocated struct.
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
    // stdio onto 0/1/2, then keep the ready pipe on fd 3 and close
    // **everything else**. `close_range` is what makes concurrent runs safe:
    // an inherited foreign write end (another run's stdio pipe) would keep
    // an EOF from ever arriving in the judger.
    let (fd_in, fd_out, fd_err) = stdio_fds;
    libc::dup2(fd_in, libc::STDIN_FILENO);
    libc::dup2(fd_out, libc::STDOUT_FILENO);
    libc::dup2(fd_err, libc::STDERR_FILENO);
    if ready_write != 3 {
        libc::dup2(ready_write, 3);
    }
    // The ready pipe must not leak into the program: CLOEXEC means the
    // program's exec closes it (the success EOF the judger waits for).
    libc::fcntl(3, libc::F_SETFD, libc::FD_CLOEXEC);
    if libc::close_range(4, libc::c_uint::MAX, 0) != 0 {
        // Kernel older than 5.9: no safe generic sweep available here.
        fail(3, errno());
    }

    // Own session: the process group id becomes the kill domain the judger
    // targets (kill(-pid) reaps A and B together). Also drops any
    // controlling terminal.
    if libc::setsid() < 0 {
        fail(3, errno());
    }
    // Judger death => supervisor death (the chain then kills B too).
    libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
    libc::signal(libc::SIGPIPE, libc::SIG_DFL);

    // ---- cgroup membership ---------------------------------------------
    // Written by the supervisor itself (not the judger): membership must be
    // in place *before* B is forked so the program inherits it, and doing it
    // from the judger would race this fork.
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
            // Capture the errno *before* close(): close() is a syscall and
            // the kernel is free to touch the thread's errno region, which
            // would report the wrong cause.
            let err = errno();
            libc::close(fd);
            fail(3, err);
        }
        libc::close(fd);
    }

    // ---- namespaces -----------------------------------------------------
    let flags = libc::CLONE_NEWNS
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWNET
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWUTS
        | libc::CLONE_NEWCGROUP;
    if libc::unshare(flags) != 0 {
        fail(3, errno());
    }
    // UTS namespace starts as a copy of the host: give it a neutral name so
    // the host name does not leak to the program.
    if libc::sethostname(c"river".as_ptr(), 5) != 0 {
        fail(3, errno());
    }
    // Make the whole mount tree private: nothing propagates to the host.
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

    // ---- tmpfs root + layout -------------------------------------------
    let err = mount::mkdir_p(&plan.root);
    if err != 0 {
        fail(3, err);
    }
    let err = mount::mount_tmpfs(&plan.root, c"mode=755", libc::MS_NOSUID | libc::MS_NODEV);
    if err != 0 {
        fail(3, err);
    }

    // ---- caller rootfs (overlayfs, read-only) ---------------------------
    // With `rootfs=` the overlay is mounted at the tmpfs root: lower = the
    // host rootfs (never written), upper = per-run tmpfs. The mountpoint
    // directories the layout needs (`/cwd`, `/proc`, `/dev`, `/.oldroot`,
    // runtime bind targets) are created *now* — they land in the upper
    // layer — and then the overlay is remounted read-only so the program
    // sees a frozen rootfs. Without a rootfs this block is skipped and the
    // system dirs are bind-mounted below instead.
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
        // Freeze the rootfs view: read-only, no suid, no devices. The
        // writable surface stays `/cwd` (bind-mounted below, on top of the
        // read-only overlay) — same model as the tmpfs root.
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
    // The cwd is the only writable bind; it still must not honour setuid
    // bits or device nodes, like every other bind (see `mount::bind_ro`).
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
    // Executable injection: create the empty target file, then bind.
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
    // Minimal /dev: tmpfs + the character devices every libc program
    // expects. `nosuid` only — `nodev` here would make the nodes unusable.
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

    // ---- pivot into the new root ---------------------------------------
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
    // Detach the old root. Failing open here would leave the host tree
    // reachable at /.oldroot, so a failure aborts the run instead of being
    // ignored.
    if libc::umount2(c"/.oldroot".as_ptr(), libc::MNT_DETACH) != 0 {
        fail(3, errno());
    }
    libc::rmdir(c"/.oldroot".as_ptr());

    // Setup complete: the parent may now trust the namespace.
    if libc::write(3, b"ok\n".as_ptr().cast(), 3) != 3 {
        libc::_exit(127);
    }

    // ---- fork the program (PID 1 of the new pid namespace) -------------
    let pid = libc::fork();
    if pid < 0 {
        // Report through the pipe before the parent sees EOF.
        fail(3, errno());
    }
    if pid == 0 {
        // Child B: fresh /proc (mounted from inside its own pid ns), then
        // drop privileges, fence the attack surface and exec.
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
        // setuid resets dumpable; set it afterwards so /proc/self/mem and
        // ptrace of the program require privilege again.
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        // Privilege escalation fence: setuid/fcap binaries inside the
        // (read-only) runtime trees must not gain privileges; and an
        // unprivileged seccomp filter requires this bit.
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

    // ---- supervisor: close the ready pipe (B holds the surviving copy),
    //      reap B and mirror its exit code --------------------------------
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

/// Report the failure errno through the ready pipe and exit.
/// Allocation-free (itoa by hand onto the stack).
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

/// Judger-death watchdog: polls its own parent pid; when the judger dies the
/// kernel reparents the watchdog (getppid() changes), which is the trigger to
/// SIGKILL the supervisor's process group.
///
/// Why not PDEATHSIG for the program: the program is PID 1 of its own pid
/// namespace, and a PDEATHSIG-delivered SIGKILL is **not** delivered to a
/// namespace init (empirically verified on Linux 6.x — the process
/// survives). An explicit `kill(-pgid)` from a process in an ancestor
/// namespace *is* delivered, so the watchdog does that instead.
///
/// Why not a pipe held by the judger: with concurrent runs, every fork
/// inherits the other runs' pipe write ends, so a pipe EOF would never
/// arrive. Polling `getppid()` has no such inheritance problem.
unsafe fn watchdog_loop(supervisor_pid: libc::pid_t) -> ! {
    // Drop every inherited fd: the watchdog needs none, and keeping them
    // would delay EOF for the run's own stdio pipes.
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
