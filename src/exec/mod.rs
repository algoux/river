//! Parent-side orchestration of one `River.exec()` (design.md §3).
//!
//! Everything here runs with the GIL released; failures are plain Rust
//! values and `api.rs` turns them into Python exceptions.

pub mod caps;
pub mod child;
pub mod idmap;
pub mod io;
pub mod landlock;
pub mod mount;
pub mod seccomp;
pub mod supervise;

use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::io::Write as _;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use seccompiler::sock_filter;

use crate::cgroup;
use crate::preflight;

/// design.md §5 step names, in the order the child executes them. The
/// `child.*` names travel to `ExecSetupError` messages; `parent.*` steps
/// mark orchestration failures around the clone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Step {
    Pdeathsig = 0,
    Idmap = 1,
    MountPrivate = 2,
    /// design.md §5 `bind_root` + `root_attr`, merged: the read-only root
    /// bind is one detached-clone-attr-attach dance (see child.rs).
    MountBindRoot = 3,
    MountProc = 4,
    MountDevpts = 5,
    MountShm = 6,
    MountMqueue = 7,
    MountTmp = 8,
    MountDev = 9,
    MountWork = 10,
    MountSys = 11,
    MountPivot = 12,
    NetLo = 13,
    Caps = 14,
    Nnp = 15,
    Landlock = 16,
    Seccomp = 17,
    Chdir = 18,
    Stdio = 19,
    Execve = 20,
}

impl Step {
    pub fn from_raw(value: u32) -> Option<Step> {
        Some(match value {
            0 => Step::Pdeathsig,
            1 => Step::Idmap,
            2 => Step::MountPrivate,
            3 => Step::MountBindRoot,
            4 => Step::MountProc,
            5 => Step::MountDevpts,
            6 => Step::MountShm,
            7 => Step::MountMqueue,
            8 => Step::MountTmp,
            9 => Step::MountDev,
            10 => Step::MountWork,
            11 => Step::MountSys,
            12 => Step::MountPivot,
            13 => Step::NetLo,
            14 => Step::Caps,
            15 => Step::Nnp,
            16 => Step::Landlock,
            17 => Step::Seccomp,
            18 => Step::Chdir,
            19 => Step::Stdio,
            20 => Step::Execve,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Step::Pdeathsig => "child.pdeathsig",
            Step::Idmap => "child.idmap",
            Step::MountPrivate => "child.mount.private",
            Step::MountBindRoot => "child.mount.bind_root",
            Step::MountProc => "child.mount.proc",
            Step::MountDevpts => "child.mount.devpts",
            Step::MountShm => "child.mount.shm",
            Step::MountMqueue => "child.mount.mqueue",
            Step::MountTmp => "child.mount.tmp",
            Step::MountDev => "child.mount.dev",
            Step::MountWork => "child.mount.work",
            Step::MountSys => "child.mount.sys",
            Step::MountPivot => "child.mount.pivot",
            Step::NetLo => "child.net.lo",
            Step::Caps => "child.caps",
            Step::Nnp => "child.nnp",
            Step::Landlock => "child.landlock",
            Step::Seccomp => "child.seccomp",
            Step::Chdir => "child.chdir",
            Step::Stdio => "child.stdio",
            Step::Execve => "child.execve",
        }
    }
}

/// One 8-byte packet on the sync socket: the step that failed plus the
/// errno (design.md §5). `SOCK_SEQPACKET` keeps it a single message.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SyncMsg {
    pub step: u32,
    pub errno: i32,
}

/// A copy_in entry, normalized in `api.rs`.
pub enum CopyInValue {
    /// `bytes`/`str` content, UTF-8 encoded for `str`.
    Bytes(Vec<u8>),
    /// Host file whose *content* is copied into the sandbox (never linked).
    HostFile(PathBuf),
}

/// Everything `api.rs` extracts from the Python call, with `envs` already
/// resolved (explicit mapping or `meta.json`).
pub struct ExecParams {
    pub executable: String,
    pub args: Vec<String>,
    pub cwd: String,
    pub envs: HashMap<String, String>,
    pub stdin: Option<Vec<u8>>,
    pub stdin_file: Option<String>,
    pub stdout_file: Option<String>,
    pub stderr_file: Option<String>,
    pub stdout_limit_bytes: Option<u64>,
    pub stderr_limit_bytes: Option<u64>,
    pub copy_in: Vec<(String, CopyInValue)>,
    pub copy_out: Vec<(String, Option<String>)>,
    pub copy_out_limit_bytes: Option<u64>,
}

/// The whole pre-serialized child state (design.md §3 step 4): strings are
/// `CString`s, argv/envp pointer arrays are pre-built (heap addresses stay
/// valid in the clone's COW copy), fds are inherited raw numbers.
pub struct ChildSpec {
    pub expected_ppid: i32,
    pub debug: bool,
    pub idmap: idmap::Idmap,
    /// Canonical host path of the rootfs, entered by *path* (not fd): a
    /// pre-clone fd pins the parent's mount objects, which the child's
    /// `CLONE_NEWNS` copy does not own, and every mount syscall would then
    /// fail with EINVAL.
    pub rootfs_path: CString,
    /// Host path of this run's work directory (the bind source for /work).
    pub work_src: CString,
    /// Backing storage for `argv_ptrs`: the child only reads through the
    /// pointer array, a dependency rustc cannot see.
    #[allow(dead_code)]
    pub argv: Vec<CString>,
    /// NUL-terminated array over `argv`.
    pub argv_ptrs: Vec<*const libc::c_char>,
    /// Backing storage for `envp_ptrs`, same as `argv`.
    #[allow(dead_code)]
    pub envp: Vec<CString>,
    /// NUL-terminated array over `envp`.
    pub envp_ptrs: Vec<*const libc::c_char>,
    /// `execve` candidates: the direct path when `executable` contains '/',
    /// otherwise every `PATH` directory joined with the name.
    pub exec_candidates: Vec<CString>,
    pub cwd: CString,
    pub stdin_file: Option<CString>,
    pub stdout_file: Option<CString>,
    pub stderr_file: Option<CString>,
    pub stdin_pipe_r: RawFd,
    pub stdout_pipe_w: RawFd,
    pub stderr_pipe_w: RawFd,
    /// Empty = do not install a filter (`RIVER_HARDENING=off`).
    pub seccomp_prog: Vec<sock_filter>,
    /// `None` = Landlock unavailable or `RIVER_HARDENING=off`.
    pub landlock_masks: Option<landlock::Masks>,
    pub sync_fd: RawFd,
}

/// Failure surfaced by `exec()`, converted to a Python exception in
/// `api.rs` (which is also the only place holding the GIL).
pub enum ExecFailure {
    /// Caller misuse (→ `ValueError`).
    BadParams(String),
    /// envs/copy_in/copy_out violations (→ `RootfsError`).
    Rootfs(String),
    /// Host-side environment trouble (→ `RiverError`).
    Host(String),
    /// The sandbox could not be established: step + errno
    /// (→ `ExecSetupError`).
    Setup {
        step: &'static str,
        errno: i32,
        context: String,
    },
    /// A copy_out entry could not be retrieved (→ `CopyOutError`).
    CopyOut { key: String, reason: String },
    /// A pending Python signal (usually Ctrl-C) interrupted the run.
    Interrupted,
}

/// Plain result of one run, still GIL-free; `api.rs` wraps it.
pub struct Outcome {
    pub status: String,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub cpu_time_used_ms: u64,
    pub wall_time_used_ms: u64,
    pub memory_used_bytes: u64,
    pub stdout: Option<Vec<u8>>,
    pub stderr: Option<Vec<u8>>,
    pub files: Vec<(String, Vec<u8>)>,
    pub error: Option<String>,
}

/// `struct clone_args`, hand-declared: libc 0.2 has no gnu binding for
/// clone3/clone_args (development-plan.md §5 V4), so this goes through
/// `libc::syscall`.
#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
}
const _: () = assert!(std::mem::size_of::<CloneArgs>() == 64);

/// Executes one run end to end (design.md §3). The GIL must be released.
pub fn run(rootfs: &Path, p: &ExecParams) -> Result<Outcome, ExecFailure> {
    let debug = std::env::var_os("RIVER_LOG").is_some_and(|v| v.eq_ignore_ascii_case("debug"));
    let hardening_off =
        std::env::var_os("RIVER_HARDENING").is_some_and(|v| v == std::ffi::OsStr::new("off"));
    log(
        debug,
        &format!("exec starting: executable={:?} cwd={:?}", p.executable, p.cwd),
    );

    // 1. The host work directory and copy_in (design.md §3 step 3, §10).
    let base = preflight::workdir_base().map_err(ExecFailure::Host)?;
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let work_dir = base
        .join(std::process::id().to_string())
        .join(SEQ.fetch_add(1, Ordering::Relaxed).to_string());
    fs::create_dir_all(&work_dir).map_err(|e| {
        ExecFailure::Host(format!("cannot create {}: {e}", work_dir.display()))
    })?;
    // design.md §10: removed when the run ends, whatever happened.
    struct WorkCleanup<'a>(&'a Path);
    impl Drop for WorkCleanup<'_> {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(self.0);
        }
    }
    let _work_cleanup = WorkCleanup(&work_dir);
    io::write_copy_in(&work_dir, &p.cwd, &p.copy_in).map_err(ExecFailure::Rootfs)?;
    log(debug, &format!("work dir ready: {}", work_dir.display()));

    // 2. Hardening artifacts (design.md §9). `RIVER_HARDENING=off` disables
    //    only these two; namespaces, the read-only rootfs and the cap drop
    //    stay (design.md §4).
    let seccomp_prog = if hardening_off {
        Vec::new()
    } else {
        seccomp::build_program().map_err(ExecFailure::Host)?
    };
    let landlock_masks = if hardening_off {
        None
    } else {
        let masks = landlock::compute_masks();
        if masks.is_none() {
            log(
                debug,
                "Landlock is unavailable (ABI 0 or ENOSYS); the filesystem hardening layer is disabled",
            );
        }
        masks
    };

    // 3. File descriptors: the sync socket and the stdio pipes (design.md §3
    //    step 4). Parent ends and child ends live in separate `OwnedFd`s so
    //    closing happens exactly once.
    let (sync_parent, sync_child) = {
        let (a, b) = io::socketpair_seqpacket()
            .map_err(|e| parent_setup("parent.socketpair", e, "sync socket".to_string()))?;
        io::set_nonblock(a)
            .map_err(|e| parent_setup("parent.socketpair", e, "sync socket".to_string()))?;
        // SAFETY: each raw fd is wrapped exactly once, right after creation.
        unsafe { (OwnedFd::from_raw_fd(a), OwnedFd::from_raw_fd(b)) }
    };
    let (stdout_parent, stdout_child): (Option<OwnedFd>, Option<OwnedFd>) = if p.stdout_file.is_none()
    {
        let (r, w) = io::pipe()
            .map_err(|e| parent_setup("parent.pipes", e, "stdout".to_string()))?;
        io::set_nonblock(r)
            .map_err(|e| parent_setup("parent.pipes", e, "stdout".to_string()))?;
        // SAFETY: each raw fd is wrapped exactly once, right after creation.
        (
            Some(unsafe { OwnedFd::from_raw_fd(r) }),
            Some(unsafe { OwnedFd::from_raw_fd(w) }),
        )
    } else {
        (None, None)
    };
    let (stderr_parent, stderr_child): (Option<OwnedFd>, Option<OwnedFd>) = if p.stderr_file.is_none()
    {
        let (r, w) = io::pipe()
            .map_err(|e| parent_setup("parent.pipes", e, "stderr".to_string()))?;
        io::set_nonblock(r)
            .map_err(|e| parent_setup("parent.pipes", e, "stderr".to_string()))?;
        // SAFETY: each raw fd is wrapped exactly once, right after creation.
        (
            Some(unsafe { OwnedFd::from_raw_fd(r) }),
            Some(unsafe { OwnedFd::from_raw_fd(w) }),
        )
    } else {
        (None, None)
    };
    let (stdin_child, stdin_parent): (Option<OwnedFd>, Option<OwnedFd>) = if p.stdin.is_some() {
        let (r, w) = io::pipe()
            .map_err(|e| parent_setup("parent.pipes", e, "stdin".to_string()))?;
        io::set_nonblock(w)
            .map_err(|e| parent_setup("parent.pipes", e, "stdin".to_string()))?;
        // SAFETY: each raw fd is wrapped exactly once, right after creation.
        (
            Some(unsafe { OwnedFd::from_raw_fd(r) }),
            Some(unsafe { OwnedFd::from_raw_fd(w) }),
        )
    } else {
        (None, None)
    };

    // 4. Pre-serialize the child state (design.md §3 step 4).
    let euid = unsafe { libc::geteuid() };
    let egid = unsafe { libc::getegid() };
    let cstring = |s: &str| -> Result<CString, ExecFailure> {
        CString::new(s)
            .map_err(|_| ExecFailure::BadParams(format!("the string {s:?} contains a NUL byte")))
    };
    let mut argv = Vec::with_capacity(1 + p.args.len());
    argv.push(cstring(&p.executable)?);
    for arg in &p.args {
        argv.push(cstring(arg)?);
    }
    let mut envp = Vec::with_capacity(p.envs.len());
    for (key, value) in &p.envs {
        envp.push(cstring(&format!("{key}={value}"))?);
    }
    let argv_ptrs: Vec<*const libc::c_char> = argv
        .iter()
        .map(|c| c.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let envp_ptrs: Vec<*const libc::c_char> = envp
        .iter()
        .map(|c| c.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let exec_candidates = if p.executable.contains('/') {
        vec![cstring(&p.executable)?]
    } else {
        let path = p.envs.get("PATH").ok_or_else(|| {
            ExecFailure::BadParams(
                "executable without '/' requires envs['PATH'] to find it inside the sandbox"
                    .to_string(),
            )
        })?;
        path.split(':')
            .filter(|dir| !dir.is_empty())
            .map(|dir| cstring(&format!("{dir}/{}", p.executable)))
            .collect::<Result<Vec<_>, _>>()?
    };
    let work_src = cstring(&work_dir.display().to_string())?;
    let spec = ChildSpec {
        expected_ppid: std::process::id() as i32,
        debug,
        idmap: idmap::Idmap {
            uid_line: format!("0 {euid} 1\n").into_bytes(),
            gid_line: format!("0 {egid} 1\n").into_bytes(),
        },
        rootfs_path: cstring(&rootfs.display().to_string())?,
        work_src,
        argv,
        argv_ptrs,
        envp,
        envp_ptrs,
        exec_candidates,
        cwd: cstring(&p.cwd)?,
        stdin_file: p.stdin_file.as_deref().map(|s| cstring(s)).transpose()?,
        stdout_file: p.stdout_file.as_deref().map(|s| cstring(s)).transpose()?,
        stderr_file: p.stderr_file.as_deref().map(|s| cstring(s)).transpose()?,
        stdin_pipe_r: stdin_child.as_ref().map_or(-1, |fd| fd.as_raw_fd()),
        stdout_pipe_w: stdout_child.as_ref().map_or(-1, |fd| fd.as_raw_fd()),
        stderr_pipe_w: stderr_child.as_ref().map_or(-1, |fd| fd.as_raw_fd()),
        seccomp_prog,
        landlock_masks,
        sync_fd: sync_child.as_raw_fd(),
    };

    // 5. clone3: one call creates every namespace (design.md §3 step 5).
    let flags: u64 = (libc::CLONE_NEWUSER
        | libc::CLONE_NEWNS
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWNET
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWUTS
        | libc::CLONE_NEWCGROUP
        | libc::CLONE_PIDFD) as u64;
    let mut pidfd: u64 = 0;
    let mut args = CloneArgs {
        flags,
        pidfd: &mut pidfd as *mut u64 as u64,
        exit_signal: libc::SIGCHLD as u64,
        ..CloneArgs::default()
    };
    // SAFETY: `args` is a plain 64-byte struct; the child continues on the
    // same (COW) stack and only reads `&spec`.
    let r = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &mut args as *mut CloneArgs,
            std::mem::size_of::<CloneArgs>(),
        )
    };
    let pid = if r == -1 {
        return Err(parent_setup(
            "parent.clone3",
            std::io::Error::last_os_error(),
            String::new(),
        ));
    } else if r == 0 {
        // The child: never returns.
        unsafe { child::entry(&spec) }
    } else {
        r as i32
    };
    // SAFETY: the CLONE_PIDFD out-param was filled by a successful clone3.
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd as RawFd) };
    log(
        debug,
        &format!("clone3 ok: pid={pid} pidfd={}", pidfd.as_raw_fd()),
    );

    // The child holds its own copies of these fds now; close ours so pipe
    // EOF and the sync HUP behave.
    drop(sync_child);
    drop(stdout_child);
    drop(stderr_child);
    drop(stdin_child);

    // 6. design.md §3 step 6 — PR 3 writes the child pid into the run
    //    cgroup's `cgroup.procs` here (creating <base>/river-<pid>-<seq>),
    //    so every limit is in force before the first sandbox instruction.
    //    PR 2 reads the metrics from the process's `river/` cgroup instead.

    // 7. "go" + supervise (design.md §3 step 7).
    let t0 = Instant::now();
    io::write_all_fd(sync_parent.as_raw_fd(), b"g")
        .map_err(|e| parent_setup("parent.go", e, "sync socket".to_string()))?;
    let supervise_input = supervise::Input {
        pid,
        pidfd,
        sync: sync_parent,
        stdout: stdout_parent,
        stderr: stderr_parent,
        stdin: stdin_parent,
        stdin_bytes: p.stdin.clone().unwrap_or_default(),
        stdout_limit_bytes: p.stdout_limit_bytes,
        stderr_limit_bytes: p.stderr_limit_bytes,
    };
    let (supervised, stdout_buf, stderr_buf) = match supervise::run(supervise_input) {
        Ok(value) => value,
        Err(supervise::Error::Interrupted) => return Err(ExecFailure::Interrupted),
        Err(supervise::Error::Io(msg)) => {
            return Err(ExecFailure::Setup {
                step: "parent.supervise",
                errno: 0,
                context: msg,
            })
        }
    };

    // 8. Reap (design.md §3 step 8) and interpret the sync report
    //    (ExecSetupError, design.md §5).
    let status = waitpid_blocking(pid);
    let (exit_code, signal) = decode_status(status);
    let wall_time_used_ms = t0.elapsed().as_millis() as u64;
    log(
        debug,
        &format!("child reaped: exit_code={exit_code:?} signal={signal:?}"),
    );

    if let Some((raw_step, errno)) = supervised.setup_error {
        let (step, context) = match Step::from_raw(raw_step) {
            Some(step @ Step::Chdir) => (step.name(), "cwd does not exist".to_string()),
            Some(step @ Step::Execve) => (
                step.name(),
                format!("executable {:?} could not be started", p.executable),
            ),
            Some(step) => (step.name(), String::new()),
            None => ("child", format!("unknown step {raw_step}")),
        };
        return Err(ExecFailure::Setup { step, errno, context });
    }

    // 9. Metrics (design.md §3 step 8). PR 2 reads the process's `river/`
    //    cgroup: the numbers include the caller itself and every sandbox
    //    so far — inaccurate but wired end to end; PR 3 switches to the
    //    per-run cgroup.
    let (cpu_time_used_ms, memory_used_bytes) = cgroup::read_metrics();

    // 10. copy_out (design.md §3 step 9).
    let files = io::read_copy_out(&work_dir, &p.cwd, &p.copy_out, p.copy_out_limit_bytes)
        .map_err(|(key, reason)| ExecFailure::CopyOut { key, reason })?;

    // 11. Verdict (design.md §4; TLE/MLE/OLE arrive with PR 3).
    let (status, error) = match (exit_code, signal) {
        (Some(0), _) => ("AC".to_string(), None),
        (Some(code), _) => ("RE".to_string(), Some(format!("exited with code {code}"))),
        (None, Some(sig)) => (
            "RE".to_string(),
            Some(format!(
                "killed by signal {sig} ({})",
                signal_name(sig)
            )),
        ),
        (None, None) => (
            "RE".to_string(),
            Some("the child did not report an exit status".to_string()),
        ),
    };

    Ok(Outcome {
        status,
        exit_code,
        signal,
        cpu_time_used_ms,
        wall_time_used_ms,
        memory_used_bytes,
        stdout: if p.stdout_file.is_some() {
            None
        } else {
            Some(stdout_buf)
        },
        stderr: if p.stderr_file.is_some() {
            None
        } else {
            Some(stderr_buf)
        },
        files,
        error,
    })
}

fn parent_setup(step: &'static str, e: std::io::Error, context: String) -> ExecFailure {
    ExecFailure::Setup {
        step,
        errno: e.raw_os_error().unwrap_or(0),
        context: if context.is_empty() {
            e.to_string()
        } else {
            format!("{context}: {e}")
        },
    }
}

fn waitpid_blocking(pid: i32) -> libc::c_int {
    let mut status: libc::c_int = 0;
    loop {
        // SAFETY: `status` is a valid out-pointer.
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r == pid {
            return status;
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::Interrupted {
            return -1;
        }
    }
}

fn decode_status(status: libc::c_int) -> (Option<i32>, Option<i32>) {
    if libc::WIFEXITED(status) {
        (Some(libc::WEXITSTATUS(status)), None)
    } else if libc::WIFSIGNALED(status) {
        (None, Some(libc::WTERMSIG(status)))
    } else {
        (None, None)
    }
}

fn signal_name(sig: i32) -> &'static str {
    match sig {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        4 => "SIGILL",
        5 => "SIGTRAP",
        6 => "SIGABRT",
        7 => "SIGBUS",
        8 => "SIGFPE",
        9 => "SIGKILL",
        11 => "SIGSEGV",
        13 => "SIGPIPE",
        14 => "SIGALRM",
        15 => "SIGTERM",
        24 => "SIGXCPU",
        25 => "SIGXFSZ",
        31 => "SIGSYS",
        _ => "unknown signal",
    }
}

fn log(debug: bool, msg: &str) {
    if debug {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "[river] {msg}");
    }
}
