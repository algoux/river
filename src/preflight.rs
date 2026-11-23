//! Preflight checks shared by `river.doctor()` and `River.__new__` (design.md §8).
//!
//! Every check yields a `Check` row `(name, ok, detail, remediation)`. The name
//! also selects which exception a failed check raises, so this module is the
//! only place that maps checks to exceptions.

use std::collections::HashMap;
use std::ffi::CStr;
use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::api::{
    CgroupNotDelegatedError, KernelTooOldError, RiverError, RootfsError, UserNamespaceDeniedError,
};
use crate::cgroup;

/// `(name, ok, detail, remediation)` — one row of a doctor report.
pub type Check = (String, bool, String, Option<String>);

/// Minimum kernel version (design.md appendix A).
const MIN_KERNEL: (u32, u32) = (6, 8);

const KERNEL_FIX: &str = "run river on Linux 6.8 or newer";
const USERNS_FIX: &str = "allow unprivileged user namespaces: `sysctl -w user.max_user_namespaces=15000` and, on Ubuntu 23.10+, `sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`";
const CGROUP_FIX: &str = "start the program inside a delegated cgroup, e.g. `systemd-run --user --scope -p Delegate=yes python app.py`, or in a user service with Delegate=yes";
const WORKDIR_FIX: &str = "point XDG_RUNTIME_DIR at a writable tmpfs directory, or make /dev/shm writable";

/// Runs every preflight check. With `raise_on_fail` the first failed check raises
/// the very exception `River()` would raise; otherwise the full report is returned.
#[pyfunction]
pub fn run_doctor_checks(raise_on_fail: bool) -> PyResult<Vec<Check>> {
    let checks = all_checks();
    if raise_on_fail {
        if let Some(failed) = checks.iter().find(|c| !c.1) {
            return Err(error_for(failed));
        }
    }
    Ok(checks)
}

/// The `River()` preflight: same checks, raises on the first failure.
pub fn check_all() -> PyResult<()> {
    run_doctor_checks(true).map(|_| ())
}

fn all_checks() -> Vec<Check> {
    vec![
        check_platform(),
        check_kernel(),
        check_userns_limit(),
        check_apparmor(),
        check_userns_probe(),
        check_cgroup(),
        check_workdir(),
        check_landlock_abi(),
    ]
}

fn error_for(check: &Check) -> PyErr {
    let message = match &check.3 {
        Some(fix) => format!("{}; fix: {fix}", check.2),
        None => check.2.clone(),
    };
    match check.0.as_str() {
        "kernel" => KernelTooOldError::new_err(message),
        "userns.max" | "userns.apparmor" | "userns.probe" => UserNamespaceDeniedError::new_err(message),
        "cgroup" => CgroupNotDelegatedError::new_err(message),
        _ => RiverError::new_err(message),
    }
}

fn ok(name: &str, detail: String) -> Check {
    (name.to_string(), true, detail, None)
}

fn fail(name: &str, detail: String, fix: &str) -> Check {
    (name.to_string(), false, detail, Some(fix.to_string()))
}

fn read_trim(path: &str) -> io::Result<String> {
    fs::read_to_string(path).map(|s| s.trim().to_string())
}

// ---------------------------------------------------------------- platform

struct Uname {
    sysname: String,
    release: String,
    machine: String,
}

fn uname() -> Uname {
    // SAFETY: `utsname` is a plain struct of char arrays; uname(2) only writes into it.
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: as above; the return value merely reports libc's own success.
    unsafe { libc::uname(&mut u) };
    let field = |c: &[libc::c_char]| {
        // SAFETY: uname(2) NUL-terminates every field of the 65-byte arrays.
        unsafe { CStr::from_ptr(c.as_ptr()) }
            .to_string_lossy()
            .into_owned()
    };
    Uname {
        sysname: field(&u.sysname),
        release: field(&u.release),
        machine: field(&u.machine),
    }
}

fn check_platform() -> Check {
    let u = uname();
    ok(
        "platform",
        format!("{} {} ({})", u.sysname, u.machine, std::env::consts::ARCH),
    )
}

// ------------------------------------------------------------------ kernel

fn check_kernel() -> Check {
    let u = uname();
    let min = format!("{}.{}", MIN_KERNEL.0, MIN_KERNEL.1);
    match parse_kernel_version(&u.release) {
        Some(v) if v >= MIN_KERNEL => ok("kernel", format!("{} (>= {min})", u.release)),
        Some(_) => fail("kernel", format!("{} is older than {min}", u.release), KERNEL_FIX),
        None => fail(
            "kernel",
            format!("cannot parse kernel release {:?}", u.release),
            KERNEL_FIX,
        ),
    }
}

/// `6.18.58.1-microsoft-standard-WSL2` → `(6, 18)`.
fn parse_kernel_version(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.split('-').next()?.split('.');
    Some((parts.next()?.parse().ok()?, parts.next()?.parse().ok()?))
}

// ------------------------------------------------------- user namespaces

fn check_userns_limit() -> Check {
    let path = "/proc/sys/user/max_user_namespaces";
    match read_trim(path) {
        Ok(s) => match s.parse::<u64>() {
            Ok(0) => fail(
                "userns.max",
                "user.max_user_namespaces=0 (user namespaces are disabled)".to_string(),
                USERNS_FIX,
            ),
            Ok(_) => ok("userns.max", format!("user.max_user_namespaces={s}")),
            Err(_) => fail("userns.max", format!("{path} holds {s:?}"), USERNS_FIX),
        },
        Err(e) => fail("userns.max", format!("cannot read {path}: {e}"), USERNS_FIX),
    }
}

fn check_apparmor() -> Check {
    let path = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";
    match read_trim(path) {
        Ok(s) if s == "0" => ok(
            "userns.apparmor",
            "kernel.apparmor_restrict_unprivileged_userns=0".to_string(),
        ),
        Ok(s) => fail(
            "userns.apparmor",
            format!("kernel.apparmor_restrict_unprivileged_userns={s} (AppArmor blocks unprivileged user namespaces)"),
            "sysctl -w kernel.apparmor_restrict_unprivileged_userns=0",
        ),
        Err(e) if e.kind() == io::ErrorKind::NotFound => ok(
            "userns.apparmor",
            "kernel.apparmor_restrict_unprivileged_userns is not present (no AppArmor restriction)".to_string(),
        ),
        Err(e) => fail(
            "userns.apparmor",
            format!("cannot read {path}: {e}"),
            "make /proc/sys/kernel readable",
        ),
    }
}

fn check_userns_probe() -> Check {
    match probe_userns() {
        Ok(()) => ok(
            "userns.probe",
            "unshare(CLONE_NEWUSER) succeeded in a forked child".to_string(),
        ),
        Err(e) => fail("userns.probe", e, USERNS_FIX),
    }
}

/// Forks a throwaway child that only calls `unshare(CLONE_NEWUSER)` and exits
/// with the errno. The child never touches the interpreter, so no Python fork
/// hooks are needed.
fn probe_userns() -> Result<(), String> {
    // SAFETY: see above; the parent just waits.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!("fork failed: {}", io::Error::last_os_error()));
    }
    if pid == 0 {
        // SAFETY: raw syscalls only, then _exit(2) which never flushes anything.
        let r = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
        let code = if r == 0 {
            0
        } else {
            unsafe { *libc::__errno_location() }
        };
        unsafe { libc::_exit(code) };
    }
    let mut status: libc::c_int = 0;
    loop {
        // SAFETY: `status` is a valid out-pointer.
        if unsafe { libc::waitpid(pid, &mut status, 0) } >= 0 {
            break;
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(format!("waitpid failed: {e}"));
        }
    }
    if libc::WIFEXITED(status) {
        match libc::WEXITSTATUS(status) {
            0 => Ok(()),
            code => Err(format!(
                "unshare(CLONE_NEWUSER) failed in a forked child: {}",
                io::Error::from_raw_os_error(code)
            )),
        }
    } else if libc::WIFSIGNALED(status) {
        Err(format!(
            "the user namespace probe child was killed by signal {}",
            libc::WTERMSIG(status)
        ))
    } else {
        Err("the user namespace probe child did not exit normally".to_string())
    }
}

// ------------------------------------------------------------------ cgroup

fn check_cgroup() -> Check {
    match cgroup::singleton() {
        Ok(base) => ok(
            "cgroup",
            format!(
                "delegated subtree {} (cpu memory pids enabled; this process parked in {})",
                base.base.display(),
                base.river.display()
            ),
        ),
        Err(e) => fail("cgroup", e, CGROUP_FIX),
    }
}

// ----------------------------------------------------------------- workdir

fn check_workdir() -> Check {
    match workdir_base() {
        Ok(p) => ok(
            "workdir",
            format!("{} (sandbox /work directories live here)", p.display()),
        ),
        Err(e) => fail("workdir", e, WORKDIR_FIX),
    }
}

/// Where sandbox `/work` directories live: `$XDG_RUNTIME_DIR/river`, otherwise
/// `/dev/shm/river-<uid>` (design.md §10). Created with mode 0700 and verified
/// to be owned by the current user.
pub fn workdir_base() -> Result<PathBuf, String> {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .filter(|p| p.is_absolute() && p.is_dir())
        .map(|p| p.join("river"))
        .unwrap_or_else(|| PathBuf::from(format!("/dev/shm/river-{}", euid())));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&base)
        .or_else(|e| if e.kind() == io::ErrorKind::AlreadyExists { Ok(()) } else { Err(e) })
        .map_err(|e| format!("cannot create {}: {e}", base.display()))?;
    let meta = fs::metadata(&base).map_err(|e| format!("cannot stat {}: {e}", base.display()))?;
    if meta.uid() != euid() {
        return Err(format!(
            "{} is owned by uid {}, not by the current user",
            base.display(),
            meta.uid()
        ));
    }
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("cannot chmod 0700 {}: {e}", base.display()))?;
    Ok(base)
}

fn euid() -> u32 {
    // SAFETY: geteuid(2) has no preconditions.
    unsafe { libc::geteuid() }
}

// ---------------------------------------------------------------- landlock

fn check_landlock_abi() -> Check {
    // Informational only: a kernel without Landlock just runs without the
    // filesystem hardening layer (design.md §9).
    let detail = match crate::exec::landlock::probe_abi() {
        Ok(abi) => format!("Landlock ABI v{abi}"),
        Err(e) if e.raw_os_error() == Some(libc::ENOSYS) => {
            "Landlock is not available on this kernel (ENOSYS); filesystem hardening will be disabled"
                .to_string()
        }
        Err(e) => format!("Landlock ABI probe failed: {e}"),
    };
    ok("landlock_abi", detail)
}

// ------------------------------------------------------------------ rootfs

/// Directories and regular files river needs as mount points inside the rootfs
/// (design.md §5, §8). Missing ones are always created; existing ones untouched.
const MOUNT_DIRS: [&str; 7] = ["proc", "sys", "dev/pts", "dev/shm", "dev/mqueue", "tmp", "work"];
const MOUNT_FILES: [&str; 6] =
    ["dev/null", "dev/zero", "dev/full", "dev/random", "dev/urandom", "dev/ptmx"];

pub struct RootfsInfo {
    /// Canonical absolute path of the rootfs.
    pub path: PathBuf,
    /// `envs` from `<rootfs>/meta.json`; `None` when the file does not exist.
    pub envs: Option<HashMap<String, String>>,
}

/// The rootfs half of the preflight (`River()` only: `doctor()` has no rootfs).
pub fn check_rootfs(py: Python<'_>, rootfs: &Path) -> PyResult<RootfsInfo> {
    let path = fs::canonicalize(rootfs)
        .map_err(|e| RootfsError::new_err(format!("rootfs {}: {e}", rootfs.display())))?;
    if !path.is_dir() {
        return Err(RootfsError::new_err(format!(
            "rootfs {} is not a directory",
            path.display()
        )));
    }
    for dir in MOUNT_DIRS {
        ensure_mount_point(&path, dir, true)?;
    }
    for file in MOUNT_FILES {
        ensure_mount_point(&path, file, false)?;
    }
    let meta = path.join("meta.json");
    let envs = match fs::read_to_string(&meta) {
        Ok(text) => Some(parse_meta(py, &meta, &text)?),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(RootfsError::new_err(format!("{}: {e}", meta.display()))),
    };
    Ok(RootfsInfo { path, envs })
}

fn ensure_mount_point(rootfs: &Path, rel: &str, is_dir: bool) -> PyResult<()> {
    let path = rootfs.join(rel);
    match fs::symlink_metadata(&path) {
        Ok(_) => return Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(RootfsError::new_err(format!(
                "cannot inspect mount point {}: {e}",
                path.display()
            )));
        }
    }
    let created = if is_dir {
        fs::create_dir_all(&path).map(|_| ())
    } else {
        fs::File::create(&path).map(|_| ())
    };
    created.map_err(|e| {
        RootfsError::new_err(format!("cannot create mount point {}: {e}", path.display()))
    })
}

/// `meta.json` (design.md §4.1): only `envs` is defined; unknown keys are ignored.
fn parse_meta(py: Python<'_>, meta: &Path, text: &str) -> PyResult<HashMap<String, String>> {
    let parsed = (|| -> PyResult<HashMap<String, String>> {
        let json = py.import("json")?;
        let meta: Bound<'_, PyDict> = json.call_method1("loads", (text,))?.extract()?;
        let envs = meta.get_item("envs")?.map(|envs| envs.extract()).transpose()?;
        Ok(envs.unwrap_or_default())
    })();
    parsed.map_err(|e| RootfsError::new_err(format!("{}: {e}", meta.display())))
}
