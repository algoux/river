//! cgroup v2: delegation detection and the per-process `river/` singleton
//! (design.md §7, steps 1–5). Per-run cgroups are added in a later PR.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const CONTROLLERS: [&str; 3] = ["cpu", "memory", "pids"];

/// The delegated subtree the calling process lives in.
pub struct CgroupBase {
    /// Delegated cgroup, e.g.
    /// `/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/run-r123.scope`.
    pub base: PathBuf,
    /// `<base>/river`: this process is parked here so that `<base>` itself holds
    /// no processes and can enable the domain controllers for its children.
    pub river: PathBuf,
}

static SINGLETON: OnceLock<Result<Arc<CgroupBase>, String>> = OnceLock::new();

/// design.md §7 steps 1–5. The outcome (success or failure) is cached for the
/// lifetime of the process: delegation does not change under a running process.
pub fn singleton() -> Result<Arc<CgroupBase>, String> {
    SINGLETON.get_or_init(init).clone()
}

fn init() -> Result<Arc<CgroupBase>, String> {
    // 1. cgroup v2 at the unified mount point.
    let root_controllers = Path::new(CGROUP_ROOT).join("cgroup.controllers");
    read_trim(&root_controllers).map_err(|_| format!("cgroup v2 is not mounted at {CGROUP_ROOT}"))?;

    // 2. Locate our own cgroup.
    let base = current_cgroup()?;

    // 3. It must expose the controllers river needs.
    let controllers = base.join("cgroup.controllers");
    let available =
        read_trim(&controllers).map_err(|e| format!("cannot read {}: {e}", controllers.display()))?;
    let missing: Vec<&str> = CONTROLLERS
        .iter()
        .copied()
        .filter(|c| !available.split_whitespace().any(|a| a == *c))
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "{} exposes controllers '{}' but river also needs '{}' (not delegated)",
            base.display(),
            available,
            missing.join(" ")
        ));
    }

    // 4. Park this process in <base>/river so that <base> holds no processes.
    let river = base.join("river");
    fs::create_dir(&river)
        .or_else(|e| if e.kind() == io::ErrorKind::AlreadyExists { Ok(()) } else { Err(e) })
        .map_err(|e| format!("cannot create {}: {e} (not delegated to this user)", river.display()))?;
    write_file(&river.join("cgroup.procs"), std::process::id().to_string())?;

    // 5. Enable the domain controllers below <base>. EACCES/EPERM mean "not delegated";
    //    EBUSY means other processes still live in <base> (a `uv run`/`make` parent, say).
    let subtree_control = base.join("cgroup.subtree_control");
    let enabled = CONTROLLERS.iter().map(|c| format!("+{c}")).collect::<Vec<_>>().join(" ");
    fs::write(&subtree_control, enabled).map_err(|e| match e.raw_os_error() {
        Some(libc::EBUSY) => format!(
            "cannot enable controllers in {}: {e}; other processes still live in {} ({}): \
             river needs a cgroup that holds only its own process, e.g. \
             `systemd-run --user --scope -p Delegate=yes -- .venv/bin/python app.py` \
             instead of wrapping it in `uv run`/`make`",
            subtree_control.display(),
            base.display(),
            procs_of(&base)
        ),
        _ => format!(
            "cannot write {}: {e} (not delegated to this user)",
            subtree_control.display()
        ),
    })?;

    Ok(Arc::new(CgroupBase { base, river }))
}

/// `pid comm` of every process in `dir/cgroup.procs`, for diagnostics.
fn procs_of(dir: &Path) -> String {
    let procs = fs::read_to_string(dir.join("cgroup.procs"))
        .map(|s| s.split_whitespace().map(str::to_string).collect::<Vec<_>>())
        .unwrap_or_default();
    let listed: Vec<String> = procs
        .iter()
        .map(|pid| {
            let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
                .map(|c| c.trim().to_string())
                .unwrap_or_else(|_| '?'.to_string());
            format!("pid {pid} ({comm})")
        })
        .collect();
    if listed.is_empty() {
        "none".to_string()
    } else {
        listed.join(", ")
    }
}

fn write_file(path: &Path, data: String) -> Result<(), String> {
    fs::write(path, data)
        .map_err(|e| format!("cannot write {}: {e} (not delegated to this user)", path.display()))
}

fn current_cgroup() -> Result<PathBuf, String> {
    let text = fs::read_to_string("/proc/self/cgroup")
        .map_err(|e| format!("cannot read /proc/self/cgroup: {e}"))?;
    let rel = text
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| {
            "this process is not on the unified cgroup v2 hierarchy (/proc/self/cgroup has no '0::' line)"
                .to_string()
        })?;
    Ok(Path::new(CGROUP_ROOT).join(rel.trim_start_matches('/')))
}

fn read_trim(path: &Path) -> io::Result<String> {
    fs::read_to_string(path).map(|s| s.trim().to_string())
}
