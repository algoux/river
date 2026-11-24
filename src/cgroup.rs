//! cgroup v2: delegation detection, the per-process `river/` singleton
//! and the per-run cgroups.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const CONTROLLERS: [&str; 3] = ["cpu", "memory", "pids"];

/// The delegated subtree the calling process lives in.
pub struct CgroupBase {
    /// Delegated cgroup, e.g.
    /// `/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/run-r123.scope`.
    pub base: PathBuf,
    /// `<base>/river`: every process of `<base>` — this one and any wrapper
    /// parent still alive (`uv run`, `make`, ...) — is parked here so that
    /// `<base>` itself holds no processes and can enable the domain controllers
    /// for its children.
    pub river: PathBuf,
}

static SINGLETON: OnceLock<Result<Arc<CgroupBase>, String>> = OnceLock::new();

/// Establishes the delegated-subtree singleton, steps 1–5. The outcome
/// (success or failure) is cached for the lifetime of the process:
/// delegation does not change under a running process.
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

    // 4. Park every process of <base> — this one and any wrapper parent still alive
    //    (`uv run`, `make`, a shell) — in <base>/river so that <base> holds no
    //    processes. A pid that cannot be moved (another user's) is left for step 5
    //    to report; the passes catch a child forked by a wrapper during the move.
    let river = base.join("river");
    fs::create_dir(&river)
        .or_else(|e| if e.kind() == io::ErrorKind::AlreadyExists { Ok(()) } else { Err(e) })
        .map_err(|e| format!("cannot create {}: {e} (not delegated to this user)", river.display()))?;
    let river_procs = river.join("cgroup.procs");
    write_file(&river_procs, std::process::id().to_string())?;
    let base_procs = base.join("cgroup.procs");
    for _ in 0..3 {
        let procs = fs::read_to_string(&base_procs).unwrap_or_default();
        if procs.trim().is_empty() {
            break;
        }
        for pid in procs.split_whitespace() {
            let _ = fs::write(&river_procs, format!("{pid}\n"));
        }
    }

    // 5. Enable the domain controllers below <base>. EACCES/EPERM mean "not delegated";
    //    EBUSY means processes still live in <base> that step 4 could not move.
    let subtree_control = base.join("cgroup.subtree_control");
    let enabled = CONTROLLERS.iter().map(|c| format!("+{c}")).collect::<Vec<_>>().join(" ");
    fs::write(&subtree_control, enabled).map_err(|e| match e.raw_os_error() {
        Some(libc::EBUSY) => format!(
            "cannot enable controllers in {}: {e}; processes still live in {} ({}) and could not be \
             moved into {} (another user's?); river moves every process of the cgroup there, \
             so a wrapper parent such as `uv run`/`make` is fine",
            subtree_control.display(),
            base.display(),
            procs_of(&base),
            river.display()
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

// ------------------------------------------------------------------ per-run

/// The knobs the exec() limits put on the run cgroup. Every
/// `None` field means the knob is never written: a limit of `None` must
/// leave the cgroup file at its default.
pub struct RunKnobs {
    pub memory_limit_bytes: Option<u64>,
    pub proc_limit: Option<u64>,
}

/// Metrics of one finished run, read from its cgroup before removal.
pub struct RunMetrics {
    pub cpu_time_used_ms: u64,
    pub memory_used_bytes: u64,
    /// `memory.events` reported an OOM kill in this cgroup.
    pub oom_kill: bool,
}

/// One exec's cgroup `<base>/river-<pid>-<seq>`: the limit
/// knobs live here, the sandbox tree runs here, `cgroup.kill` clears it and
/// the metrics are read from it before the `rmdir`. Dropping without
/// `finish()` is the failure-path cleanup.
pub struct RunCgroup {
    dir: PathBuf,
    finished: AtomicBool,
}

impl RunCgroup {
    /// Create the cgroup and write the knobs
    /// before the child exists, so every limit is in force before "go".
    pub fn create(knobs: &RunKnobs) -> Result<Self, String> {
        let base = singleton()?;
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = base.base.join(format!(
            "river-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir)
            .map_err(|e| format!("cannot create run cgroup {}: {e}", dir.display()))?;
        if let Some(bytes) = knobs.memory_limit_bytes {
            write_knob(&dir, "memory.max", &bytes.to_string())?;
            write_knob(&dir, "memory.swap.max", "0")?;
            write_knob(&dir, "memory.oom.group", "1")?;
        }
        if let Some(pids) = knobs.proc_limit {
            write_knob(&dir, "pids.max", &pids.to_string())?;
        }
        Ok(RunCgroup {
            dir,
            finished: AtomicBool::new(false),
        })
    }

    /// The cgroup's path, for logging and diagnostics.
    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// Move the freshly cloned child in; the caller
    /// sends "go" right after, so every limit precedes the first sandboxed
    /// instruction.
    pub fn attach(&self, pid: i32) -> Result<(), String> {
        write_knob(&self.dir, "cgroup.procs", &pid.to_string())
    }

    /// Atomic kill of every process in the cgroup (5.14+).
    pub fn kill(&self) {
        let _ = fs::write(self.dir.join("cgroup.kill"), b"1");
    }

    /// Wait until `cgroup.events` reports `populated 0`: after the pid-1
    /// reap the namespace teardown is normally
    /// instantaneous, and the cap only guards against a stuck straggler.
    fn wait_empty(&self, cap: Duration) -> bool {
        let deadline = Instant::now() + cap;
        loop {
            match read_trim(&self.dir.join("cgroup.events")) {
                Ok(text) => {
                    if text.lines().any(|line| line == "populated 0") {
                        return true;
                    }
                }
                Err(_) => return true, // already removed
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// Wait for the teardown, read `cpu.stat` / `memory.peak` /
    /// `memory.events`, then `rmdir`. The run already
    /// happened, so an unreadable file degrades to zero instead of failing.
    pub fn finish(&self) -> RunMetrics {
        if !self.wait_empty(Duration::from_secs(5)) {
            // A process refuses to die (D state, say): force the kill once
            // more, wait a little longer, then read what is still there.
            self.kill();
            self.wait_empty(Duration::from_secs(2));
        }
        let cpu_time_used_ms = read_trim(&self.dir.join("cpu.stat"))
            .ok()
            .and_then(|s| {
                s.lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|usec| usec.parse::<u64>().ok())
            })
            .map_or(0, |usec| usec.div_ceil(1000));
        let memory_used_bytes = read_trim(&self.dir.join("memory.peak"))
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        let oom_kill = read_trim(&self.dir.join("memory.events")).map_or(false, |text| {
            oom_event(&text, "oom_kill") || oom_event(&text, "oom_group_kill")
        });
        self.finished.store(true, Ordering::Release);
        let _ = fs::remove_dir(&self.dir);
        RunMetrics {
            cpu_time_used_ms,
            memory_used_bytes,
            oom_kill,
        }
    }
}

impl Drop for RunCgroup {
    /// Failure-path cleanup: no live process and no cgroup
    /// directory survive an exec that bailed out mid-run.
    fn drop(&mut self) {
        if !self.finished.swap(true, Ordering::AcqRel) {
            self.kill();
            self.wait_empty(Duration::from_secs(2));
            let _ = fs::remove_dir(&self.dir);
        }
    }
}

/// `memory.events`: did the counter `name` ever tick (the MLE verdict's source)? A
/// group OOM kill shows up as `oom_group_kill`; both count as OOM evidence.
fn oom_event(text: &str, name: &str) -> bool {
    text.lines().any(|line| {
        let mut fields = line.split_whitespace();
        fields.next() == Some(name) && fields.next().is_some_and(|count| count != "0")
    })
}

fn write_knob(dir: &Path, name: &str, value: &str) -> Result<(), String> {
    fs::write(dir.join(name), value)
        .map_err(|e| format!("cannot write {} in {}: {e}", name, dir.display()))
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
