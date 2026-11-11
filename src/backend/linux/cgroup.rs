//! cgroups v2 session: one directory per sandbox session under
//! `/sys/fs/cgroup`, one child group per run. The run group limits CPU,
//! memory (with swap off) and process count, and is where the sandboxed
//! child is placed at birth (`clone3(CLONE_INTO_CGROUP)`), so no fast
//! payload can spend cycles outside the limits.
//!
//! Accounting after the run: `cpu.stat` (`usage_usec`), `memory.peak` and
//! `memory.events` (`oom_kill`).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Controllers the run groups need; enabled in the session group's
/// subtree_control so the per-run children get them.
const CONTROLLERS: &[&str] = &["cpu", "memory", "pids"];

/// Fork-bomb ceiling per run; no knob until someone needs one.
const MAX_PROCESSES: &str = "256";

/// The session cgroup directory; created on `__enter__`, destroyed on
/// `__exit__`.
pub(crate) struct Session {
    path: PathBuf,
    run_sequence: u64,
}

impl Session {
    /// Creates `river-<pid>.<seq>` under the unified hierarchy root.
    pub(crate) fn create() -> io::Result<Self> {
        static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = Path::new("/sys/fs/cgroup").join(format!(
            "river-{}.{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        let session = Self {
            path,
            run_sequence: 0,
        };
        // Enable the controllers for the per-run children; the controllers
        // in the session group itself come from the root's subtree_control.
        let mut wanted = String::new();
        for controller in CONTROLLERS {
            if !session.controller_available(controller)? {
                return Err(io::Error::other(format!(
                    "cgroup controller `{controller}` is not available in {}",
                    session.path.display()
                )));
            }
            wanted.push_str(&format!("+{controller} "));
        }
        write(&session.path.join("cgroup.subtree_control"), &wanted)?;
        Ok(session)
    }

    fn controller_available(&self, controller: &str) -> io::Result<bool> {
        let controllers = fs::read_to_string(self.path.join("cgroup.controllers"))?;
        Ok(controllers.split_whitespace().any(|name| name == controller))
    }

    /// Creates the per-run child group with the given limits applied.
    pub(crate) fn run_group(
        &mut self,
        cpu_time_limit_ms: Option<u64>,
        memory_limit_bytes: Option<u64>,
    ) -> io::Result<RunGroup> {
        self.run_sequence += 1;
        let path = self.path.join(format!("run-{}", self.run_sequence));
        fs::create_dir(&path)?;

        if let Some(limit_ms) = cpu_time_limit_ms {
            // Quota in microseconds over the default 100ms period; a quota
            // below the kernel minimum of 1000us is raised to it.
            let quota = (limit_ms * 1000).max(1000);
            write(&path.join("cpu.max"), &format!("{quota} 100000"))?;
        }
        if let Some(limit) = memory_limit_bytes {
            write(&path.join("memory.max"), &limit.to_string())?;
            // Without this the payload could dodge the cap into swap.
            write(&path.join("memory.swap.max"), "0")?;
        }
        write(&path.join("pids.max"), MAX_PROCESSES)?;
        Ok(RunGroup { path })
    }

    /// Kills every process left in the session and removes the directory
    /// tree. Best effort: teardown must not mask the run's own errors.
    pub(crate) fn destroy(self) {
        let _ = write(&self.path.join("cgroup.kill"), "1");
        let _ = remove_tree(&self.path);
    }
}

/// One run's cgroup: limits already applied, the child is born into it.
pub(crate) struct RunGroup {
    path: PathBuf,
}

/// Post-run resource accounting.
pub(crate) struct RunStats {
    pub cpu_time_used_us: u64,
    pub memory_used_bytes: u64,
    pub oom_kills: u64,
}

impl RunGroup {
    /// The directory to pass as `clone3(CLONE_INTO_CGROUP)` target.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the counters after the child is reaped.
    pub(crate) fn stats(&self) -> io::Result<RunStats> {
        let cpu_stat = fs::read_to_string(self.path.join("cpu.stat"))?;
        let events = fs::read_to_string(self.path.join("memory.events"))?;
        // memory.peak landed in 5.19; a missing file reads as zero.
        let peak = fs::read_to_string(self.path.join("memory.peak"))
            .ok()
            .and_then(|value| parse_number(&value))
            .unwrap_or(0);
        Ok(RunStats {
            cpu_time_used_us: field(&cpu_stat, "usage_usec").unwrap_or(0),
            memory_used_bytes: peak,
            oom_kills: field(&events, "oom_kill").unwrap_or(0),
        })
    }

    /// Removes the (now process-free) run group.
    pub(crate) fn remove(self) {
        let _ = fs::remove_dir(&self.path);
    }
}

fn field(contents: &str, name: &str) -> Option<u64> {
    contents
        .lines()
        .find_map(|line| line.strip_prefix(name))
        .and_then(parse_number)
}

fn parse_number(text: &str) -> Option<u64> {
    text.trim().parse().ok()
}

fn write(path: &Path, contents: &str) -> io::Result<()> {
    fs::write(path, contents)
        .map_err(|error| io::Error::other(format!("{}: {error}", path.display())))
}

/// Removes a cgroup directory tree bottom-up: rmdir only works on groups
/// with no member processes and no child groups.
fn remove_tree(path: &Path) -> io::Result<()> {
    let entries = fs::read_dir(path)?;
    for entry in entries {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            remove_tree(&entry.path())?;
        }
    }
    fs::remove_dir(path)
}
