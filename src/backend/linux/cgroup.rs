//! cgroups v2 integration.
//!
//! Every run gets a private cgroup under `/sys/fs/cgroup/river/`:
//!
//! ```text
//! /sys/fs/cgroup/river/cgroup.subtree_control  "+memory +pids"  (once)
//! /sys/fs/cgroup/river/run-<judger-pid>-<n>/
//!     memory.max      caller limit, or physical memory as the ceiling
//!     pids.max        live-process cap (default 64, ceilings)
//!     cpu.stat        usage_usec — CPU of the whole tree
//!     memory.peak     peak RSS (+ page cache) of the whole tree
//!     cgroup.procs    membership: residual-descendant detection
//!     cgroup.kill     "1" = SIGKILL the whole subtree atomically
//! ```
//!
//! The **supervisor** (ns.rs) writes its own pid into `cgroup.procs` right
//! after `setsid`, before it forks the program: cgroup membership is
//! inherited by children, so the program and all its descendants are
//! accounted (and killed) together. Doing it from the judger would race the
//! supervisor's fork.
//!
//! Verdicts are still the contract's job: this module only reports numbers.

use std::fs;
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const RIVER_DIR: &str = "river";

/// Environment override for the cgroup2 mount point (a container/delegated
/// deployment may root the hierarchy elsewhere, e.g. inside a systemd
/// scope). Defaults to the standard unified mount.
const CGROUP_ROOT_ENV: &str = "RIVER_CGROUP_ROOT";
const DEFAULT_CGROUP_ROOT: &str = "/sys/fs/cgroup";

static RUN_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The configured cgroup2 mount point.
pub(crate) fn cgroup_root() -> PathBuf {
    PathBuf::from(std::env::var_os(CGROUP_ROOT_ENV).unwrap_or_else(|| DEFAULT_CGROUP_ROOT.into()))
}

/// A per-run cgroup; removed on drop (best effort — a leaked directory is
/// reclaimed by the next sweep).
pub(crate) struct Cgroup {
    path: PathBuf,
    /// Exclusive `flock` on the cgroup directory, held for the run's
    /// lifetime — exactly the protocol the workdir uses with its sibling lock file.
    /// `sweep_stale_cgroups` treats "lock acquirable" as "owner is gone";
    /// without this the sweep would reclaim live groups (a run started by
    /// another thread/process was killed within milliseconds — verified).
    ///
    /// `None` only when the filesystem rejects `flock`; the sweep then falls
    /// back to the `/proc/<pid>` liveness check, which is safe for live
    /// owners (the pid exists).
    _owner: Option<fs::File>,
    /// `cpu.stat` kept open for the run's lifetime.
    ///
    /// The monitor reads the tree's CPU time every 10 ms while a CPU limit
    /// is set — 100 reads/second per run. Re-opening the file each time
    /// (`fs::read_to_string`) costs a measured **~15 µs** per poll versus
    /// **~1.5 µs** for a `pread` on a held descriptor (11x, measured on
    /// cgroupfs), which at 100 concurrent runs is ~135 ms/s of judge CPU.
    ///
    /// `None` if the file could not be opened at creation; the reader then
    /// falls back to `read_to_string`.
    cpu_stat: Option<fs::File>,
}

impl Cgroup {
    /// Create the per-run cgroup and write its limits. Must be called by the
    /// judger **before** the spawn so the supervisor's membership write and
    /// the program's first allocations are already limited.
    pub(crate) fn create(memory_limit_bytes: u64, max_pids: u32) -> io::Result<Self> {
        let base = cgroup_root();
        if !base.join("cgroup.controllers").exists() {
            return Err(io::Error::other(format!(
                "cgroups v2 not mounted at {} (river supports v2 only; \
                 set {CGROUP_ROOT_ENV} for a delegated hierarchy)",
                base.display()
            )));
        }
        let river = base.join(RIVER_DIR);
        fs::create_dir_all(&river)?;
        // Enable the controllers for children of `river`. Writing the same
        // values again is harmless; a missing controller is a hard error
        // because the limit contract would silently not be enforced.
        write_file(&river.join("cgroup.subtree_control"), "+memory +pids\n")?;

        let n = RUN_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = river.join(format!("run-{}-{n}", std::process::id()));
        // A stale directory from a crashed judger with the same pid+counter
        // cannot parse as live if empty; try to remove it once.
        if path.exists() {
            let _ = fs::remove_dir(&path);
        }
        fs::create_dir(&path)?;

        // Take the ownership lock *before* writing any limit: a sweep must
        // never see a half-initialised group without an owner.
        let owner = lock_owner(&path).ok();
        // Opened before `path` moves into the struct; a failure only costs
        // the read_to_string fallback, so it is not fatal.
        let cpu_stat = fs::File::open(path.join("cpu.stat")).ok();
        let cg = Cgroup {
            path,
            _owner: owner,
            cpu_stat,
        };
        write_file(&cg.file("memory.max"), &format!("{memory_limit_bytes}\n"))?;
        // Swap must be excluded from the limit: with `memory.swap.max=max`
        // (the default) a slow allocator can keep pushing pages to swap and
        // stay charged below `memory.max` forever, so the kernel never OOMs
        // it and the run only ends at the wall clock (measured: 20s at a
        // 64MB cap vs 1.6s with swap disabled). Older kernels without the
        // knob keep the old behaviour.
        if let Err(e) = write_file(&cg.file("memory.swap.max"), "0\n")
            && e.kind() != io::ErrorKind::NotFound
        {
            return Err(e);
        }
        write_file(&cg.file("pids.max"), &format!("{max_pids}\n"))?;
        Ok(cg)
    }

    fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    /// Path of `cgroup.procs` as a `CString` for the supervisor's raw-syscall
    /// membership write (built pre-fork, no allocation in the child).
    pub(crate) fn procs_path_c(&self) -> io::Result<std::ffi::CString> {
        std::ffi::CString::new(
            self.file("cgroup.procs")
                .to_str()
                .ok_or_else(|| io::Error::other("non-UTF8 cgroup path"))?,
        )
        .map_err(|_| io::Error::other("NUL in cgroup path"))
    }

    /// Did the kernel OOM killer reap a task in this cgroup during the run?
    /// `memory.events` `oom_kill` is the **direct** evidence for `MLE`
    /// (better than inferring it from `memory.peak`).
    pub(crate) fn oom_killed(&self) -> io::Result<bool> {
        let text = fs::read_to_string(self.file("memory.events"))?;
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("oom_kill ") {
                let n: u64 = rest
                    .trim()
                    .parse()
                    .map_err(|_| io::Error::other("bad oom_kill count in memory.events"))?;
                return Ok(n > 0);
            }
        }
        Ok(false)
    }

    /// CPU time of the whole tree, microseconds (`cpu.stat` `usage_usec`).
    ///
    /// Reads through the descriptor opened at creation when possible (see
    /// [`Cgroup::cpu_stat`]): this runs 100x/second per run while a CPU limit
    /// is set, and a `pread` is ~11x cheaper than re-opening the file.
    pub(crate) fn usage_usec(&self) -> io::Result<u64> {
        let text = match &self.cpu_stat {
            Some(f) => {
                // `cpu.stat` is a small seq_file; 256 bytes hold every
                // counter comfortably. `read_at` returns the byte count, so
                // a short read is handled (we never assume it fills the
                // buffer).
                let mut buf = [0u8; 256];
                let n = f.read_at(&mut buf, 0)?;
                String::from_utf8_lossy(&buf[..n]).into_owned()
            }
            None => fs::read_to_string(self.file("cpu.stat"))?,
        };
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("usage_usec ") {
                return rest
                    .trim()
                    .parse()
                    .map_err(|_| io::Error::other("bad usage_usec"));
            }
        }
        Err(io::Error::other("usage_usec missing from cpu.stat"))
    }

    /// Peak memory of the whole tree, bytes (`memory.peak`).
    pub(crate) fn peak_bytes(&self) -> io::Result<u64> {
        fs::read_to_string(self.file("memory.peak"))?
            .trim()
            .parse()
            .map_err(|_| io::Error::other("bad memory.peak"))
    }

    /// Pids currently in the cgroup (`cgroup.procs`). Empty means the tree
    /// is fully gone.
    pub(crate) fn live_pids(&self) -> io::Result<Vec<libc::pid_t>> {
        let text = fs::read_to_string(self.file("cgroup.procs"))?;
        Ok(text
            .lines()
            .filter_map(|l| l.trim().parse::<libc::pid_t>().ok())
            .collect())
    }

    /// SIGKILL every process in the subtree atomically (`cgroup.kill`, Linux
    /// 5.14+). Falls back to per-pid kills when the knob is missing.
    pub(crate) fn kill_all(&self) -> io::Result<()> {
        if write_file(&self.file("cgroup.kill"), "1\n").is_ok() {
            return Ok(());
        }
        for pid in self.live_pids()? {
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
        Ok(())
    }

    /// Wait until the cgroup is empty (bounded), returning the number of
    /// processes that survived the grace period. Used for anti-cheat
    /// residual detection after the main process exited.
    pub(crate) fn wait_until_empty(&self, timeout: std::time::Duration) -> io::Result<u32> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let pids = self.live_pids()?;
            if pids.is_empty() {
                return Ok(0);
            }
            if std::time::Instant::now() >= deadline {
                return Ok(pids.len() as u32);
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        // Release the ownership lock first: a concurrent sweep may be
        // waiting for it, and rmdir itself must not be blocked by our own
        // open descriptor. A leftover directory is reclaimed by the sweep.
        self._owner.take();
        // Best effort: rmdir fails while processes remain; the next sweep
        // (stage L5) reclaims abandoned directories.
        let _ = fs::remove_dir(&self.path);
    }
}

fn write_file(path: &Path, data: &str) -> io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .truncate(false)
        .open(path)?;
    f.write_all(data.as_bytes())?;
    f.flush()
}

/// Total physical memory in bytes, from `/proc/meminfo` `MemTotal`.
pub(crate) fn physical_memory_bytes() -> io::Result<u64> {
    let data = fs::read_to_string("/proc/meminfo")?;
    for line in data.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kb: u64 = rest
                .trim()
                .trim_end_matches(" kB")
                .trim()
                .parse()
                .map_err(|_| io::Error::other("cannot parse /proc/meminfo MemTotal"))?;
            return Ok(kb * 1024);
        }
    }
    Err(io::Error::other("MemTotal missing in /proc/meminfo"))
}

/// Best-effort sweep of per-run cgroups abandoned by a dead judger (the
/// judger was hard-killed before `Drop` could `rmdir`).
///
/// Ownership is decided by a **flock on the directory fd itself** (cgroupfs
/// directories accept `flock`), exactly like the workdir's lock file: pids
/// are reused within milliseconds, so a name-encoded pid alone would make a
/// just-killed judger's cgroup look alive. When the filesystem rejects
/// `flock`, the pid check is used as a fallback.
///
/// A stale group may still have members if the watchdog failed: they are
/// SIGKILLed, then the directory is removed (retrying briefly on `EBUSY`,
/// and never silently leaving the group behind).
pub(crate) fn sweep_stale_cgroups() {
    static SWEEP_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = SWEEP_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let river = cgroup_root().join(RIVER_DIR);
    let entries = match fs::read_dir(&river) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(pid) = name.strip_prefix("run-").and_then(|r| r.split('-').next()) else {
            continue;
        };
        let Ok(pid) = pid.parse::<u32>() else {
            continue;
        };
        let stale = Cgroup {
            path: entry.path(),
            _owner: None,
            // The sweep only needs the path and the lock; it never reads
            // metrics from a cgroup it is about to reclaim.
            cpu_stat: None,
        };
        let free = lock_dir(&stale.path);
        match free {
            Some(true) => {}         // owner gone
            Some(false) => continue, // live run
            None => {
                // flock unsupported here: fall back to the pid check.
                if Path::new(&format!("/proc/{pid}")).exists() {
                    continue;
                }
            }
        }
        let _ = stale.kill_all();
        let _ = stale.wait_until_empty(std::time::Duration::from_millis(50));
        drop(stale);
        // rmdir can briefly fail with EBUSY while the last task is torn
        // down; retry a few times rather than leaking the group.
        for _ in 0..10 {
            if !entry.path().exists() {
                break;
            }
            if fs::remove_dir(entry.path()).is_ok() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
}

/// Take the exclusive, non-blocking ownership lock on a cgroup directory.
///
/// The lock lives as long as the returned descriptor: it is released by the
/// kernel when the judger dies (including SIGKILL), which is exactly the
/// liveness signal the sweep consumes.
fn lock_owner(path: &Path) -> io::Result<fs::File> {
    let dir = fs::File::open(path)?;
    let rc = unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(dir)
}

/// Try to take an exclusive, non-blocking flock on a directory fd.
/// `Some(true)` = acquired (owner is gone; caller may reclaim),
/// `Some(false)` = held by a live owner, `None` = flock unsupported.
fn lock_dir(path: &Path) -> Option<bool> {
    use std::os::fd::AsRawFd;
    let dir = fs::File::open(path).ok()?;
    let rc = unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        return Some(true);
    }
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    if errno == libc::EWOULDBLOCK {
        return Some(false);
    }
    None
}
