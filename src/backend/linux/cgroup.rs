use std::fs;
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const RIVER_DIR: &str = "river";

const CGROUP_ROOT_ENV: &str = "RIVER_CGROUP_ROOT";
const DEFAULT_CGROUP_ROOT: &str = "/sys/fs/cgroup";

static RUN_COUNTER: AtomicU64 = AtomicU64::new(0);

pub(crate) fn cgroup_root() -> PathBuf {
    PathBuf::from(std::env::var_os(CGROUP_ROOT_ENV).unwrap_or_else(|| DEFAULT_CGROUP_ROOT.into()))
}

pub(crate) struct Cgroup {
    path: PathBuf,
    _owner: Option<fs::File>,
    cpu_stat: Option<fs::File>,
}

impl Cgroup {
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
        write_file(&river.join("cgroup.subtree_control"), "+memory +pids\n")?;

        let n = RUN_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = river.join(format!("run-{}-{n}", std::process::id()));
        if path.exists() {
            let _ = fs::remove_dir(&path);
        }
        fs::create_dir(&path)?;

        let owner = lock_owner(&path).ok();
        let cpu_stat = fs::File::open(path.join("cpu.stat")).ok();
        let cg = Cgroup {
            path,
            _owner: owner,
            cpu_stat,
        };
        write_file(&cg.file("memory.max"), &format!("{memory_limit_bytes}\n"))?;
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

    pub(crate) fn procs_path_c(&self) -> io::Result<std::ffi::CString> {
        std::ffi::CString::new(
            self.file("cgroup.procs")
                .to_str()
                .ok_or_else(|| io::Error::other("non-UTF8 cgroup path"))?,
        )
        .map_err(|_| io::Error::other("NUL in cgroup path"))
    }

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

    pub(crate) fn usage_usec(&self) -> io::Result<u64> {
        let text = match &self.cpu_stat {
            Some(f) => {
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

    pub(crate) fn peak_bytes(&self) -> io::Result<u64> {
        fs::read_to_string(self.file("memory.peak"))?
            .trim()
            .parse()
            .map_err(|_| io::Error::other("bad memory.peak"))
    }

    pub(crate) fn live_pids(&self) -> io::Result<Vec<libc::pid_t>> {
        let text = fs::read_to_string(self.file("cgroup.procs"))?;
        Ok(text
            .lines()
            .filter_map(|l| l.trim().parse::<libc::pid_t>().ok())
            .collect())
    }

    pub(crate) fn kill_all(&self) -> io::Result<()> {
        if write_file(&self.file("cgroup.kill"), "1\n").is_ok() {
            return Ok(());
        }
        for pid in self.live_pids()? {
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
        Ok(())
    }

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
        self._owner.take();
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
            cpu_stat: None,
        };
        let free = lock_dir(&stale.path);
        match free {
            Some(true) => {}
            Some(false) => continue,
            None => {
                if Path::new(&format!("/proc/{pid}")).exists() {
                    continue;
                }
            }
        }
        let _ = stale.kill_all();
        let _ = stale.wait_until_empty(std::time::Duration::from_millis(50));
        drop(stale);
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

fn lock_owner(path: &Path) -> io::Result<fs::File> {
    let dir = fs::File::open(path)?;
    let rc = unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(dir)
}

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
