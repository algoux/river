//! Per-run uid/gid leases (the Linux analogue of the Windows profile slot
//! pool).
//!
//! Every run used to drop to the fixed `nobody` (65534) identity. That left
//! a documented confidentiality hole: the per-run workdir is 0700 and owned
//! by the sandbox uid, so *any other process running as that same uid* —
//! a concurrent run on the same judger, or an unrelated host service —
//! could read **and overwrite** a live run's inputs and products (verified
//! live: `setpriv --reuid=65534 cat <workdir>/secret.txt` succeeded).
//!
//! Each run now leases an exclusive uid (and matching gid) from a fixed
//! high range. The lease is an `flock` on a per-uid lock file under
//! `<tmp>/river-uidpool/`: the kernel releases it when the leasing process
//! dies, so a hard-killed judger leaks nothing (the next acquirer gets the
//! flock immediately — no sweep needed, unlike workdirs/cgroups).
//!
//! - Default range: `[100000, 100064)` — 64 concurrent runs, overridable
//!   with `RIVER_UID_BASE` / `RIVER_UID_COUNT` (deployment knob for hosts
//!   that already use the default range).
//! - `doctor()` (and the first lease) verify the range does not intersect
//!   `/etc/passwd` — a collision would silently give the program an
//!   existing host identity, so it is a construction-blocking error.
//! - Exhaustion blocks (20 ms poll), mirroring the Windows slot pool: a
//!   judge prefers waiting over sharing an identity.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::time::Duration;

/// Default first uid of the lease range (well above system accounts).
const DEFAULT_BASE: u32 = 100_000;
/// Default pool size (concurrent Linux runs before acquire blocks).
const DEFAULT_COUNT: u32 = 64;
/// Poll interval while every uid in the pool is leased.
const ACQUIRE_POLL: Duration = Duration::from_millis(20);

struct Range {
    base: u32,
    count: u32,
}

fn range() -> Result<&'static Range, String> {
    static RANGE: std::sync::OnceLock<Result<Range, String>> = std::sync::OnceLock::new();
    RANGE
        .get_or_init(|| {
            let base = match std::env::var("RIVER_UID_BASE") {
                Ok(v) => v
                    .parse::<u32>()
                    .map_err(|_| "RIVER_UID_BASE must be an integer")?,
                Err(_) => DEFAULT_BASE,
            };
            let count = match std::env::var("RIVER_UID_COUNT") {
                Ok(v) => {
                    let n = v
                        .parse::<u32>()
                        .map_err(|_| "RIVER_UID_COUNT must be an integer")?;
                    if n == 0 {
                        return Err("RIVER_UID_COUNT must be >= 1".to_string());
                    }
                    n
                }
                Err(_) => DEFAULT_COUNT,
            };
            // uid_t is i32 on Linux; keep the whole range representable.
            if u64::from(base) + u64::from(count) > libc::uid_t::MAX as u64 {
                return Err("RIVER_UID_BASE + RIVER_UID_COUNT overflows uid_t".to_string());
            }
            Ok(Range { base, count })
        })
        .as_ref()
        .map_err(|e| e.clone())
}

/// The per-uid lock directory (`<tmp>/river-uidpool`), created on demand.
fn pool_dir() -> io::Result<PathBuf> {
    let dir = std::env::temp_dir().join("river-uidpool");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Fail-closed check: no account in `/etc/passwd` may use a uid from the
/// lease range (a collision would hand the program an existing host
/// identity — file ownership, cron deliveries, `nobody`-style shared
/// access). Returns the offending uid on collision.
fn colliding_system_uid(range: &Range) -> Option<u32> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in passwd.lines() {
        let Some(uid) = line.split(':').nth(2).and_then(|f| f.parse::<u32>().ok()) else {
            continue;
        };
        if (range.base..range.base + range.count).contains(&uid) {
            return Some(uid);
        }
    }
    None
}

/// Doctor facts for the uid pool: whether it is configured and collision-free.
pub(crate) fn facts() -> Vec<(&'static str, crate::backend::DoctorValue)> {
    use crate::backend::DoctorValue;
    let mut out = Vec::new();
    match range() {
        Ok(r) => {
            out.push(("per_run_uid_base", DoctorValue::Str(r.base.to_string())));
            out.push(("per_run_uid_count", DoctorValue::Str(r.count.to_string())));
            if let Some(uid) = colliding_system_uid(&r) {
                out.push(("per_run_uid_collision", DoctorValue::Str(uid.to_string())));
            }
        }
        Err(e) => out.push(("per_run_uid_error", DoctorValue::Str(e))),
    }
    out
}

/// Errors that must block `Sandbox` construction (fail closed).
pub(crate) fn blocking_errors() -> Vec<String> {
    let mut errors = Vec::new();
    match range() {
        Ok(r) => {
            if let Some(uid) = colliding_system_uid(&r) {
                errors.push(format!(
                    "per-run uid range [{}, {}) collides with /etc/passwd uid {uid} \
                     (set RIVER_UID_BASE/RIVER_UID_COUNT to a free range)",
                    r.base,
                    r.base + r.count
                ));
            }
        }
        Err(e) => errors.push(format!("per-run uid pool misconfigured: {e}")),
    }
    errors
}

/// An exclusive uid/gid lease. Released when dropped (the `flock` dies with
/// the file descriptor; a hard-killed judger releases it kernel-side).
pub(crate) struct UidGuard {
    pub(crate) uid: libc::uid_t,
    pub(crate) gid: libc::gid_t,
    _lock: File,
}

/// Lease a free uid from the pool, blocking while all are taken.
pub(crate) fn acquire() -> io::Result<UidGuard> {
    let range = range().map_err(io::Error::other)?;
    // First use double-checks the /etc/passwd collision (cheap: one read).
    if let Some(uid) = colliding_system_uid(&range) {
        return Err(io::Error::other(format!(
            "per-run uid range [{}, {}) collides with /etc/passwd uid {uid}",
            range.base,
            range.base + range.count
        )));
    }
    let dir = pool_dir()?;
    loop {
        for offset in 0..range.count {
            let uid = range.base + offset;
            let path = dir.join(uid.to_string());
            let mut options = OpenOptions::new();
            options.create(true).read(true).write(true);
            let file = options.open(&path)?;
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if rc == 0 {
                return Ok(UidGuard {
                    uid: uid as libc::uid_t,
                    gid: uid as libc::gid_t,
                    _lock: file,
                });
            }
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EWOULDBLOCK) {
                return Err(err);
            }
            // leased by another run: try the next uid
        }
        std::thread::sleep(ACQUIRE_POLL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two live leases must yield distinct uids, and a dropped lease is
    /// reusable (kernel-side `flock` release).
    #[test]
    fn leases_are_exclusive_and_reusable() {
        let a = acquire().expect("uid lease");
        let b = acquire().expect("second uid lease");
        assert_ne!(a.uid, b.uid, "two live leases share a uid");
        let uid_b = b.uid;
        drop(a);
        // The freed uid becomes available again; a concurrent judger may
        // race us for it, so only the invariant "never the still-leased
        // uid" is asserted here.
        let c = acquire().expect("re-lease after drop");
        assert_ne!(c.uid, uid_b, "re-lease handed out the still-leased uid");
        drop(c);
        drop(b);
    }
}
