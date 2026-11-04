//! Per-run AppContainer profiles from a fixed, session-local slot pool.
//!
//! A fixed profile name was one identity shared by every run of every judger
//! process: files written under `%LOCALAPPDATA%\Packages\<profile>\AC` survived
//! between runs (verified: a file written by run 1 was readable by run 2 and
//! visible on the host forever), a cross-run channel and a disk-fill surface.
//!
//! Creating and deleting a profile *per run* would give the strongest SID
//! isolation, but measures at ~6.6 ms (create 4.7 + delete 1.9) per run and
//! serializes every run on one RPC lock — ~2-3x the total cost of a short run
//! and a hard throughput ceiling.
//!
//! Instead the machine-local pool has a small, fixed set of **slots**. A run
//! leases one slot exclusively (a named mutex, so the lease also excludes
//! other judger processes in the same session), wipes the slot's package
//! directory before the run, and wipes it again on release. Profiles are
//! created once per (session, slot) and reused forever, so:
//!
//! - no run can see anything a previous run wrote (the directory is emptied
//!   under the lease, and no other process can hold the slot at the same
//!   time);
//! - no profile/SID/registry churn and no unbounded ACL growth: there are at
//!   most `slots` package SIDs per session, and each gets its `runtimes`
//!   grants once;
//! - concurrent runs are capped at `slots` (default: CPU parallelism clamped
//!   to 4..=16), which matches what a judge actually needs.

use std::io;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use windows_sys::Win32::Foundation::{HANDLE, WAIT_ABANDONED_0, WAIT_FAILED, WAIT_OBJECT_0};
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::Threading::{
    CreateMutexW, GetCurrentProcessId, INFINITE, ReleaseMutex, WaitForMultipleObjects,
    WaitForSingleObject,
};

use super::token::{AppContainer, wide_of_text};
use super::workdir::wipe_dir_contents;

/// Upper bound on pool slots (also keeps `WaitForMultipleObjects` well below
/// its 64-handle limit).
const MAX_SLOTS: usize = 16;
const MIN_SLOTS: usize = 4;

struct Slot {
    name: String,
    /// Session-local named mutex; ownership of the handle is the lease.
    mutex: HANDLE,
    /// Created on first use of the slot, kept for the process lifetime.
    app: OnceLock<Arc<AppContainer>>,
    /// `%LOCALAPPDATA%\Packages\<name>\AC`, `None` when the variable is
    /// missing (the run then simply has no directory to wipe).
    package: Option<PathBuf>,
}

struct Pool {
    slots: Vec<Slot>,
    /// Serializes the *mutating* profile-creation RPC machine-wide:
    /// `CreateAppContainerProfile` corrupts the profile registry when
    /// concurrent callers race (observed historically within one process,
    /// and two judger processes can race on their first slot just the same).
    create_mutex: HANDLE,
}

// SAFETY: the pool only holds immutable strings/paths and Win32 handles
// (named mutexes and AppContainer SIDs). Windows handles and SIDs are valid
// across threads; every mutation of a slot is serialized by that slot's
// mutex / OnceLock.
unsafe impl Send for Pool {}
unsafe impl Sync for Pool {}

impl Slot {
    fn app(&self, create_mutex: HANDLE) -> io::Result<&Arc<AppContainer>> {
        if let Some(app) = self.app.get() {
            return Ok(app);
        }
        // SAFETY: the handle is a valid mutex created by `init_pool`; an
        // abandoned mutex (previous owner died mid-creation) is still ours.
        unsafe { WaitForSingleObject(create_mutex, INFINITE) };
        let result = (|| {
            let created = AppContainer::create_or_open_named(&self.name)?;
            // The slot mutex already serializes this slot; `set` can only
            // lose to an impossible race, so the error is ignored.
            let _ = self.app.set(Arc::new(created));
            self.app
                .get()
                .ok_or_else(|| io::Error::other("profile slot lost its AppContainer"))
        })();
        // SAFETY: this thread owns the mutex acquired above.
        unsafe { ReleaseMutex(create_mutex) };
        result
    }

    fn wipe(&self) {
        if let Some(dir) = &self.package {
            // Best effort outside of `acquire` (a stale file must not fail a
            // run that is otherwise healthy); `acquire` reports the error.
            let _ = wipe_dir_contents(dir);
        }
    }
}

fn session_id() -> u32 {
    let mut sid: u32 = 0;
    // SAFETY: out-pointer is valid; the call cannot fail for our own pid.
    unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut sid) };
    sid
}

fn slot_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(MIN_SLOTS)
        .clamp(MIN_SLOTS, MAX_SLOTS)
}

fn init_pool() -> Result<Pool, String> {
    let session = session_id();
    let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    let create_mutex = named_mutex(&format!("Local\\river.sandbox.profile.create.{session}"))?;
    let mut slots = Vec::with_capacity(slot_count());
    for index in 0..slot_count() {
        let name = format!("river.sandbox.{session}.{index}");
        let mutex = named_mutex(&format!("Local\\river.sandbox.profile.{session}.{index}"))?;
        let package = base
            .as_ref()
            .map(|root| root.join("Packages").join(&name).join("AC"));
        slots.push(Slot {
            name,
            mutex,
            app: OnceLock::new(),
            package,
        });
    }
    Ok(Pool {
        slots,
        create_mutex,
    })
}

fn named_mutex(name: &str) -> Result<HANDLE, String> {
    let wide = wide_of_text(name);
    // SAFETY: name is NUL-terminated; no ACL (default), not initially owned.
    let mutex = unsafe { CreateMutexW(std::ptr::null(), 0, wide.as_ptr()) };
    if mutex.is_null() {
        Err(format!(
            "CreateMutexW({name}): {}",
            io::Error::last_os_error()
        ))
    } else {
        Ok(mutex)
    }
}

fn pool() -> io::Result<&'static Pool> {
    static POOL: OnceLock<Result<Pool, String>> = OnceLock::new();
    match POOL.get_or_init(init_pool) {
        Ok(pool) => Ok(pool),
        Err(message) => Err(io::Error::other(message.clone())),
    }
}

/// A leased profile slot. Dropping it wipes the package directory and
/// releases the lease (also on error paths inside `run`).
pub(crate) struct SlotGuard {
    pool: &'static Pool,
    index: usize,
}

impl SlotGuard {
    pub(crate) fn app(&self) -> io::Result<&AppContainer> {
        Ok(self.pool.slots[self.index].app(self.pool.create_mutex)?)
    }
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        let slot = &self.pool.slots[self.index];
        slot.wipe();
        // SAFETY: the mutex handle is valid and owned by this guard (it was
        // acquired by `acquire`), and every guard releases it exactly once.
        unsafe { ReleaseMutex(slot.mutex) };
    }
}

/// Lease a slot for one run, creating its profile and wiping its package
/// directory first. Blocks while all slots are busy.
pub(crate) fn acquire() -> io::Result<SlotGuard> {
    let pool = pool()?;
    let handles: Vec<HANDLE> = pool.slots.iter().map(|slot| slot.mutex).collect();
    // SAFETY: handles are valid; wait for any one of them to be signaled.
    let rc = unsafe {
        WaitForMultipleObjects(
            handles.len() as u32,
            handles.as_ptr(),
            0, // bWaitAll = FALSE
            INFINITE,
        )
    };
    if rc == WAIT_FAILED {
        return Err(io::Error::last_os_error());
    }
    // A slot whose previous owner was killed comes back as WAIT_ABANDONED_0+i:
    // the mutex is ours now (its state may be inconsistent, but the only
    // state is the package folder, which is wiped below).
    let count = pool.slots.len() as u32;
    let index = if (WAIT_OBJECT_0..WAIT_OBJECT_0 + count).contains(&rc) {
        (rc - WAIT_OBJECT_0) as usize
    } else if (WAIT_ABANDONED_0..WAIT_ABANDONED_0 + count).contains(&rc) {
        (rc - WAIT_ABANDONED_0) as usize
    } else {
        return Err(io::Error::other(
            "WaitForMultipleObjects: unexpected result",
        ));
    };

    let slot = &pool.slots[index];
    let lease = (|| -> io::Result<()> {
        let _ = slot.app(pool.create_mutex)?; // create the profile before wiping
        if let Some(dir) = &slot.package
            && dir.exists()
        {
            wipe_dir_contents(dir)?;
        }
        Ok(())
    })();
    if let Err(error) = lease {
        // SAFETY: this thread owns the mutex acquired above.
        unsafe { ReleaseMutex(slot.mutex) };
        return Err(error);
    }
    Ok(SlotGuard { pool, index })
}
