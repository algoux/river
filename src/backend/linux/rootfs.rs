//! Child-side root filesystem: builds the sandbox mount tree and pivots into
//! it. Runs between `clone3` and `execve`, so it must only use raw syscalls
//! (no allocation beyond the `CString`s the caller pre-built) and reports
//! failures as errno over the status pipe.
//!
//! Layout after `pivot_root`:
//!
//! ```text
//! /                       tmpfs (per-run)
//! ├── workspace/          bind <- host session workdir (rw)
//! │   └── tmp/            TMPDIR of the child
//! ├── proc/               new procfs for the private PID namespace
//! ├── dev/                tmpfs with null/zero/random/urandom bind-mounted in
//! ├── runtime/<name>/     bind <- each caller runtime dir (ro)
//! └── usr bin sbin lib lib64 etc   bind <- host system dirs (ro)
//! ```
//!
//! The read-only system dirs are what makes a host dynamic linker, libc and
//! shell runnable inside the sandbox; they exist on every mainstream distro
//! layout and are simply skipped when absent.
//!
//! With a caller-supplied `rootfs` the root is an overlayfs instead
//! (lowerdir = the caller tree, upperdir/workdir on a private tmpfs under
//! the workdir) and no host system dir is merged: the rootfs must be
//! self-contained.

use super::spawn::RootFs;

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_ulong, c_void};

use libc::{
    MNT_DETACH as MS_DETACH, MS_BIND, MS_NODEV, MS_NOSUID, MS_PRIVATE, MS_RDONLY, MS_REC,
    MS_REMOUNT,
};

/// Host directories merged read-only into the new root, in mount order.
const SYSTEM_DIRS: &[&str] = &["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"];

/// Device files bind-mounted into the per-run tmpfs `/dev`.
const DEVICES: &[&str] = &["null", "zero", "random", "urandom"];

fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

fn mkdir(path: &CStr) -> c_int {
    unsafe { libc::mkdir(path.as_ptr(), 0o755) }
}

fn mkdir_ok(path: &CStr) -> Result<(), i32> {
    if mkdir(path) != 0 && last_errno() != libc::EEXIST {
        return Err(last_errno());
    }
    Ok(())
}

fn mount(
    source: Option<&CStr>,
    target: &CStr,
    fstype: Option<&CStr>,
    flags: c_ulong,
    data: Option<&CStr>,
) -> Result<(), i32> {
    let ret = unsafe {
        libc::mount(
            source.map_or(std::ptr::null(), |s| s.as_ptr()),
            target.as_ptr(),
            fstype.map_or(std::ptr::null(), |s| s.as_ptr()),
            flags,
            data.map_or(std::ptr::null(), |s| s.as_ptr()) as *const c_void,
        )
    };
    if ret != 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// Builds the sandbox root under `<workdir>/root` and pivots into it.
/// On return the process is chdir'd to `/` inside the new root and the host
/// filesystem is unmounted. `stage` receives a code naming the phase that
/// failed (see `stage_name`), so the caller can report it.
///
/// Without `rootfs` the new root is a tmpfs with the host system dirs
/// merged in read-only. With `rootfs` it is an overlayfs whose lower layer
/// is either the caller directory directly or a squashfs image the parent
/// bound to a loop device; the per-run `upperdir`/`workdir` live on a
/// private tmpfs under the session workdir, so the caller tree is never
/// written — the mount-point directories land in the upper layer — and
/// nothing from the host is merged: the rootfs must be self-contained.
pub(super) fn setup_and_pivot(
    workdir: &CStr,
    runtimes: &[CString],
    rootfs: Option<&RootFs>,
    stage: &mut u32,
) -> Result<(), i32> {
    macro_rules! phased {
        ($code:expr, $body:expr) => {{
            *stage = $code;
            $body?;
        }};
    }

    // Stop mount events propagating to the host namespace before any mount.
    phased!(
        10,
        mount(Some(c"none"), c"/", None, MS_REC | MS_PRIVATE, None)
    );

    let root = join_bytes(workdir.to_bytes(), b"/root")?;
    phased!(11, mkdir_ok(&root));
    match rootfs {
        None => {
            // The per-run root: a fresh tmpfs, so nothing of the host tree
            // leaks in except what is explicitly bound below.
            phased!(
                12,
                mount(
                    Some(c"tmpfs"),
                    &root,
                    Some(c"tmpfs"),
                    MS_NOSUID | MS_NODEV,
                    None,
                )
            );
        }
        Some(rootfs) => {
            // The overlay's writable internals live on a private tmpfs under
            // the session workdir — the only host tree river may write. The
            // /workspace bind is non-recursive, so this mount never shows up
            // inside the sandbox; after the pivot the overlay is the only
            // thing keeping it alive.
            let ovl = join_bytes(workdir.to_bytes(), b"/ovl")?;
            phased!(29, mkdir_ok(&ovl));
            phased!(
                30,
                mount(
                    Some(c"tmpfs"),
                    &ovl,
                    Some(c"tmpfs"),
                    MS_NOSUID | MS_NODEV,
                    Some(c"mode=700"),
                )
            );
            let upper = join_bytes(ovl.to_bytes(), b"/upper")?;
            let overlay_work = join_bytes(ovl.to_bytes(), b"/work")?;
            phased!(31, mkdir_ok(&upper));
            phased!(31, mkdir_ok(&overlay_work));
            let lowerdir = match rootfs {
                RootFs::Dir(path) => path.to_owned(),
                // The parent bound the image to this loop device; mount it
                // read-only here and use that mount as the lower layer. The
                // mount dies with this namespace, the binding with the
                // parent's LoopGuard.
                RootFs::Squashfs(device) => {
                    let sqfs = join_bytes(ovl.to_bytes(), b"/sqfs")?;
                    phased!(31, mkdir_ok(&sqfs));
                    phased!(
                        34,
                        mount(
                            Some(device),
                            &sqfs,
                            Some(c"squashfs"),
                            MS_RDONLY | MS_NOSUID | MS_NODEV,
                            None,
                        )
                    );
                    sqfs
                }
            };
            // shortcut: a directory path rejects ',' and ':' at construction
            // (overlay option separators); anything else the kernel dislikes
            // surfaces as the mount's own errno
            let options = format!(
                "lowerdir={},upperdir={},workdir={}",
                lowerdir.to_string_lossy(),
                upper.to_string_lossy(),
                overlay_work.to_string_lossy(),
            );
            let options = CString::new(options).map_err(|_| libc::EINVAL)?;
            phased!(
                32,
                mount(Some(c"none"), &root, Some(c"overlay"), 0, Some(&options))
            );
        }
    }

    *stage = 13;
    for name in ["proc", "dev", "runtime", "workspace", ".oldroot"] {
        mkdir_ok(&join(&root, name))?;
    }
    // The runtime mount points must exist before the overlay is frozen
    // read-only below; the default-mode root tmpfs is writable either way.
    for runtime in runtimes {
        if let Some(name) = runtime_name(runtime) {
            let mut target = join_bytes(root.to_bytes(), b"/runtime/")?;
            target = join_bytes(target.to_bytes(), name)?;
            mkdir_ok(&target)?;
        }
    }

    // Rootfs mode: the merged view is frozen read-only before anything is
    // mounted on top of it. (The mount-point dirs above landed in the
    // writable upper layer.)
    if rootfs.is_some() {
        phased!(
            33,
            mount(
                None,
                &root,
                None,
                MS_REC | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV,
                None,
            )
        );
    }

    // The writable scratch: the session workdir bind-mounted at /workspace.
    // Non-recursive on purpose: a recursive bind would copy the overlay
    // backing tmpfs (workdir/ovl) into /workspace and hand the child the
    // writable upper layer. The workdir is river's own scratch directory
    // and holds no mounts the sandbox needs.
    // nodev/nosuid need the second remount step (a bind alone cannot apply
    // them): without nodev the payload, running as root, could mknod a disk
    // device node here and open the host's raw disk.
    let workspace = join(&root, "workspace");
    phased!(14, mount(Some(workdir), &workspace, None, MS_BIND, None));
    phased!(
        14,
        mount(
            None,
            &workspace,
            None,
            MS_BIND | MS_REMOUNT | MS_NODEV | MS_NOSUID,
            None,
        )
    );

    // A minimal /dev: tmpfs plus the char devices almost every program needs.
    phased!(
        15,
        mount(
            Some(c"tmpfs"),
            &join(&root, "dev"),
            Some(c"tmpfs"),
            MS_NOSUID | MS_NODEV,
            Some(c"mode=755"),
        )
    );
    for device in DEVICES {
        *stage = 16;
        let target = join(&join(&root, "dev"), device);
        // Bind requires the target to exist; an empty file is fine.
        let ret = unsafe { libc::open(target.as_ptr(), libc::O_CREAT | libc::O_WRONLY, 0o666) };
        if ret < 0 {
            return Err(last_errno());
        }
        unsafe { libc::close(ret) };
        let source = join_bytes(b"/dev/", device.as_bytes())?;
        mount(Some(&source), &target, None, MS_BIND, None)?;
    }

    // Shared memory (python multiprocessing, numpy). mode=1777 like the
    // host; no size cap on purpose — tmpfs pages land in the cgroup memory
    // counter, so memory.max stays the single limit and an overshoot keeps
    // the MLE verdict instead of turning into an ENOSPC runtime error.
    let shm = join(&root, "dev/shm");
    phased!(35, mkdir_ok(&shm));
    phased!(
        35,
        mount(
            Some(c"tmpfs"),
            &shm,
            Some(c"tmpfs"),
            MS_NOSUID | MS_NODEV,
            Some(c"mode=1777"),
        )
    );

    // Read-only host system dirs, default mode only. `/bin`, `/sbin`,
    // `/lib` and `/lib64` are often symlinks into `/usr` on modern distros;
    // mounting through a symlink resolves to the same tree, so no special
    // casing is needed. A caller rootfs is self-contained instead.
    if rootfs.is_none() {
        for dir in SYSTEM_DIRS {
            *stage = 17;
            let source = CString::new(*dir).map_err(|_| libc::EINVAL)?;
            if !path_exists(&source) {
                continue;
            }
            let target = join(&root, dir.trim_start_matches('/'));
            mkdir_ok(&target)?;
            bind_read_only(&source, &target)?;
        }
    }

    // Caller runtimes, read-only at /runtime/<name> (mount points created
    // at stage 13, before the read-only freeze).
    for runtime in runtimes {
        *stage = 18;
        let name = runtime_name(runtime).unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        let mut target = join_bytes(root.to_bytes(), b"/runtime/")?;
        target = join_bytes(target.to_bytes(), name)?;
        bind_read_only(runtime, &target)?;
    }

    // New procfs, scoped to this PID namespace (the child is `clone3`-born
    // inside it already).
    phased!(
        19,
        mount(
            Some(c"proc"),
            &join(&root, "proc"),
            Some(c"proc"),
            MS_NOSUID | MS_NODEV,
            None,
        )
    );

    // Pivot: / becomes the per-run root, the host root lands under
    // /.oldroot and is detached immediately after.
    let old_root = join(&root, ".oldroot");
    *stage = 20;
    if unsafe { libc::chdir(root.as_ptr()) } != 0 {
        return Err(last_errno());
    }
    *stage = 21;
    if unsafe { libc::syscall(libc::SYS_pivot_root, root.as_ptr(), old_root.as_ptr()) } != 0 {
        return Err(last_errno());
    }
    *stage = 22;
    if unsafe { libc::chdir(c"/".as_ptr()) } != 0 {
        return Err(last_errno());
    }
    *stage = 23;
    if unsafe { libc::umount2(c"/.oldroot".as_ptr() as *const c_char, MS_DETACH) } != 0 {
        return Err(last_errno());
    }
    unsafe { libc::rmdir(c"/.oldroot".as_ptr()) };
    Ok(())
}

/// Human-readable name of a failed setup phase (10-based codes above).
pub(super) fn stage_name(stage: u32) -> &'static str {
    match stage {
        10 => "mount --make-rprivate /",
        11 => "mkdir sandbox root",
        12 => "mount sandbox root tmpfs",
        13 => "mkdir sandbox root entries",
        14 => "bind-mount workspace",
        15 => "mount /dev tmpfs",
        16 => "bind-mount /dev node",
        17 => "bind-mount system dir",
        18 => "bind-mount runtime",
        19 => "mount /proc",
        20 | 21 => "pivot_root",
        22 => "chdir /",
        23 => "detach old root",
        29 => "mkdir overlay scratch",
        30 => "mount overlay scratch tmpfs",
        31 => "mkdir overlay upper/work",
        32 => "mount rootfs overlay",
        33 => "freeze rootfs read-only",
        34 => "mount squashfs image",
        35 => "mount /dev/shm",
        _ => "sandbox setup",
    }
}

/// The basename of a runtime path (its mount name at `/runtime/<name>`).
fn runtime_name(runtime: &CStr) -> Option<&[u8]> {
    runtime
        .to_bytes()
        .rsplit(|&b| b == b'/')
        .next()
        .filter(|name| !name.is_empty())
}

/// A read-only bind: two mounts, because a bind cannot be created and
/// restricted in one step.
fn bind_read_only(source: &CStr, target: &CStr) -> Result<(), i32> {
    mount(Some(source), target, None, MS_BIND | MS_REC, None)?;
    mount(
        None,
        target,
        None,
        MS_BIND | MS_REC | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV,
        None,
    )
}

fn path_exists(path: &CStr) -> bool {
    unsafe { libc::access(path.as_ptr(), libc::F_OK) == 0 }
}

fn join(base: &CStr, name: &str) -> CString {
    join_bytes(base.to_bytes(), name.as_bytes()).expect("no NUL in names")
}

fn join_bytes(base: &[u8], suffix: &[u8]) -> Result<CString, i32> {
    let mut bytes = base.to_vec();
    if !bytes.ends_with(b"/") && !suffix.starts_with(b"/") {
        bytes.push(b'/');
    }
    bytes.extend_from_slice(suffix);
    CString::new(bytes).map_err(|_| libc::EINVAL)
}
