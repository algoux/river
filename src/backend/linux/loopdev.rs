//! Loop-device plumbing for squashfs rootfs images. The parent binds the
//! image to a loop device (a global host resource), the child mounts that
//! device read-only inside its own mount namespace, and [`LoopGuard`]
//! detaches the binding after the run — including copy_out — is over.

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::path::Path;

// libc does not bind the loop ioctls; values from linux/loop.h.
const LOOP_SET_FD: libc::c_ulong = 0x4C00;
const LOOP_CLR_FD: libc::c_ulong = 0x4C01;
const LOOP_CTL_GET_FREE: libc::c_ulong = 0x4C82;

/// How many times to ask for a free device before giving up: GET_FREE
/// nominally returns an unbound loop device, but a concurrent binder can
/// still win the race and make LOOP_SET_FD fail with EBUSY.
const ATTACH_ATTEMPTS: usize = 8;

/// Detaches the loop binding when dropped. Best effort: EINVAL means
/// already detached, EBUSY means a mount outlived this process — neither
/// is recoverable here.
pub(crate) struct LoopGuard {
    device: OwnedFd,
}

/// Binds `image` to a free loop device and returns the device path plus a
/// guard that detaches it. Fails loudly when the host has no loop support:
/// a squashfs rootfs never silently falls back to another mode.
pub(crate) fn attach(image: &Path) -> io::Result<(CString, LoopGuard)> {
    let image = File::open(image)?;
    let control = File::options()
        .read(true)
        .write(true)
        .open("/dev/loop-control")
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("no /dev/loop-control: a squashfs rootfs needs a loop device ({error})"),
            )
        })?;
    for _ in 0..ATTACH_ATTEMPTS {
        let number = unsafe { libc::ioctl(control.as_raw_fd(), LOOP_CTL_GET_FREE) };
        if number < 0 {
            return Err(io::Error::last_os_error());
        }
        let path = format!("/dev/loop{number}");
        let device = match File::options().read(true).write(true).open(&path) {
            Ok(device) => device,
            Err(error) if error.raw_os_error() == Some(libc::EBUSY) => continue,
            Err(error) => return Err(error),
        };
        let bound =
            unsafe { libc::ioctl(device.as_raw_fd(), LOOP_SET_FD, image.as_fd().as_raw_fd()) };
        if bound == 0 {
            let path = CString::new(path)
                .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
            return Ok((path, LoopGuard { device: device.into() }));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EBUSY) {
            return Err(error);
        }
    }
    Err(io::Error::other("no free loop device for the squashfs image"))
}

impl Drop for LoopGuard {
    fn drop(&mut self) {
        unsafe { libc::ioctl(self.device.as_raw_fd(), LOOP_CLR_FD, 0) };
    }
}
