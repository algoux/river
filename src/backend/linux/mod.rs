//! Linux backend: mount/pid/net/ipc/uts/cgroup namespaces (identity &
//! filesystem, unconditional network denial) + cgroups v2 (resources &
//! process tree) + seccomp allowlist + a judger-death watchdog. See
//! docs/linux-backend.md for the mechanism details and decision log.

pub mod cgroup;
pub mod monitor;
pub mod mount;
pub mod ns;
pub mod sandbox;
pub mod seccomp;
pub mod stdio;
pub mod uidpool;
pub mod workdir;

pub use sandbox::Sandbox;
