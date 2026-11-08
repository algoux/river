//! Windows backend: AppContainer (identity & filesystem) + Job Object
//! (resources & process tree) + mitigation policies (kernel attack surface).
//! See docs/windows-backend.md for the decision log and measured pitfalls.

pub mod acl;
pub mod job;
pub mod monitor;
pub mod profile;
pub mod sandbox;
pub mod spawn;
pub mod stdio;
pub mod token;
pub mod workdir;

pub use sandbox::Sandbox;
