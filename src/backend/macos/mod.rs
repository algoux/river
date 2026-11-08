//! macOS backend — **not implemented yet**.
//!
//! The module keeps the platform split: `Sandbox` exists on macOS so the
//! class and its constructor are available, but `run()` raises
//! `NotImplementedError` rather than pretending to sandbox anything.

pub mod sandbox;

pub use sandbox::Sandbox;
