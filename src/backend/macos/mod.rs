//! macOS backend.
//!
//! Not implemented yet; until it is this backend runs entirely on the
//! shared `Backend` defaults.

use crate::backend::common::Backend;

/// Placeholder macOS backend; the sandboxing mechanics land here when
/// implemented.
pub(crate) struct Macos;

impl Backend for Macos {}
