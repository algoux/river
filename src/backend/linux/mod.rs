//! Linux backend: mount/pid namespaces + seccomp + cgroups v2.
//!
//! The real mechanics have not landed yet; until they do this backend runs
//! entirely on the shared `Backend` defaults. The building blocks are
//! demonstrated in `examples/linux_*`.

use crate::backend::common::Backend;

/// Placeholder Linux backend; the namespace/seccomp/cgroups mechanics land
/// here when implemented.
pub(crate) struct Linux;

impl Backend for Linux {}
