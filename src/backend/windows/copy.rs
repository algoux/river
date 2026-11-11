//! Windows `copy_in`/`copy_out`: the platform-neutral copying lives in
//! `backend::common::copy`; this wrapper adds the AppContainer DACL step.
//!
//! The copies are created below the workdir and would inherit its read/write
//! grant for the AppContainer identity, so [`acl::protect_read_only`] replaces
//! their DACLs when an AppContainer session is active.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use windows_sys::Win32::Security::PSID;

use super::acl;
use crate::backend::common::copy;

/// Copies every `host source -> workdir-relative destination` entry into
/// `workdir`, then protects each top-level entry when `appcontainer_sid` is
/// present.
pub(crate) fn provision(
    workdir: &Path,
    entries: &HashMap<PathBuf, PathBuf>,
    appcontainer_sid: Option<PSID>,
) -> io::Result<()> {
    let tops = copy::provision(workdir, entries)?;
    if let Some(sid) = appcontainer_sid {
        for top in &tops {
            let is_dir = fs::metadata(top)?.is_dir();
            acl::protect_read_only(top, sid, is_dir)?;
        }
    }
    Ok(())
}

/// Collects every `workdir-relative source -> host destination` entry.
pub(crate) fn collect(
    workdir: &Path,
    entries: &HashMap<PathBuf, PathBuf>,
    limit: Option<u64>,
) -> io::Result<bool> {
    copy::collect(workdir, entries, limit)
}
