//! `copy_in` provisioning and `copy_out` recovery for the session workdir.
//!
//! `copy_in` maps `host source -> workdir-relative destination`. A host
//! directory is copied recursively; symlinks and junctions found below it are
//! skipped (following a link farm is never worth it). The destination's
//! top-level entry is owned by `copy_in`: it is removed and recreated on
//! every run, which keeps repeated runs working even after the previous copy
//! was protected read-only.
//!
//! The copies are created below the workdir and would inherit its read/write
//! grant for the AppContainer identity, so [`acl::protect_read_only`] replaces
//! their DACLs when an AppContainer session is active. A plain run has no
//! separate identity to protect against and copies without the DACL step.
//!
//! `copy_out` maps `workdir-relative source -> host destination` and runs
//! only after a successful (`AC`) run. Directories are collected recursively;
//! symlinks and junctions are skipped at every depth, because the sandboxed
//! program writes the workdir and following a link it planted would read host
//! files through the judger. A missing source is skipped. A total-byte cap
//! stops the collection before the breaching file is written.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use windows_sys::Win32::Security::PSID;

use super::acl;

/// Copies every `host source -> workdir-relative destination` entry into
/// `workdir`, then protects each top-level entry when `appcontainer_sid` is
/// present.
pub(crate) fn provision(
    workdir: &Path,
    entries: &HashMap<PathBuf, PathBuf>,
    appcontainer_sid: Option<PSID>,
) -> io::Result<()> {
    let mut tops = HashSet::new();
    for destination in entries.values() {
        if let Some(Component::Normal(name)) = destination.components().next() {
            tops.insert(workdir.join(name));
        }
    }

    // The top-level entry is fully owned by `copy_in`; recreating it is also
    // what makes a repeated run able to overwrite a read-only copy.
    for top in &tops {
        remove_existing(top)?;
    }

    for (source, destination) in entries {
        let target = workdir.join(destination);
        copy_entry(source, &target).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("{} -> {}: {error}", source.display(), target.display()),
            )
        })?;
    }

    if let Some(sid) = appcontainer_sid {
        for top in &tops {
            let is_dir = fs::metadata(top)?.is_dir();
            acl::protect_read_only(top, sid, is_dir)?;
        }
    }
    Ok(())
}

/// Removes whatever currently occupies a top-level destination.
fn remove_existing(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() || metadata.file_type().is_symlink() => {
            fs::remove_dir_all(path)
        }
        Ok(_) => fs::remove_file(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn copy_entry(source: &Path, target: &Path) -> io::Result<()> {
    let metadata = fs::metadata(source)?;
    if metadata.is_dir() {
        copy_dir(source, target)
    } else {
        copy_file(source, target)
    }
}

fn copy_file(source: &Path, target: &Path) -> io::Result<()> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(source, target)?;
    Ok(())
}

fn copy_dir(source: &Path, target: &Path) -> io::Result<()> {
    fs::create_dir_all(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        // `DirEntry::metadata` does not traverse symlinks, so junctions and
        // symlinks are visible here and skipped as a whole.
        let metadata = entry.metadata()?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        let child = target.join(entry.file_name());
        if metadata.is_dir() {
            copy_dir(&entry.path(), &child)?;
        } else {
            fs::copy(entry.path(), &child)?;
        }
    }
    Ok(())
}

/// Collects every `workdir-relative source -> host destination` entry.
///
/// Missing sources are skipped (optional products). Returns `true` when the
/// total would pass `limit`; the breaching file is not written and collection
/// stops, so no partial file is left behind.
pub(crate) fn collect(
    workdir: &Path,
    entries: &HashMap<PathBuf, PathBuf>,
    limit: Option<u64>,
) -> io::Result<bool> {
    let mut total = 0u64;
    for (relative, destination) in entries {
        let source = workdir.join(relative);
        let metadata = match fs::symlink_metadata(&source) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if metadata.file_type().is_symlink() {
            continue;
        }
        let exceeded = if metadata.is_dir() {
            collect_dir(&source, destination, limit, &mut total)
        } else {
            collect_file(&source, &metadata, destination, limit, &mut total)
        }
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("{} -> {}: {error}", source.display(), destination.display()),
            )
        })?;
        if exceeded {
            return Ok(true);
        }
    }
    Ok(false)
}

fn collect_dir(
    source: &Path,
    destination: &Path,
    limit: Option<u64>,
    total: &mut u64,
) -> io::Result<bool> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        // `DirEntry::metadata` does not traverse symlinks, so junctions and
        // symlinks are visible here and skipped as a whole.
        let metadata = entry.metadata()?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        let child = destination.join(entry.file_name());
        let exceeded = if metadata.is_dir() {
            collect_dir(&entry.path(), &child, limit, total)?
        } else {
            collect_file(&entry.path(), &metadata, &child, limit, total)?
        };
        if exceeded {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Copies one regular file. The quota is checked before the destination is
/// touched, so a file that would breach it is not collected at all.
fn collect_file(
    source: &Path,
    metadata: &fs::Metadata,
    destination: &Path,
    limit: Option<u64>,
    total: &mut u64,
) -> io::Result<bool> {
    if let Some(limit) = limit
        && total.saturating_add(metadata.len()) > limit
    {
        return Ok(true);
    }
    if let Some(parent) = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    *total = total.saturating_add(fs::copy(source, destination)?);
    Ok(false)
}
