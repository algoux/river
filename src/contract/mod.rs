//! The frozen, platform-neutral API contract.
//!
//! Everything in this module is pure data + pure functions: argument
//! validation, evidence-driven verdict classification, and the `Status`
//! pyclass. Platform backends depend on this module; this module never
//! depends on a backend. That inversion is what keeps the semantics written
//! (and unit-tested) exactly once across platforms.

pub mod status;
pub mod verdict;

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

/// Source of a `copy_in` entry: inline bytes or a host-side file/directory
/// path (a directory is provisioned recursively).
#[derive(Clone)]
pub(crate) enum CopyInSource {
    Bytes(Vec<u8>),
    Path(PathBuf),
}

/// One `copy_out` request: a sandbox-relative source path (a file or a
/// directory — directories are collected recursively) and the host-side
/// destination path it must be written to.
#[derive(Clone)]
pub(crate) struct CopyOutEntry {
    /// Path inside the sandbox working directory (validated relative).
    pub src_rel: String,
    /// Absolute host path the collected content is written to (parents are
    /// created as needed).
    pub dst_host: PathBuf,
}

/// Frozen `run()` argument set shared by all platform backends.
///
/// Coordinate system contract:
/// - `executable`, `stdin_file`, `stdout_file`, `stderr_file`: host paths
/// - `cwd`: path relative to the sandbox private working directory
/// - `copy_in` keys: paths relative to the sandbox working directory
/// - `copy_out` keys: paths relative to the sandbox working directory
///   (values are host paths; collection never follows symlinks)
///
/// Limit semantics: `None` means *no caller-imposed limit*. Backends must
/// still enforce internal safety ceilings (see [`SafetyCeilings`]) so that
/// unlimited runs cannot take down the host.
pub(crate) struct RunSpec {
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub cwd: Option<String>,
    pub env: Option<HashMap<String, String>>,
    pub time_limit_ms: Option<u64>,
    pub wall_time_limit_ms: Option<u64>,
    pub memory_limit_kb: Option<u64>,
    pub stdin: Option<Vec<u8>>,
    pub stdin_file: Option<PathBuf>,
    pub copy_in: Option<HashMap<String, CopyInSource>>,
    /// Product-recovery requests (sandbox-relative source -> host path).
    pub copy_out: Option<Vec<CopyOutEntry>>,
    /// Kill threshold for the *total collected bytes*: exceeding it stops
    /// the collection and classifies the run as `OLE` (output quota).
    pub copy_out_limit_bytes: Option<u64>,
    pub stdout_limit_kb: Option<u64>,
    pub stderr_limit_kb: Option<u64>,
    pub stdout_file: Option<PathBuf>,
    pub stderr_file: Option<PathBuf>,
}

impl RunSpec {
    /// Effective wall clock limit: explicit value, else `2 * time_limit + 1000ms`
    /// when a CPU time limit is set, else `None` (unlimited).
    pub(crate) fn effective_wall_time_limit_ms(&self) -> Option<u64> {
        self.wall_time_limit_ms.or_else(|| {
            self.time_limit_ms
                .map(|t| t.saturating_mul(2).saturating_add(1000))
        })
    }
}

/// Internal safety ceilings: the *mechanism* guarantees that stay in place
/// even when the caller passes `None` (i.e. "no caller-imposed limit").
/// "Unlimited" is a caller-side semantic, never a missing mechanism
/// (DESIGN.md §2.2).
#[derive(Clone, Copy)]
pub(crate) struct SafetyCeilings {
    /// Wall-clock ceiling applied to a run whose effective wall limit is
    /// `None`. Default: 24 hours.
    pub wall_limit: Duration,
    /// Cap on simultaneously alive processes per run (main process
    /// included). Default: 64.
    pub max_processes: u32,
    /// Per-channel memory-capture ceiling applied when the caller passes no
    /// `stdout_limit_kb` / `stderr_limit_kb` (the sample is capped and marked
    /// truncated; no kill). Default: 64 MiB.
    pub capture_limit_bytes: u64,
    /// Per-channel file-sink ceiling (`stdout_file` / `stderr_file` archive)
    /// so an output fountain cannot fill the host disk before the run is
    /// reaped. Default: 1 GiB.
    pub file_sink_limit_bytes: u64,
}

impl Default for SafetyCeilings {
    fn default() -> Self {
        SafetyCeilings {
            wall_limit: Duration::from_secs(24 * 3600),
            max_processes: 64,
            capture_limit_bytes: 64 * 1024 * 1024,
            file_sink_limit_bytes: 1024 * 1024 * 1024,
        }
    }
}

/// Internal safety ceilings for stdio capture, derived from
/// [`SafetyCeilings`]. They apply when the caller passes no explicit
/// `stdout_limit_kb` / `stderr_limit_kb` ("unlimited" is a caller-side
/// semantic, never a missing mechanism).
#[derive(Clone, Copy)]
pub(crate) struct StdioCeilings {
    /// Memory-capture ceiling per channel when no user `*_limit_kb` is set
    /// (the sample is capped and marked truncated; no kill).
    pub capture_limit_bytes: u64,
    /// File-sink ceiling per channel (`stdout_file` / `stderr_file` archive).
    pub sink_limit_bytes: u64,
}

impl From<SafetyCeilings> for StdioCeilings {
    fn from(c: SafetyCeilings) -> Self {
        StdioCeilings {
            capture_limit_bytes: c.capture_limit_bytes,
            sink_limit_bytes: c.file_sink_limit_bytes,
        }
    }
}

/// Effective per-channel memory-capture cap: the caller's kill threshold,
/// but never above the internal ceiling. A caller that passes a 1 GiB
/// `stdout_limit_kb` still gets its output killed at 1 GiB, while the judger
/// only buffers `capture_ceiling_bytes` (the rest is counted, not kept).
pub(crate) fn capture_ceiling(user_limit: Option<u64>, capture_ceiling_bytes: u64) -> u64 {
    user_limit.map_or(capture_ceiling_bytes, |limit| {
        limit.min(capture_ceiling_bytes)
    })
}

/// Parse the raw `copy_in` mapping (`sandbox-relative path -> bytes | host
/// path`, the latter also accepting a host *directory*).
pub(crate) fn parse_copy_in(
    map: &HashMap<String, pyo3::Py<pyo3::PyAny>>,
    py: Python<'_>,
) -> PyResult<HashMap<String, CopyInSource>> {
    let mut out = HashMap::with_capacity(map.len());
    for (key, value) in map {
        let bound = value.bind(py);
        if let Ok(bytes) = bound.extract::<Vec<u8>>() {
            out.insert(key.clone(), CopyInSource::Bytes(bytes));
        } else if let Ok(path) = bound.extract::<PathBuf>() {
            out.insert(key.clone(), CopyInSource::Path(path));
        } else {
            return Err(PyValueError::new_err(format!(
                "copy_in[{key:?}]: value must be bytes, a host file path, or a host directory path"
            )));
        }
    }
    Ok(out)
}

/// Parse the raw `copy_out` mapping (`sandbox-relative path -> host path`).
/// The destination must be a host path (a file, or a directory when the
/// source is a directory). Accepts `str` and `os.PathLike`.
pub(crate) fn parse_copy_out(map: &HashMap<String, PathBuf>) -> PyResult<Vec<CopyOutEntry>> {
    Ok(map
        .iter()
        .map(|(src, dst)| CopyOutEntry {
            src_rel: src.clone(),
            dst_host: dst.clone(),
        })
        .collect())
}

/// Validate one sandbox-relative path key (shared by `copy_in`, `copy_out`
/// and `cwd`): only plain relative components are accepted. Anything else —
/// empty, absolute, rooted, prefix-bearing, `..`/`.` components, drive
/// colons — is rejected.
///
/// Why `has_root()` and not just `is_absolute()`: on Windows a path like
/// `"/foo"` or `"\foo"` is *rooted but not absolute* (`is_absolute() ==
/// false`, the drive prefix is missing), yet `Path::join("/foo")` **replaces
/// the base down to the drive root**, so `"C:\workdir".join("/Users/x")`
/// resolves to `C:\Users\x` — a host path far outside the sandbox working
/// directory (verified exploit: `copy_out` / `copy_in` keys and `cwd` all
/// escaped the workdir this way). Requiring every component to be
/// `Component::Normal(_)` closes the whole class: RootDir, Prefix, CurDir
/// and ParentDir are all rejected, on every platform.
fn validate_rel_key(kind: &str, key: &str) -> PyResult<()> {
    let path = Path::new(key);
    if key.is_empty()
        || path.has_root()
        || key.contains(':')
        || !path.components().all(|c| matches!(c, Component::Normal(_)))
    {
        return Err(PyValueError::new_err(format!(
            "invalid {kind} key {key:?}: must be a relative path inside the sandbox working directory"
        )));
    }
    Ok(())
}

/// Cross-platform argument validation, run before any backend work.
pub(crate) fn validate(spec: &RunSpec) -> PyResult<()> {
    if spec.stdin.is_some() && spec.stdin_file.is_some() {
        return Err(PyValueError::new_err(
            "stdin and stdin_file are mutually exclusive",
        ));
    }
    for key in spec.copy_in.iter().flat_map(|m| m.keys()) {
        validate_rel_key("copy_in", key)?;
    }
    for entry in spec.copy_out.iter().flatten() {
        validate_rel_key("copy_out", &entry.src_rel)?;
    }
    // `cwd` shares the coordinate system (a path relative to the sandbox
    // working directory) and the same validation: it used to be unchecked,
    // so `cwd=r"..\.."` or an absolute path silently moved the program
    // outside the private workdir.
    if let Some(cwd) = &spec.cwd {
        validate_rel_key("cwd", cwd)?;
    }
    Ok(())
}
