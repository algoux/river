pub mod status;

use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug)]
// The Windows backend reads every field; the placeholder backends only read
// the three limits, so suppress the unused-field lint there.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) struct RunSpec {
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub cwd: Option<String>,
    pub envs: Option<HashMap<String, String>>,
    pub cpu_time_limit_ms: Option<u64>,
    pub wall_time_limit_ms: Option<u64>,
    pub memory_limit_bytes: Option<u64>,
    pub stdin_file: Option<PathBuf>,
    pub copy_in: Option<HashMap<PathBuf, PathBuf>>,
    pub copy_out: Option<HashMap<PathBuf, PathBuf>>,
    pub copy_out_limit_bytes: Option<u64>,
    pub stdout_limit_bytes: Option<u64>,
    pub stderr_limit_bytes: Option<u64>,
    pub stdout_file: Option<PathBuf>,
    pub stderr_file: Option<PathBuf>,
}
