use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

use pyo3::prelude::*;
use pyo3::types::PyAny;

use crate::backend::linux::cgroup::{self, Cgroup, physical_memory_bytes};
use crate::backend::linux::monitor;
use crate::backend::linux::ns;
use crate::backend::linux::seccomp;
use crate::backend::linux::stdio::{StdinSource, StdioSet};
use crate::backend::linux::uidpool;
use crate::backend::linux::workdir::{self, WorkDir};
use crate::contract::status::Status;
use crate::contract::verdict::{KillOrigin, RunEvidence, classify};
use crate::contract::{RunSpec, SafetyCeilings, parse_copy_in, parse_copy_out, validate};

const RESIDUAL_GRACE: Duration = Duration::from_millis(100);

const CHILD_FSIZE_BYTES: u64 = 64 * 1024 * 1024;

const CHILD_NOFILE: u64 = 1024;

fn validate_rootfs(path: &std::path::Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!(
            "rootfs must be an absolute host path: {}",
            path.display()
        ));
    }
    if path == std::path::Path::new("/") {
        return Err("rootfs \"/\" is refused: it would expose the whole host".to_string());
    }
    match std::fs::symlink_metadata(path) {
        Ok(md) => {
            if !md.is_dir() && !md.is_file() {
                return Err(format!(
                    "rootfs must be a directory or a squashfs image file: {}",
                    path.display()
                ));
            }
            Ok(())
        }
        Err(_) => Err(format!("rootfs does not exist: {}", path.display())),
    }
}

fn child_limits(cpu_limit_ms: Option<u64>, uid: libc::uid_t, gid: libc::gid_t) -> ns::ChildLimits {
    ns::ChildLimits {
        fsize_bytes: CHILD_FSIZE_BYTES,
        nofile: CHILD_NOFILE,
        cpu_secs: cpu_limit_ms.map(|ms| ms.saturating_add(999).div_ceil(1000) + 1),
        uid,
        gid,
    }
}

#[pyclass(module = "river", frozen)]
pub struct Sandbox {
    pub rootfs: Option<PathBuf>,
    pub runtimes: Vec<PathBuf>,
}

#[pymethods]
impl Sandbox {
    #[new]
    #[pyo3(signature = (rootfs=None, runtimes=None))]
    #[pyo3(text_signature = "(rootfs=None, runtimes=None)")]
    fn new(rootfs: Option<PathBuf>, runtimes: Option<Vec<PathBuf>>) -> PyResult<Self> {
        if let Some(fs) = &rootfs {
            validate_rootfs(fs).map_err(pyo3::exceptions::PyValueError::new_err)?;
        }
        Ok(Self {
            rootfs,
            runtimes: runtimes.unwrap_or_default(),
        })
    }

    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        workdir::sweep_stale_workdirs();
        cgroup::sweep_stale_cgroups();
        slf
    }

    fn __exit__(
        &self,
        _exc_type: &Bound<'_, PyAny>,
        _exc_value: &Bound<'_, PyAny>,
        _traceback: &Bound<'_, PyAny>,
    ) -> bool {
        workdir::sweep_stale_workdirs();
        cgroup::sweep_stale_cgroups();
        false
    }

    #[pyo3(signature = (
        executable,
        args = vec![],
        cwd = None,
        env = None,
        time_limit_ms = None,
        wall_time_limit_ms = None,
        memory_limit_kb = None,
        stdin = None,
        stdin_file = None,
        copy_in = None,
        copy_out = None,
        copy_out_limit_kb = None,
        stdout_limit_kb = None,
        stderr_limit_kb = None,
        stdout_file = None,
        stderr_file = None,
    ))]
    #[pyo3(
        text_signature = "(executable, args=[], cwd=None, env=None, time_limit_ms=None, wall_time_limit_ms=None, memory_limit_kb=None, stdin=None, stdin_file=None, copy_in=None, copy_out=None, copy_out_limit_kb=None, stdout_limit_kb=None, stderr_limit_kb=None, stdout_file=None, stderr_file=None)"
    )]
    #[allow(clippy::too_many_arguments)]
    fn run(
        &self,
        executable: PathBuf,
        args: Vec<String>,
        cwd: Option<String>,
        env: Option<HashMap<String, String>>,
        time_limit_ms: Option<u64>,
        wall_time_limit_ms: Option<u64>,
        memory_limit_kb: Option<u64>,
        stdin: Option<Vec<u8>>,
        stdin_file: Option<PathBuf>,
        copy_in: Option<HashMap<String, Py<PyAny>>>,
        copy_out: Option<HashMap<String, PathBuf>>,
        copy_out_limit_kb: Option<u64>,
        stdout_limit_kb: Option<u64>,
        stderr_limit_kb: Option<u64>,
        stdout_file: Option<PathBuf>,
        stderr_file: Option<PathBuf>,
        py: Python<'_>,
    ) -> PyResult<Status> {
        let spec = RunSpec {
            executable,
            args,
            cwd,
            env,
            time_limit_ms,
            wall_time_limit_ms,
            memory_limit_kb,
            stdin,
            stdin_file,
            copy_in: match &copy_in {
                Some(map) => Some(parse_copy_in(map, py)?),
                None => None,
            },
            copy_out: match &copy_out {
                Some(map) => Some(parse_copy_out(map)?),
                None => None,
            },
            copy_out_limit_bytes: copy_out_limit_kb.map(|kb| kb.saturating_mul(1024)),
            stdout_limit_kb,
            stderr_limit_kb,
            stdout_file,
            stderr_file,
        };
        validate(&spec)?;

        let memory_limit_bytes = spec
            .memory_limit_kb
            .map(|kb| kb.saturating_mul(1024))
            .unwrap_or_else(|| physical_memory_bytes().unwrap_or(u64::MAX));
        let cpu_time_limit_ms = spec.time_limit_ms;
        let stdout_limit = spec.stdout_limit_kb.map(|kb| kb.saturating_mul(1024));
        let stderr_limit = spec.stderr_limit_kb.map(|kb| kb.saturating_mul(1024));
        let wall_limit = spec
            .effective_wall_time_limit_ms()
            .map(Duration::from_millis)
            .unwrap_or(SafetyCeilings::default().wall_limit);
        let copy_out_limit_bytes = spec.copy_out_limit_bytes;
        let seccomp = match seccomp::filters() {
            Ok(program) => Some(program),
            Err(e) => return Ok(Status::infra_se(e)),
        };

        let result = py.detach(move || -> io::Result<_> {
            let RunSpec {
                executable: exe,
                args,
                cwd: cwd_rel,
                env,
                stdin,
                stdin_file,
                copy_in,
                copy_out,
                stdout_file,
                stderr_file,
                ..
            } = spec;
            let stdin_src = match (stdin, stdin_file) {
                (Some(bytes), _) => StdinSource::Bytes(bytes),
                (None, Some(path)) => StdinSource::File(path),
                _ => StdinSource::Null,
            };
            let env_map = env.unwrap_or_default();
            let workdir = WorkDir::create()?;
            if let Some(files) = &copy_in {
                workdir.provision(files)?;
            }
            let tmp_dir = workdir.path().join("tmp");
            std::fs::create_dir(&tmp_dir)?;
            let identity = uidpool::acquire()?;
            workdir.grant_to(identity.uid, identity.gid)?;
            WorkDir::grant_dir_to(&tmp_dir, identity.uid, identity.gid)?;

            let mut env_vars: Vec<(String, String)> = vec![
                (
                    "PATH".to_string(),
                    "/usr/local/bin:/usr/bin:/bin".to_string(),
                ),
                ("HOME".to_string(), "/cwd".to_string()),
                ("TMPDIR".to_string(), "/cwd/tmp".to_string()),
            ];
            for (k, v) in &env_map {
                env_vars.push((k.clone(), v.clone()));
            }

            let mut set = StdioSet::new(
                stdin_src,
                stdout_limit,
                stderr_limit,
                stdout_file,
                stderr_file,
                SafetyCeilings::default().into(),
            )?;
            let cgroup = Cgroup::create(
                memory_limit_bytes,
                SafetyCeilings::default().max_processes + 1,
            )?;
            let procs_c = cgroup.procs_path_c()?;
            let child = ns::spawn(
                &exe,
                &args,
                workdir.path(),
                self.rootfs.as_deref(),
                &self.runtimes,
                cwd_rel.as_deref(),
                &env_vars,
                Some(&procs_c),
                child_limits(cpu_time_limit_ms, identity.uid, identity.gid),
                seccomp,
                &mut set,
            )?;

            let outcome = monitor::monitor(
                child.pid,
                wall_limit,
                &set.overflow(),
                Some(&cgroup),
                cpu_time_limit_ms,
            )?;
            let residual = cgroup.wait_until_empty(RESIDUAL_GRACE)?;
            if residual > 0 {
                cgroup.kill_all()?;
                let _ = cgroup.wait_until_empty(RESIDUAL_GRACE);
            }
            let oom_killed = cgroup.oom_killed().unwrap_or(false);
            let collected = match &copy_out {
                Some(entries) => workdir.collect(entries, copy_out_limit_bytes)?,
                None => crate::backend::linux::workdir::Collected::default(),
            };
            let cpu_used_ms = cgroup
                .usage_usec()
                .map(|us| us / 1000)
                .unwrap_or(outcome.cpu_time_ms);
            let peak_bytes = cgroup.peak_bytes().unwrap_or(outcome.peak_memory_bytes);
            let (out, err, overflowed) = set.finish()?;
            child.disarm();
            Ok((
                outcome,
                residual,
                oom_killed,
                cpu_used_ms,
                peak_bytes,
                out,
                err,
                overflowed,
                collected.quota_exceeded,
            ))
        });

        match result {
            Ok((
                outcome,
                residual,
                oom_killed,
                cpu_used_ms,
                peak_bytes,
                out,
                err,
                overflowed,
                quota_exceeded,
            )) => {
                let kill = if overflowed {
                    KillOrigin::OutputLimit
                } else if quota_exceeded {
                    KillOrigin::CopyOutQuota
                } else {
                    outcome.kill
                };
                let evidence = RunEvidence {
                    kill,
                    exit_code: outcome.exit_code,
                    residual_processes: residual,
                    oom_killed,
                    cpu_time_limit_ms,
                    cpu_time_used_ms: cpu_used_ms,
                    memory_limit_bytes: Some(memory_limit_bytes),
                    peak_memory_bytes: peak_bytes,
                };
                let mut status = Status::from_verdict(classify(&evidence));
                status.time_used_ms = cpu_used_ms;
                status.wall_time_used_ms = outcome.wall_time_ms;
                status.memory_used_kb = peak_bytes / 1024;
                status.exit_code = outcome.exit_code;
                status.oom_killed = oom_killed;
                status.stdout = out.data;
                status.stderr = err.data;
                status.stdout_truncated = out.truncated;
                status.stderr_truncated = err.truncated;
                status.stdout_file_truncated = out.sink_truncated;
                status.stderr_file_truncated = err.sink_truncated;
                Ok(status)
            }
            Err(e) => Ok(Status::infra_se(e.to_string())),
        }
    }

    fn __repr__(&self) -> String {
        match &self.rootfs {
            Some(rootfs) => format!(
                "Sandbox(rootfs={:?}, runtimes=[{}])",
                rootfs.display().to_string(),
                self.runtimes.len()
            ),
            None => format!("Sandbox(runtimes=[{}])", self.runtimes.len()),
        }
    }
}
