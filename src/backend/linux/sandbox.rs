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
use crate::backend::linux::workdir::{self, WorkDir};
use crate::contract::status::Status;
use crate::contract::verdict::{KillOrigin, RunEvidence, classify};
use crate::contract::{RunSpec, SafetyCeilings, parse_copy_in, validate};

/// How long a cgroup may take to become empty after the main process was
/// reaped before its leftovers count as residual descendants (anti-cheat).
/// The kernel removes tasks from `cgroup.procs` asynchronously, so a short
/// grace period avoids the Windows §5.4 false positive.
const RESIDUAL_GRACE: Duration = Duration::from_millis(100);

/// `RLIMIT_FSIZE` for the sandboxed program: a single file it writes cannot
/// grow past this, so a runaway writer dies on `SIGXFSZ` instead of filling
/// the host disk. (Total `cwd` usage still relies on the caller's disk.)
const CHILD_FSIZE_BYTES: u64 = 64 * 1024 * 1024;

/// `RLIMIT_NOFILE` for the sandboxed program.
const CHILD_NOFILE: u64 = 1024;

/// Translate the contract limits into the child-side rlimits.
fn child_limits(cpu_limit_ms: Option<u64>) -> ns::ChildLimits {
    ns::ChildLimits {
        fsize_bytes: CHILD_FSIZE_BYTES,
        nofile: CHILD_NOFILE,
        // RLIMIT_CPU backstop: the judger's 10ms `cpu.stat` poll is the
        // primary enforcement; this only guarantees the kernel kills a
        // multi-process escape eventually.
        cpu_secs: cpu_limit_ms.map(|ms| (ms + 999) / 1000 + 1),
    }
}

/// Linux sandbox.
///
/// The sandbox filesystem model (first stage, docs/linux-plan.md §2.1):
/// - a fresh private writable working directory per `run`, pivoted into a
///   mount namespace so the rest of the host filesystem is invisible;
/// - each path in `runtimes` exposed read-only (+execute) via bind mounts;
/// - `copy_in` files provisioned into the working directory (read-only for
///   the program: root-owned, mode 0444, program runs as nobody);
/// - network access denied (empty network namespace).
///
/// `rootfs` (a caller-supplied root tree) is stage L6: passing it raises
/// `ValueError` for now — check `river.capabilities()`.
///
/// Concurrency: the class is `frozen` — it holds no mutable state (only the
/// configured `runtimes` and the safety ceilings), and every run keeps all
/// of its state in locals. `run()` may therefore be called concurrently from
/// several Python threads on the same `Sandbox`.
#[pyclass(module = "river", frozen)]
pub struct Sandbox {
    pub rootfs: Option<PathBuf>,
    pub runtimes: Vec<PathBuf>,
    /// Internal safety ceilings (mechanism guarantees that stay in place
    /// when the caller passes `None` limits). Configurable so a deployment
    /// can tighten the defaults; never disableable.
    pub(crate) ceilings: SafetyCeilings,
}

#[pymethods]
impl Sandbox {
    #[new]
    #[pyo3(signature = (rootfs=None, runtimes=None, max_wall_secs=None, max_processes=None))]
    #[pyo3(text_signature = "(rootfs=None, runtimes=None, max_wall_secs=None, max_processes=None)")]
    fn new(
        rootfs: Option<PathBuf>,
        runtimes: Option<Vec<PathBuf>>,
        max_wall_secs: Option<u64>,
        max_processes: Option<u32>,
    ) -> PyResult<Self> {
        if rootfs.is_some() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "rootfs is not supported yet on Linux (stage L6); use runtimes=[...] to \
                 expose read-only runtime directories instead (check river.capabilities())",
            ));
        }
        // Fail closed: a missing mechanism (cgroups v2, memory.peak,
        // seccomp) must surface here, not as a silent per-run degradation.
        crate::backend::linux::preflight().map_err(pyo3::exceptions::PyRuntimeError::new_err)?;
        let mut ceilings = SafetyCeilings::default();
        if let Some(secs) = max_wall_secs {
            ceilings.wall_limit = Duration::from_secs(secs.max(1));
        }
        if let Some(n) = max_processes {
            ceilings.max_processes = n.max(1);
        }
        Ok(Self {
            rootfs: None,
            runtimes: runtimes.unwrap_or_default(),
            ceilings,
        })
    }

    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        // Defensive net: reclaim directories/cgroups abandoned by a
        // *different* judger process that was hard-killed (its Drop never
        // ran). Never touches live owners, including ourselves.
        workdir::sweep_stale_workdirs();
        cgroup::sweep_stale_cgroups();
        slf
    }

    /// Exit protocol: everything a `run` leaves behind is owned by per-run
    /// RAII guards (the workdir, the cgroup directory, the stdio pipes), so a
    /// normal block exit has nothing left to do. Always returns `false`
    /// (never suppresses block exceptions).
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

    /// Run an untrusted executable inside the sandbox and collect its status.
    ///
    /// Coordinate systems: `executable` is a host path; `cwd` and `copy_in`
    /// keys are relative to the per-run private working directory.
    ///
    /// Limits: `None` means no caller-imposed limit (internal safety ceilings
    /// still apply). `wall_time_limit_ms` defaults to `2 * time_limit_ms +
    /// 1000` when only a CPU time limit is given.
    ///
    /// `stdin` / `stdin_file` are mutually exclusive. `*_file` output
    /// parameters receive the full captured stream (host paths); the returned
    /// `Status` still carries truncated copies plus truncation flags.
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
        stdout_limit_kb = None,
        stderr_limit_kb = None,
        stdout_file = None,
        stderr_file = None,
    ))]
    #[pyo3(
        text_signature = "(executable, args=[], cwd=None, env=None, time_limit_ms=None, wall_time_limit_ms=None, memory_limit_kb=None, stdin=None, stdin_file=None, copy_in=None, stdout_limit_kb=None, stderr_limit_kb=None, stdout_file=None, stderr_file=None)"
    )]
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
            stdout_limit_kb,
            stderr_limit_kb,
            stdout_file,
            stderr_file,
        };
        validate(&spec)?;

        // --- translate the frozen contract into backend primitives --------
        let stdin_src = match (&spec.stdin, &spec.stdin_file) {
            (Some(bytes), _) => StdinSource::Bytes(bytes.clone()),
            (None, Some(path)) => StdinSource::File(path.clone()),
            _ => StdinSource::Null,
        };
        // Effective limits the sandbox enforces (user limit or safety
        // fallback); the verdict compares measurements against these
        // (contract S9 evidence).
        let memory_limit_bytes = spec
            .memory_limit_kb
            .map(|kb| kb.saturating_mul(1024))
            .unwrap_or_else(|| physical_memory_bytes().unwrap_or(u64::MAX));
        let cpu_time_limit_ms = spec.time_limit_ms;
        let stdout_limit = spec.stdout_limit_kb.map(|kb| kb.saturating_mul(1024));
        let stderr_limit = spec.stderr_limit_kb.map(|kb| kb.saturating_mul(1024));
        // Wall limit: user value, the 2x+1s default for CPU-limited runs, or
        // the configured safety ceiling for "unlimited" runs.
        let wall_limit = spec
            .effective_wall_time_limit_ms()
            .map(Duration::from_millis)
            .unwrap_or(self.ceilings.wall_limit);
        let exe = spec.executable.clone();
        let args = spec.args.clone();
        let (stdout_file, stderr_file) = (spec.stdout_file.clone(), spec.stderr_file.clone());
        let copy_in = spec.copy_in.clone();
        let cwd_rel = spec.cwd.clone();
        let env_map = spec.env.clone().unwrap_or_default();
        let runtimes = self.runtimes.clone();

        // Compile (once per process) the seccomp allowlist; a failure must
        // not silently disable the filter.
        let seccomp = match seccomp::program() {
            Ok(program) => Some(program),
            Err(e) => return Ok(Status::infra_se(e)),
        };

        // Blocking pipeline with the GIL released. All threads (stdio
        // feeder/readers) are created inside this closure, after the fork —
        // the fork-safety rule from docs/linux-plan.md §2.2.
        let result = py.detach(move || -> io::Result<_> {
            // Per-run working directory: the only writable place the program
            // sees. `WorkDir` removes itself on drop (also on error paths).
            // The program reaches it as `/cwd` inside the sandbox.
            let workdir = WorkDir::create()?;
            if let Some(files) = &copy_in {
                workdir.provision(files)?;
            }
            // TMPDIR target: `/cwd/tmp` from the program's point of view.
            let tmp_dir = workdir.path().join("tmp");
            std::fs::create_dir(&tmp_dir)?;
            // The program is nobody; the bind-mounted workdir must belong to
            // it or nothing is writable (copy_in files stay root:0444).
            workdir.grant_to(ns::NOBODY_UID, ns::NOBODY_GID)?;

            // Whitelisted environment, in **sandbox coordinates** (the
            // program never sees host paths). Base + caller overrides.
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
            )?;
            // Per-run cgroup: limits must exist before the program runs.
            // pids.max covers the supervisor too (+1), so the program's own
            // allowance stays exactly `max_processes` (DESIGN §3.6).
            let cgroup = Cgroup::create(memory_limit_bytes, self.ceilings.max_processes + 1)?;
            let procs_c = cgroup.procs_path_c()?;
            let child = ns::spawn(
                &exe,
                &args,
                workdir.path(),
                &runtimes,
                cwd_rel.as_deref(),
                &env_vars,
                Some(&procs_c),
                child_limits(cpu_time_limit_ms),
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
            // The whole tree is gone once the supervisor (or its pid-ns
            // init) exited; force-kill any survivor, then take the
            // measurements before the cgroup directory disappears.
            let residual = cgroup.wait_until_empty(RESIDUAL_GRACE)?;
            if residual > 0 {
                cgroup.kill_all()?;
                let _ = cgroup.wait_until_empty(RESIDUAL_GRACE);
            }
            let oom_killed = cgroup.oom_killed().unwrap_or(false);
            let cpu_used_ms = cgroup
                .usage_usec()
                .map(|us| us / 1000)
                .unwrap_or(outcome.cpu_time_ms);
            let peak_bytes = cgroup.peak_bytes().unwrap_or(outcome.peak_memory_bytes);
            let (out, err, overflowed) = set.finish()?;
            // Normal end: stop and reap the judger-death watchdog.
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
            ))
        });

        match result {
            Ok((outcome, residual, oom_killed, cpu_used_ms, peak_bytes, out, err, overflowed)) => {
                // Evidence-priority verdict (contract S9): the backend
                // reports what it observed; the contract classifies it.
                //
                // Output-limit evidence is *direct observation*: a fast
                // writer can exit before the monitor sees the reader's flag,
                // so the complete result from `finish` has the last word.
                // (OLE outranks inferred memory/time evidence by contract.)
                let kill = if overflowed {
                    KillOrigin::OutputLimit
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
                status.exit_code = outcome.exit_code as i32;
                status.oom_killed = oom_killed;
                status.stdout = out.data;
                status.stderr = err.data;
                status.stdout_truncated = out.truncated;
                status.stderr_truncated = err.truncated;
                Ok(status)
            }
            Err(e) => {
                // Infra failure: report as SE per the frozen contract
                // (validation errors raise; runtime failures surface here).
                Ok(Status::infra_se(e.to_string()))
            }
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "Sandbox(runtimes=[{}], max_wall_secs={}, max_processes={})",
            self.runtimes.len(),
            self.ceilings.wall_limit.as_secs(),
            self.ceilings.max_processes
        )
    }
}
