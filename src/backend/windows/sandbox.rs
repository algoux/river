use std::collections::HashMap;
use std::path::PathBuf;

use pyo3::prelude::*;
use pyo3::types::PyAny;

use crate::contract::RunSpec;
use crate::contract::status::Status;

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
        if rootfs.is_some() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "rootfs is not supported on Windows; use runtimes=[...] to expose \
                 read-only runtime directories instead",
            ));
        }
        Ok(Self {
            rootfs: None,
            runtimes: runtimes.unwrap_or_default(),
        })
    }

    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __exit__(
        &self,
        _exc_type: &Bound<'_, PyAny>,
        _exc_value: &Bound<'_, PyAny>,
        _traceback: &Bound<'_, PyAny>,
    ) -> bool {
        false
    }

    #[pyo3(signature = (
        executable,
        args = vec![],
        cwd = None,
        envs = None,
        cpu_time_limit_ms = None,
        wall_time_limit_ms = None,
        memory_limit_bytes = None,
        stdin_file = None,
        copy_in = None,
        copy_out = None,
        copy_out_limit_bytes = None,
        stdout_limit_bytes = None,
        stderr_limit_bytes = None,
        stdout_file = None,
        stderr_file = None,
    ))]
    #[pyo3(text_signature = "(
        executable,
        args=[],
        cwd=None,
        envs=None,
        cpu_time_limit_ms=None,
        wall_time_limit_ms=None,
        memory_limit_bytes=None,
        stdin=None,
        stdin_file=None,
        copy_in=None,
        copy_out=None,
        copy_out_limit_bytes=None,
        stdout_limit_bytes=None,
        stderr_limit_bytes=None,
        stdout_file=None,
        stderr_file=None
    )")]
    #[allow(clippy::too_many_arguments)]
    fn exec(
        &self,
        executable: PathBuf,
        args: Vec<String>,
        cwd: Option<String>,
        envs: Option<HashMap<String, String>>,
        cpu_time_limit_ms: Option<u64>,
        wall_time_limit_ms: Option<u64>,
        memory_limit_bytes: Option<u64>,
        stdin_file: Option<PathBuf>,
        copy_in: Option<HashMap<PathBuf, PathBuf>>,
        copy_out: Option<HashMap<PathBuf, PathBuf>>,
        copy_out_limit_bytes: Option<u64>,
        stdout_limit_bytes: Option<u64>,
        stderr_limit_bytes: Option<u64>,
        stdout_file: Option<PathBuf>,
        stderr_file: Option<PathBuf>,
        _py: Python<'_>,
    ) -> PyResult<Status> {
        let _spec = RunSpec {
            executable,
            args,
            cwd,
            envs,
            cpu_time_limit_ms,
            wall_time_limit_ms,
            memory_limit_bytes,
            stdin_file,
            copy_in,
            copy_out,
            copy_out_limit_bytes,
            stdout_limit_bytes,
            stderr_limit_bytes,
            stdout_file,
            stderr_file,
        };

        println!("Sandbox.exec called with spec: {:#?}", _spec);

        Ok(Default::default())
    }

    fn __repr__(&self) -> String {
        format!("Sandbox(runtimes=[{}])", self.runtimes.len())
    }
}
