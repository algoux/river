mod error;
mod runner;
mod utils;

use crate::runner::Runner;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;

#[pyclass]
struct RiverResult {
    time_used: i32,
    memory_used: i32,
    signal: i32,
    exit_code: i32,
}

#[pymethods]
impl RiverResult {
    #[getter]
    fn time_used(&self) -> i32 {
        self.time_used
    }
    #[getter]
    fn memory_used(&self) -> i32 {
        self.memory_used
    }
    #[getter]
    fn signal(&self) -> i32 {
        self.signal
    }
    #[getter]
    fn exit_code(&self) -> i32 {
        self.exit_code
    }
}

#[pyclass]
#[derive(Clone, Debug)]
struct River {
    file: String,
    args: Vec<String>,
    time_limit: Option<i32>,
    memory_limit: Option<i32>,
    in_fd: Option<i32>,
    out_fd: Option<i32>,
    err_fd: Option<i32>,
}

#[pymethods]
impl River {
    #[new]
    fn new(cmd: &str) -> Self {
        let commands: Vec<&str> = cmd.split_whitespace().collect();
        Self {
            file: commands[0].to_string(),
            args: commands[1..].iter().map(|f| f.to_string()).collect(),
            time_limit: None,
            memory_limit: None,
            in_fd: None,
            out_fd: None,
            err_fd: None,
        }
    }

    #[setter]
    fn set_time_limit(&mut self, time_limit: i32) {
        self.time_limit = Some(time_limit)
    }
    #[getter]
    fn get_time_limit(&self) -> Option<i32> {
        self.time_limit
    }

    #[setter]
    fn set_memory_limit(&mut self, memory_limit: i32) {
        self.memory_limit = Some(memory_limit)
    }
    #[getter]
    fn get_memory_limit(&self) -> Option<i32> {
        self.memory_limit
    }

    #[setter]
    fn set_in_fd(&mut self, fd: i32) {
        self.in_fd = Some(fd)
    }
    #[getter]
    fn get_in_fd(&self) -> Option<i32> {
        self.in_fd
    }

    #[setter]
    fn set_out_fd(&mut self, fd: i32) {
        self.out_fd = Some(fd)
    }
    #[getter]
    fn get_out_fd(&self) -> Option<i32> {
        self.out_fd
    }

    #[setter]
    fn set_err_fd(&mut self, fd: i32) {
        self.err_fd = Some(fd)
    }
    #[getter]
    fn get_err_fd(&self) -> Option<i32> {
        self.err_fd
    }

    #[pyo3(signature = ())]
    fn run(&self) -> PyResult<RiverResult> {
        match unsafe { Runner::run(self) } {
            Ok(r) => Ok(r),
            Err(err) => Err(PyRuntimeError::new_err(err.to_string())),
        }
    }

    fn __str__(&self) -> String {
        let mut resp = String::from("command:      ");
        resp.push_str(&self.file);
        if self.args.len() > 0 {
            resp.push_str(" ");
            resp.push_str(&self.args.join(" "));
        }
        if let Some(t) = self.time_limit {
            resp.push_str(format!("\ntime limit:   {}", t).as_str());
        }
        if let Some(t) = self.memory_limit {
            resp.push_str(format!("\nmemory limit: {}", t).as_str());
        }

        resp
    }
}

#[pymodule]
fn river(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<River>()?;
    m.add_class::<RiverResult>()?;
    Ok(())
}
