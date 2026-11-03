use pyo3::prelude::*;

#[pyclass(module = "river")]
#[derive(Default)]
pub struct Status {
    pub time_used: u64,
    pub memory_used: u64,
    pub wall_time_used: u64,
    pub status: i32,
    pub signal: i32,
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[pymethods]
impl Status {
    #[getter]
    fn time_used(&self) -> u64 {
        self.time_used
    }

    #[getter]
    fn memory_used(&self) -> u64 {
        self.memory_used
    }

    #[getter]
    fn wall_time_used(&self) -> u64 {
        self.wall_time_used
    }

    #[getter]
    fn status(&self) -> i32 {
        self.status
    }

    #[getter]
    fn signal(&self) -> i32 {
        self.signal
    }

    #[getter]
    fn exit_code(&self) -> i32 {
        self.exit_code
    }

    #[getter]
    fn stdout(&self) -> Vec<u8> {
        self.stdout.clone()
    }

    #[getter]
    fn stderr(&self) -> Vec<u8> {
        self.stderr.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "Status(status={:?}, exit_code={:?}, signal={:?})",
            self.status, self.exit_code, self.signal
        )
    }
}
