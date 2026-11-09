use pyo3::prelude::*;

#[pyclass(module = "river")]
#[derive(Default)]
pub struct Status {
    pub cpu_time_used_ms: u64,
    pub wall_time_used_ms: u64,
    pub memory_used_bytes: u64,
    pub status: String,
    pub signal: i32,
    pub exit_code: u32,
}

#[pymethods]
impl Status {
    #[getter]
    fn cpu_time_used_ms(&self) -> u64 {
        self.cpu_time_used_ms
    }

    #[getter]
    fn wall_time_used_ms(&self) -> u64 {
        self.wall_time_used_ms
    }

    #[getter]
    fn memory_used_bytes(&self) -> u64 {
        self.memory_used_bytes
    }

    #[getter]
    fn status(&self) -> String {
        self.status.clone()
    }

    #[getter]
    fn signal(&self) -> i32 {
        self.signal
    }

    #[getter]
    fn exit_code(&self) -> u32 {
        self.exit_code
    }

    fn __repr__(&self) -> String {
        format!(
            "Status(status={:?}, exit_code={:?}, signal={:?},  cpu_time_used_ms={}, wall_time_used_ms={}, memory_used_bytes={})",
            self.status,
            self.exit_code,
            self.signal,
            self.cpu_time_used_ms,
            self.wall_time_used_ms,
            self.memory_used_bytes
        )
    }
}
