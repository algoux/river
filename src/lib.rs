use pyo3::prelude::*;

#[pyclass]
struct River {
    file: String,
    args: Vec<String>,
    time_limit: Option<i64>,
    memory_limit: Option<i64>,
    in_fd: Option<i64>,
    out_fd: Option<i64>,
    err_fd: Option<i64>,
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
    fn set_time_limit(&mut self, time_limit: i64) {
        self.time_limit = Some(time_limit)
    }
    #[getter]
    fn get_time_limit(&self) -> Option<i64> {
        self.time_limit
    }

    #[setter]
    fn set_memory_limit(&mut self, memory_limit: i64) {
        self.memory_limit = Some(memory_limit)
    }
    #[getter]
    fn get_memory_limit(&self) -> Option<i64> {
        self.memory_limit
    }

    #[setter]
    fn set_in_fd(&mut self, fd: i64) {
        self.in_fd = Some(fd)
    }
    #[getter]
    fn get_in_fd(&self) -> Option<i64> {
        self.in_fd
    }

    #[setter]
    fn set_out_fd(&mut self, fd: i64) {
        self.out_fd = Some(fd)
    }
    #[getter]
    fn get_out_fd(&self) -> Option<i64> {
        self.out_fd
    }

    #[setter]
    fn set_err_fd(&mut self, fd: i64) {
        self.err_fd = Some(fd)
    }
    #[getter]
    fn get_err_fd(&self) -> Option<i64> {
        self.err_fd
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
    Ok(())
}
