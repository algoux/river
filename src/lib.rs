use pyo3::prelude::*;

#[pyclass]
struct River {
    file: String,
}

#[pymethods]
impl River {
    #[new]
    fn new(file: String) -> Self {
        Self { file }
    }

    #[getter]
    fn val(&self) -> String {
        self.file.to_string()
    }

    fn __str__(&self) -> String {
        self.file.to_string()
    }
}

#[pymodule]
fn river(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<River>()?;
    Ok(())
}
