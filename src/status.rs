use std::fmt;
use std::fmt::Formatter;

#[derive(Debug)]
pub struct Status {
    pub time_used: u64,
    pub cpu_time_used: u64,
    pub memory_used: u64,
    pub exit_code: i32,
    pub status: i32,
    pub signal: i32,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Default for Status {
    fn default() -> Self {
        Status {
            time_used: 0,
            cpu_time_used: 0,
            memory_used: 0,
            exit_code: 0,
            status: 0,
            signal: 0,
        }
    }
}
