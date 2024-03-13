use std::fmt;
use std::fmt::Formatter;
use std::fs;

use serde::{Deserialize, Serialize};

use crate::error::Error::{IOError, SerdeJsonError};
use crate::error::Result;

#[derive(Debug, Serialize, Deserialize)]
pub struct Status {
    pub time_used: u64,
    pub cpu_time_used: u64,
    pub memory_used: u64,
    pub exit_code: i32,
    pub status: i32,
    pub signal: i32,
}

impl Status {
    pub fn write(&self, file: Option<String>) -> Result<()> {
        let json_str = serde_json::to_string_pretty(&self).map_err(|e| SerdeJsonError(e))?;
        if let Some(f) = file {
            fs::write(f, format!("{}", json_str)).map_err(|e| IOError(e))?;
        } else {
            println!("{}", json_str);
        };
        Ok(())
    }
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
