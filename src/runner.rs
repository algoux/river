use crate::error::{Error, RResult};
use crate::{River, RiverResult};
use std::os::unix::process::ExitStatusExt;
use std::process::Command;

pub struct Runner {}

impl Runner {
    pub unsafe fn run(river: &River) -> RResult<RiverResult> {
        let output = Command::new(river.file.as_str())
            .args(river.args.iter())
            .output()
            .expect("failed to execute process");

        let signal = if let Some(s) = output.status.signal() {
            s
        } else {
            0
        };
        // return Err(Error::E(String::from("Hello World!")));

        Ok(RiverResult {
            time_used: 0,
            memory_used: 0,
            signal,
            exit_code: 0,
        })
    }
}
