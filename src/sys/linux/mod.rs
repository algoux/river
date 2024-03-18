mod seccomp;

use crate::status::Status;
use crate::sys::SandboxImpl;
use crate::Opts;

#[derive(Debug)]
pub struct Sandbox {
    inner_args: Vec<String>,
    time_limit: Option<u32>,
    cpu_time_limit: Option<u32>,
    memory_limit: Option<u32>,
    input: Option<String>,
    output: Option<String>,
    error: Option<String>,
}

impl SandboxImpl for Sandbox {
    fn with_opts(opts: Opts) -> Self {
        Sandbox {
            inner_args: opts.command,
            time_limit: opts.time_limit,
            cpu_time_limit: opts.cpu_time_limit,
            memory_limit: opts.memory_limit,
            input: opts.input,
            output: opts.output,
            error: opts.error,
        }
    }

    unsafe fn run(&mut self) -> crate::error::Result<Status> {
        let status: Status = Default::default();
        Ok(status)
    }
}
