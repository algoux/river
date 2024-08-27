use crate::error::{Error, RResult};
use crate::utils::last_err;
use crate::{River, RiverResult};
use std::os::unix::process::ExitStatusExt;
use std::process::Command;
use std::ptr;
use std::time::Instant;

#[macro_export]
macro_rules! linux_syscall {
    ($expression:expr) => {{
        let ret = $expression;
        if ret < 0 {
            return Err(Error::E(last_err()));
        };
        ret
    }};
}

const STACK_SIZE: usize = 1024 * 1024;

pub struct Runner {}

impl Runner {
    pub unsafe fn run(river: &River) -> RResult<RiverResult> {
        // 开始计时，用于计算程序运行所用时间
        let runner_start = Instant::now();

        let stack = libc::mmap(
            ptr::null_mut(),
            STACK_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if stack == libc::MAP_FAILED {
            return Err(Error::E(last_err()));
        }
        let output = Command::new(river.file.as_str())
            .args(river.args.iter())
            .output()
            .expect("failed to execute process");

        let signal = if let Some(s) = output.status.signal() {
            s
        } else {
            0
        };

        linux_syscall!(libc::munmap(stack, STACK_SIZE));

        let time_used = runner_start.elapsed();
        Ok(RiverResult {
            time_used: time_used.as_millis() as i32,
            memory_used: 0,
            signal,
            exit_code: 0,
        })
    }
}
