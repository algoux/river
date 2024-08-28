use crate::error::{Error, RResult};
use crate::utils::last_err;
use crate::{River, RiverResult};
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
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_STACK,
            -1,
            0,
        );
        if stack == libc::MAP_FAILED {
            return Err(Error::E(last_err()));
        }

        let pid = linux_syscall!(libc::clone(
            runit,
            (stack as usize + STACK_SIZE) as *mut libc::c_void,
            libc::SIGCHLD
                | libc::CLONE_NEWUSER // 在 namespaces 空间内使用新的用户，这允许我们在不使用 root 用户的情况下创建新的 namespaces 空间
                | libc::CLONE_NEWUTS // 设置新的 UTS 名称空间（主机名、网络名等）
                | libc::CLONE_NEWNET // 设置新的网络空间，如果没有配置网络，则该沙盒内部将无法联网
                | libc::CLONE_NEWNS // 为沙盒内部设置新的 namespaces 空间
                | libc::CLONE_NEWIPC // IPC 隔离
                | libc::CLONE_NEWCGROUP // 在新的 CGROUP 中创建沙盒
                | libc::CLONE_NEWPID, // 外部进程对沙盒不可见
            &mut river.clone() as *mut _ as *mut libc::c_void,
        ));

        linux_syscall!(libc::munmap(stack, STACK_SIZE));

        let time_used = runner_start.elapsed();
        Ok(RiverResult {
            time_used: time_used.as_millis() as i32,
            memory_used: 0,
            signal: 0,
            exit_code: 0,
        })
    }
}

extern "C" fn runit(river: *mut libc::c_void) -> i32 {
    let river = unsafe { &mut *(river as *mut River) };
    println!("{}", river.file);
    0
}
