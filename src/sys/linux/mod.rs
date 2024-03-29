use crate::error::Error::{LinuxError, S};
use libc::pid_t;
use std::ptr;
use std::time::Instant;

use crate::status::Status;
use crate::sys::SandboxImpl;
use crate::Opts;

mod seccomp;
mod utils;

const STACK_SIZE: usize = 1024 * 1024;

#[macro_export]
macro_rules! linux_syscall {
    ($expression:expr) => {{
        let ret = $expression;
        if ret < 0 {
            let err = std::io::Error::last_os_error().raw_os_error();
            return Err(LinuxError(String::from(file!()), line!(), err));
        };
        ret
    }};
}

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
        let stack = libc::mmap(
            ptr::null_mut(),
            STACK_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_STACK,
            -1,
            0,
        );
        if stack == libc::MAP_FAILED {
            let err = std::io::Error::last_os_error().raw_os_error();
            return Err(LinuxError(String::from(file!()), line!(), err));
        }

        let pid = linux_syscall!(libc::clone(
            runit,
            (stack as usize + STACK_SIZE) as *mut libc::c_void,
            libc::SIGCHLD
                | libc::CLONE_NEWUTS // 设置新的 UTS 名称空间（主机名、网络名等）
                | libc::CLONE_NEWNET // 设置新的网络空间，如果没有配置网络，则该沙盒内部将无法联网
                | libc::CLONE_NEWNS // 为沙盒内部设置新的 namespaces 空间
                | libc::CLONE_NEWIPC // IPC 隔离
                | libc::CLONE_NEWCGROUP // 在新的 CGROUP 中创建沙盒
                | libc::CLONE_NEWPID, // 外部进程对沙盒不可见
            self as *mut _ as *mut libc::c_void,
        ));

        let status = wait_it(pid);

        linux_syscall!(libc::munmap(stack, STACK_SIZE));

        status
    }
}

extern "C" fn runit(sandbox: *mut libc::c_void) -> i32 {
    let sandbox = unsafe { &mut *(sandbox as *mut Sandbox) };
    println!("{:?}", sandbox);

    let pid = unsafe { libc::fork() };

    if pid > 0 {
        // 父进程
        runit_parent(pid)
    } else {
        // 子进程
        runit_child()
    }
}

fn runit_parent(pid: pid_t) -> i32 {
    0
}

fn runit_child() -> i32 {
    0
}

unsafe fn wait_it(pid: i32) -> crate::error::Result<Status> {
    let start_time = Instant::now();

    let mut status: i32 = 0;
    let mut rusage: libc::rusage = utils::new_rusage();

    linux_syscall!(libc::wait4(pid, &mut status, 0, &mut rusage));

    let cpu_time_used = rusage.ru_utime.tv_sec * 1000
        + i64::from(rusage.ru_utime.tv_usec) / 1000
        + rusage.ru_stime.tv_sec * 1000
        + i64::from(rusage.ru_stime.tv_usec) / 1000;
    let memory_used = rusage.ru_maxrss;
    let mut exit_code = 0;
    let exited = libc::WIFEXITED(status);
    if exited {
        exit_code = libc::WEXITSTATUS(status);
    }
    let signal = if libc::WIFSIGNALED(status) {
        libc::WTERMSIG(status)
    } else if libc::WIFSTOPPED(status) {
        libc::WSTOPSIG(status)
    } else {
        0
    };

    let time_used = start_time.elapsed().as_millis();
    Ok(Status {
        time_used: time_used as u64,
        cpu_time_used: cpu_time_used as u64,
        memory_used: memory_used as u64,
        exit_code,
        status,
        signal,
    })
}
