use crate::error::Error::LinuxError;
use std::ptr;

use crate::status::Status;
use crate::sys::SandboxImpl;
use crate::Opts;

mod seccomp;

const STACK_SIZE: usize = 1024 * 1024;

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

        let pid = libc::clone(
            runit,
            (stack as usize + STACK_SIZE) as *mut libc::c_void,
            libc::SIGCHLD
                | libc::CLONE_NEWUTS  // 设置新的 UTS 名称空间（主机名、网络名等）
                | libc::CLONE_NEWNET  // 设置新的网络空间，如果没有配置网络，则该沙盒内部将无法联网
                | libc::CLONE_NEWNS  // 为沙盒内部设置新的 namespaces 空间
                | libc::CLONE_NEWIPC  // IPC 隔离
                | libc::CLONE_NEWCGROUP  // 在新的 CGROUP 中创建沙盒
                | libc::CLONE_NEWPID, // 外部进程对沙盒不可见
            self as *mut _ as *mut libc::c_void,
        );
        Ok(status)
    }
}

extern "C" fn runit(sandbox: *mut libc::c_void) -> i32 {
    let sandbox = unsafe { &mut *(sandbox as *mut Sandbox) };
    println!("{:?}", sandbox);
    0
}

fn wait_it(pid: i32) -> Status {
    Status::default()
}
