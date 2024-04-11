use crate::error::Error::{LinuxError, S};
use libc::pid_t;
use std::ffi::CString;
use std::path::Path;
use std::ptr;
use std::time::Instant;

use crate::status::Status;
use crate::sys::linux::utils::{last_err, ExecArgs};
use crate::sys::SandboxImpl;
use crate::{syscall_or_panic, Opts};

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
    file_size_limit: Option<u32>,
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
            file_size_limit: Some(0),
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
                | libc::CLONE_NEWUSER // 在 namespaces 空间内使用新的用户，这允许我们在不使用 root 用户的情况下创建新的 namespaces 空间
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

/**
 *  从这里开始主流程将无法获取函数返回值等信息，因此有异常就直接 panic 退出
 */
extern "C" fn runit(sandbox: *mut libc::c_void) -> i32 {
    let sandbox = unsafe { &mut *(sandbox as *mut Sandbox) };

    // 判断 runit 是否存在
    let runit_exists = Path::new("/usr/bin/runit").exists();

    let pid = unsafe { libc::fork() };

    if pid > 0 {
        // 父进程
        runit_parent(&sandbox, pid, runit_exists)
    } else {
        // 子进程
        runit_child(&sandbox, runit_exists)
    }
}

fn runit_parent(sandbox: &Sandbox, pid: pid_t, runit_exists: bool) -> i32 {
    0
}

fn runit_child(sandbox: &Sandbox, runit_exists: bool) -> i32 {
    // 进行资源与安全限制等
    let mut rlimit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // CPU 时间限制，单位为 S
    if let Some(time_limit) = sandbox.time_limit {
        rlimit.rlim_cur = (time_limit / 1000 + 1) as u64;
        if time_limit % 1000 > 800 {
            rlimit.rlim_cur += 1;
        }
        rlimit.rlim_max = rlimit.rlim_cur;
        unsafe {
            syscall_or_panic!(
                libc::setrlimit(libc::RLIMIT_CPU, &rlimit),
                "setrlimit RLIMIT_CPU"
            )
        };
    }
    // 内存限制，单位为 kib
    if let Some(memory_limit) = sandbox.memory_limit {
        rlimit.rlim_cur = memory_limit as u64 * 1024 * 2;
        rlimit.rlim_max = memory_limit as u64 * 1024 * 2;
        unsafe {
            syscall_or_panic!(
                libc::setrlimit(libc::RLIMIT_AS, &rlimit),
                "setrlimit RLIMIT_AS"
            )
        };

        rlimit.rlim_cur = memory_limit as u64 * 1024 * 2;
        rlimit.rlim_max = memory_limit as u64 * 1024 * 2;
        unsafe {
            syscall_or_panic!(
                libc::setrlimit(libc::RLIMIT_STACK, &rlimit),
                "setrlimit RLIMIT_STACK"
            )
        };
    }
    // 文件大小限制，单位为 bit
    if let Some(file_size_limit) = sandbox.file_size_limit {
        rlimit.rlim_cur = file_size_limit as u64;
        rlimit.rlim_max = file_size_limit as u64;
        unsafe {
            syscall_or_panic!(
                libc::setrlimit(libc::RLIMIT_FSIZE, &rlimit),
                "setrlimit RLIMIT_FSIZE"
            )
        };
    }
    // 重定向输入输出流
    if let Some(file) = &sandbox.input {
        let f = CString::new(file.clone()).unwrap();
        let fd = unsafe {
            syscall_or_panic!(
                libc::open(f.as_ptr(), libc::O_RDONLY, 0o644),
                format!("open input file `{}`", file)
            )
        };
        unsafe { syscall_or_panic!(libc::dup2(fd, libc::STDIN_FILENO), "dup2 stdin") };
    }
    if let Some(file) = &sandbox.output {
        let f = CString::new(file.clone()).unwrap();
        let fd = unsafe {
            syscall_or_panic!(
                libc::open(f.as_ptr(), libc::O_CREAT | libc::O_RDWR, 0o644),
                format!("open output file `{}`", file)
            )
        };
        unsafe { syscall_or_panic!(libc::dup2(fd, libc::STDOUT_FILENO), "dup2 stdout") };
    }
    if let Some(file) = &sandbox.error {
        let f = CString::new(file.clone()).unwrap();
        let fd = unsafe {
            syscall_or_panic!(
                libc::open(f.as_ptr(), libc::O_CREAT | libc::O_RDWR, 0o644),
                format!("open error file `{}`", file)
            )
        };
        unsafe { syscall_or_panic!(libc::dup2(fd, libc::STDERR_FILENO), "dup2 stderr") };
    }

    let exec_args = if !runit_exists {
        ExecArgs::build(&sandbox.inner_args)
    } else {
        ExecArgs::build(&sandbox.inner_args)
    }
    .unwrap();

    unsafe {
        syscall_or_panic!(
            libc::execve(exec_args.pathname, exec_args.argv, exec_args.envp),
            "execve"
        )
    }
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
