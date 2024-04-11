use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::mem;
use std::ptr;

use libc;

use crate::error::{errno_str, Result};

/// 一个全为 `0` 的 `rusage`
#[inline(always)]
pub fn new_rusage() -> libc::rusage {
    libc::rusage {
        ru_utime: libc::timeval {
            tv_sec: 0 as libc::time_t,
            tv_usec: 0 as libc::suseconds_t,
        },
        ru_stime: libc::timeval {
            tv_sec: 0 as libc::time_t,
            tv_usec: 0 as libc::suseconds_t,
        },
        ru_maxrss: 0 as libc::c_long,
        ru_ixrss: 0 as libc::c_long,
        ru_idrss: 0 as libc::c_long,
        ru_isrss: 0 as libc::c_long,
        ru_minflt: 0 as libc::c_long,
        ru_majflt: 0 as libc::c_long,
        ru_nswap: 0 as libc::c_long,
        ru_inblock: 0 as libc::c_long,
        ru_oublock: 0 as libc::c_long,
        ru_msgsnd: 0 as libc::c_long,
        ru_msgrcv: 0 as libc::c_long,
        ru_nsignals: 0 as libc::c_long,
        ru_nvcsw: 0 as libc::c_long,
        ru_nivcsw: 0 as libc::c_long,
    }
}

pub fn last_err() -> String {
    errno_str(std::io::Error::last_os_error().raw_os_error())
}

#[macro_export]
macro_rules! string_to_cstring {
    ($expression:expr) => {
        match CString::new($expression) {
            Ok(value) => value,
            Err(err) => return Err(crate::error::Error::StringToCStringError(err)),
        }
    };
}

/// 执行指定的系统调用，如果返回值小于 0，则抛出异常并结束进程
#[macro_export]
macro_rules! syscall_or_panic {
    ($expression:expr, $syscall:expr) => {{
        let ret = $expression;
        if ret < 0 {
            let last_err = last_err();
            panic!(
                "{file}:{line}: {message}\n ret = {ret}, err = {last_err}",
                file = file!(),
                line = line!(),
                message = $syscall
            );
        };
        ret
    }};
}

pub struct ExecArgs {
    pub pathname: *const libc::c_char,
    pub argv: *const *const libc::c_char,
    pub envp: *const *const libc::c_char,
    args: usize,
    envs: usize,
}

impl ExecArgs {
    pub fn build(args: &Vec<String>) -> Result<ExecArgs> {
        let pathname = args[0].clone();
        let pathname_str = string_to_cstring!(pathname);
        let pathname = pathname_str.as_ptr();

        let mut argv_vec: Vec<*const libc::c_char> = vec![];
        for item in args.iter() {
            let cstr = string_to_cstring!(item.clone());
            let cptr = cstr.as_ptr();
            // 需要使用 mem::forget 来标记
            // 否则在此次循环结束后，cstr 就会被回收，后续 exec 函数无法通过指针获取到字符串内容
            mem::forget(cstr);
            argv_vec.push(cptr);
        }
        // argv 与 envp 的参数需要使用 NULL 来标记结束
        argv_vec.push(ptr::null());
        let argv: *const *const libc::c_char = argv_vec.as_ptr() as *const *const libc::c_char;

        // env 传递环境变量
        let mut envp_vec: Vec<*const libc::c_char> = vec![];
        envp_vec.push(ptr::null());
        let envs = envp_vec.len();
        let envp = envp_vec.as_ptr() as *const *const libc::c_char;

        mem::forget(pathname_str);
        mem::forget(argv_vec);
        mem::forget(envp_vec);
        Ok(ExecArgs {
            pathname,
            argv,
            args: args.len(),
            envp,
            envs,
        })
    }
}

impl Drop for ExecArgs {
    fn drop(&mut self) {
        // 将 forget 的内存重新获取，并释放
        let c_string = unsafe { CString::from_raw(self.pathname as *mut i8) };
        drop(c_string);
        let argv = unsafe {
            Vec::from_raw_parts(
                self.argv as *mut *const libc::c_void,
                self.args - 1,
                self.args - 1,
            )
        };
        for arg in &argv {
            let c_string = unsafe { CString::from_raw(*arg as *mut i8) };
            drop(c_string);
        }
        drop(argv);
        let envp = unsafe {
            Vec::from_raw_parts(
                self.envp as *mut *const libc::c_void,
                self.envs - 1,
                self.envs - 1,
            )
        };
        for env in &envp {
            let c_string = unsafe { CString::from_raw(*env as *mut i8) };
            drop(c_string);
        }
        drop(envp);
    }
}
