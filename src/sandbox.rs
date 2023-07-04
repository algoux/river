use crate::error::Result;
use log::debug;
use std::mem::size_of;

use crate::error::Error::WinError;
use crate::status::Status;

use windows::Win32::Foundation::{FILETIME, WAIT_FAILED, WAIT_TIMEOUT};
use windows::Win32::System::ProcessStatus::PROCESS_MEMORY_COUNTERS;
use windows::Win32::System::Threading::{GetProcessTimes, TerminateProcess};
use windows::{
    core::{PCSTR, PSTR},
    Win32::Foundation::GetLastError,
    Win32::System::ProcessStatus::GetProcessMemoryInfo,
    Win32::System::Threading,
    Win32::System::Threading::{
        WaitForSingleObject, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOA,
    },
};

pub struct Sandbox {
    inner_args: Vec<String>,
    pub time_limit: Option<u32>,
}

#[cfg(target_os = "windows")]
impl Sandbox {
    pub fn new(args: Vec<String>) -> Self {
        Sandbox {
            inner_args: args,
            time_limit: None,
        }
    }

    pub fn time_limit(mut self, l: Option<u32>) -> Self {
        self.time_limit = l;
        self
    }

    pub fn run(&mut self) -> Result<Status> {
        let mut status: Status = Default::default();
        // 执行的目标 app，前置的命令行解析保证 inner_args 至少有一项
        let app = Vec::from((&self.inner_args[0]).as_bytes()).as_ptr();
        // 执行的文件参数
        let command_line = &self.inner_args[1..].join(" ");
        let command_line_pstr = if self.inner_args.len() > 1 {
            PSTR::from_raw(Vec::from(command_line.as_bytes()).as_mut_ptr())
        } else {
            PSTR::null()
        };

        let mut info: STARTUPINFOA = Default::default();
        let mut information: PROCESS_INFORMATION = Default::default();

        let code = unsafe {
            Threading::CreateProcessA(
                PCSTR::from_raw(app),
                command_line_pstr,
                None,
                None,
                false,
                // CREATE_SUSPENDED: 创建一个暂停的进程，需要 ResumeThread 之后才可以正常运行
                CREATE_SUSPENDED,
                None,
                None,
                &mut info,
                &mut information,
            )
        };
        if code.ok().is_err() {
            return Err(WinError(String::from("CreateProcessA"), unsafe {
                GetLastError()
            }));
        }

        unsafe {
            // 唤醒被暂停的进程
            if Threading::ResumeThread(information.hThread) != 1 {
                return Err(WinError(String::from("ResumeThread"), GetLastError()));
            }
        }

        let timeout = if let Some(t) = self.time_limit {
            t
        } else {
            // 如果 dwMilliseconds 为 INFINITE，则仅当发出对象信号时，该函数才会返回
            0xFFFFFFFF
        };

        let wait_ret = unsafe { WaitForSingleObject(information.hProcess, timeout) };
        if wait_ret == WAIT_TIMEOUT {
            // 超时中断进程
            unsafe {
                debug!("Terminated due to timeout");
                if TerminateProcess(information.hProcess, 0).ok().is_err() {
                    return Err(WinError(String::from("TerminateProcess"), GetLastError()));
                }
                WaitForSingleObject(information.hProcess, 0xFFFFFFFF);
            }
        } else if wait_ret == WAIT_FAILED {
            return Err(WinError(String::from("WaitForSingleObject"), unsafe {
                GetLastError()
            }));
        }

        let mut pmc: PROCESS_MEMORY_COUNTERS = Default::default();

        unsafe {
            // 获取内存使用情况
            GetProcessMemoryInfo(
                information.hProcess,
                &mut pmc,
                size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
            );
            status.memory_used = (pmc.PeakWorkingSetSize / 1024) as u64;
        }

        let mut lp_creation_time: FILETIME = Default::default();
        let mut lp_exit_time: FILETIME = Default::default();
        let mut lp_kernel_time: FILETIME = Default::default();
        let mut lp_user_time: FILETIME = Default::default();
        unsafe {
            GetProcessTimes(
                information.hProcess,
                &mut lp_creation_time,
                &mut lp_exit_time,
                &mut lp_kernel_time,
                &mut lp_user_time,
            );
        }

        // TODO: 需要判断一下，防止溢出和除零
        status.time_used = (lp_exit_time.dwLowDateTime - lp_creation_time.dwLowDateTime) as u64 / 10000;
        status.cpu_time_used = (lp_kernel_time.dwLowDateTime + lp_user_time.dwLowDateTime) as u64 / 10000;

        Ok(status)
    }
}
