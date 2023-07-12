use crate::error::Result;
use std::ffi::c_void;
use std::mem::size_of;

use crate::error::Error::WinError;
use crate::status::Status;

use windows::{
    core::{PCSTR, PSTR},
    Win32::Foundation::GetLastError,
    Win32::Foundation::{FILETIME, WAIT_FAILED, WAIT_TIMEOUT},
    Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectA, JobObjectBasicLimitInformation,
        SetInformationJobObject, JOBOBJECT_BASIC_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_PRIORITY_CLASS, JOB_OBJECT_LIMIT_PROCESS_TIME,
    },
    Win32::System::ProcessStatus::GetProcessMemoryInfo,
    Win32::System::ProcessStatus::PROCESS_MEMORY_COUNTERS,
    Win32::System::Threading::{
        CreateProcessA, GetProcessTimes, ResumeThread, SetProcessWorkingSetSize, TerminateProcess,
        WaitForSingleObject, CREATE_SUSPENDED, IDLE_PRIORITY_CLASS, PROCESS_INFORMATION,
        STARTUPINFOA,
    },
};

pub struct Sandbox {
    inner_args: Vec<String>,
    pub time_limit: Option<u32>,
    pub cpu_time_limit: Option<u32>,
    pub memory_limit: Option<u32>,
}

impl Sandbox {
    pub fn new(args: Vec<String>) -> Self {
        Sandbox {
            inner_args: args,
            time_limit: None,
            cpu_time_limit: None,
            memory_limit: None,
        }
    }

    pub fn time_limit(mut self, l: Option<u32>) -> Self {
        self.time_limit = l;
        self
    }
    pub fn cpu_time_limit(mut self, l: Option<u32>) -> Self {
        self.cpu_time_limit = l;
        self
    }
    pub fn memory_limit(mut self, l: Option<u32>) -> Self {
        self.memory_limit = l;
        self
    }
}

#[macro_export]
macro_rules! winapi_bool {
    ($expression:expr) => {
        if $expression.as_bool() == false {
            return Err(WinError(String::from(file!()), line!(), unsafe {
                GetLastError()
            }));
        }
    };
}

#[cfg(target_os = "windows")]
impl Sandbox {
    pub unsafe fn run(&mut self) -> Result<Status> {
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

        winapi_bool!(CreateProcessA(
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
        ));

        self.limit(&information)?;

        // 唤醒被暂停的进程
        if ResumeThread(information.hThread) != 1 {
            return Err(WinError(String::from(file!()), line!(), unsafe {
                GetLastError()
            }));
        }

        self.wait_it(&information)
    }

    unsafe fn wait_it(&mut self, information: &PROCESS_INFORMATION) -> Result<Status> {
        let mut status: Status = Default::default();

        let timeout = if let Some(t) = self.time_limit {
            t
        } else {
            // 如果 dwMilliseconds 为 INFINITE，则仅当发出对象信号时，该函数才会返回
            0xFFFFFFFF
        };

        let wait_ret = WaitForSingleObject(information.hProcess, timeout);
        if wait_ret == WAIT_TIMEOUT {
            // 超时中断进程
            winapi_bool!(TerminateProcess(information.hProcess, 0));
            // 此处不检查返回值
            WaitForSingleObject(information.hProcess, 0xFFFFFFFF);
        } else if wait_ret == WAIT_FAILED {
            return Err(WinError(String::from(file!()), line!(), unsafe {
                GetLastError()
            }));
        }

        let mut pmc: PROCESS_MEMORY_COUNTERS = Default::default();

        // 获取内存使用情况
        winapi_bool!(GetProcessMemoryInfo(
            information.hProcess,
            &mut pmc,
            size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        ));

        status.memory_used = (pmc.PeakWorkingSetSize / 1024) as u64;

        let mut lp_creation_time: FILETIME = Default::default();
        let mut lp_exit_time: FILETIME = Default::default();
        let mut lp_kernel_time: FILETIME = Default::default();
        let mut lp_user_time: FILETIME = Default::default();
        winapi_bool!(GetProcessTimes(
            information.hProcess,
            &mut lp_creation_time,
            &mut lp_exit_time,
            &mut lp_kernel_time,
            &mut lp_user_time,
        ));

        status.time_used =
            (lp_exit_time.dwLowDateTime - lp_creation_time.dwLowDateTime) as u64 / 10000;
        status.cpu_time_used =
            (lp_kernel_time.dwLowDateTime + lp_user_time.dwLowDateTime) as u64 / 10000;

        return Ok(status);
    }

    unsafe fn limit(&mut self, information: &PROCESS_INFORMATION) -> Result<Status> {
        let job = match CreateJobObjectA(None, None) {
            Ok(resp) => resp,
            Err(_) => {
                return Err(WinError(String::from(file!()), line!(), unsafe {
                    GetLastError()
                }));
            }
        };

        let mut limit: JOBOBJECT_BASIC_LIMIT_INFORMATION = Default::default();
        limit.LimitFlags = JOB_OBJECT_LIMIT_PRIORITY_CLASS;
        limit.PriorityClass = IDLE_PRIORITY_CLASS.0;

        // 系统定期检查以确定与作业关联的每个进程是否累积了比设置限制更多的用户模式时间。 如果已终止，则终止进程。
        // cpu 时间限制，此限制不会实时结束进程（需要等到下次检查？）
        if let Some(l) = self.cpu_time_limit {
            limit.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_TIME;
            limit.PerProcessUserTimeLimit = l as i64 * 10000;
            limit.PerJobUserTimeLimit = l as i64 * 10000;
        }

        // 内存限制
        if let Some(l) = self.memory_limit {
            // 与 cpu 时间限制类似，此限制并不能保证可用性
            winapi_bool!(SetProcessWorkingSetSize(
                information.hProcess,
                1,
                l as usize * 1024
            ))
        }

        // 设置 job 限制
        winapi_bool!(SetInformationJobObject(
            job,
            JobObjectBasicLimitInformation,
            &limit as *const _ as *const c_void,
            size_of::<JOBOBJECT_BASIC_LIMIT_INFORMATION>() as u32,
        ));

        // 将 job 附加到进程
        winapi_bool!(AssignProcessToJobObject(job, information.hProcess));

        Ok(Default::default())
    }
}
