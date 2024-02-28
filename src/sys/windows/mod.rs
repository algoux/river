use std::ffi::c_void;
use std::mem::size_of;
use windows::core::{PCSTR, PSTR};
use windows::Win32::Foundation::{GetLastError, WAIT_FAILED, WAIT_TIMEOUT};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectA, JobObjectBasicLimitInformation,
    SetInformationJobObject, JOBOBJECT_BASIC_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_PRIORITY_CLASS,
    JOB_OBJECT_LIMIT_PROCESS_TIME,
};
use windows::Win32::System::Threading::{
    CreateProcessA, ResumeThread, SetProcessWorkingSetSize, TerminateProcess, WaitForSingleObject,
    CREATE_SUSPENDED, IDLE_PRIORITY_CLASS, PROCESS_INFORMATION, STARTUPINFOA,
};

use crate::error::Error::{WinError, E};
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
    result: Option<String>,
}

impl Sandbox {
    unsafe fn set_limit(&mut self, information: &PROCESS_INFORMATION) -> crate::error::Result<()> {
        // 创建 JOB
        let job = match CreateJobObjectA(None, None) {
            Ok(j) => j,
            Err(e) => return Err(WinError(file!().to_string(), line!(), e)),
        };

        let mut limit: JOBOBJECT_BASIC_LIMIT_INFORMATION = Default::default();
        limit.LimitFlags = JOB_OBJECT_LIMIT_PRIORITY_CLASS;
        limit.PriorityClass = IDLE_PRIORITY_CLASS.0;

        // 内存限制
        if let Some(l) = self.memory_limit {
            // 与 cpu 时间限制类似，此限制并不能保证可用性
            if let Err(e) = SetProcessWorkingSetSize(information.hProcess, 1, l as usize * 1024) {
                return Err(WinError(file!().to_string(), line!(), e));
            }
        }

        // 系统定期检查以确定与作业关联的每个进程是否累积了比设置限制更多的用户模式时间。 如果已终止，则终止进程。
        // cpu 时间限制，此限制不会实时结束进程（需要等到下次检查？）
        if let Some(l) = self.cpu_time_limit {
            limit.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_TIME;
            limit.PerProcessUserTimeLimit = l as i64 * 10000;
            limit.PerJobUserTimeLimit = l as i64 * 10000;
        }

        // 设置 job 限制
        if let Err(e) = SetInformationJobObject(
            job,
            JobObjectBasicLimitInformation,
            &limit as *const _ as *const c_void,
            size_of::<JOBOBJECT_BASIC_LIMIT_INFORMATION>() as u32,
        ) {
            return Err(WinError(file!().to_string(), line!(), e));
        }
        // 将 job 附加到进程
        if let Err(e) = AssignProcessToJobObject(job, information.hProcess) {
            return Err(WinError(file!().to_string(), line!(), e));
        }
        Ok(())
    }

    unsafe fn wait_it(&mut self, information: &PROCESS_INFORMATION) -> crate::error::Result<()> {
        let timeout = if let Some(t) = self.time_limit {
            t
        } else {
            // 如果 dwMilliseconds 为 INFINITE，则仅当发出对象信号时，该函数才会返回
            0xFFFFFFFF
        };
        let wait_ret = WaitForSingleObject(information.hProcess, timeout);
        if wait_ret == WAIT_TIMEOUT {
            // 超时中断进程
            if let Err(e) = TerminateProcess(information.hProcess, 0) {
                return Err(WinError(file!().to_string(), line!(), e));
            }
            // 此处不检查返回值
            WaitForSingleObject(information.hProcess, 0xFFFFFFFF);
        } else if wait_ret == WAIT_FAILED {
            return Err(E(file!().to_string(), line!(), "WAIT_FAILED".to_string()));
        }
        Ok(())
    }
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
            result: opts.result,
        }
    }

    unsafe fn run(&mut self) -> crate::error::Result<()> {
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

        // 创建进程
        if let Err(e) = CreateProcessA(
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
        ) {
            return Err(WinError(String::from(file!()), line!(), e));
        }

        self.set_limit(&information)?;

        // 唤醒被暂停的进程
        if ResumeThread(information.hThread) != 1 {
            return Err(E(
                String::from(file!()),
                line!(),
                "唤醒进程失败".to_string(),
            ));
        }

        self.wait_it(&information)
    }
}

#[cfg(test)]
mod tests {
    use crate::error::Result;
    use crate::sys::windows::Sandbox;
    use crate::sys::SandboxImpl;
    use crate::Opts;

    #[test]
    fn hello() {
        assert_eq!(1 + 1, 2);
    }

    /**
     * 启动记事本
     */
    #[test]
    fn notepad() -> Result<()> {
        let mut opts: Opts = Opts::default();
        opts.command.push("C:/Windows/notepad.exe".to_string());
        unsafe { Sandbox::with_opts(opts).run() }
    }

    /**
     * 执行不存在的可执行文件
     */
    #[test]
    #[should_panic]
    fn not_found() {
        let mut opts: Opts = Opts::default();
        opts.command.push("Z:/not-found.exe".to_string());
        unsafe {
            Sandbox::with_opts(opts).run().unwrap();
        }
    }

    /**
     * 测试时间限制
     */
    #[test]
    fn time_limit() -> Result<()> {
        let mut opts: Opts = Opts::default();
        opts.command.push("C:/Windows/notepad.exe".to_string());
        opts.time_limit = Some(1000);
        unsafe { Sandbox::with_opts(opts).run() }
    }
}
