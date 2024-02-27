use windows::core::{PCSTR, PSTR};
use windows::Win32::Foundation::GetLastError;
use windows::Win32::System::Threading::{
    CreateProcessA, ResumeThread, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOA,
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

        // 唤醒被暂停的进程
        if ResumeThread(information.hThread) != 1 {
            return Err(E(
                String::from(file!()),
                line!(),
                "唤醒进程失败".to_string(),
            ));
        }

        Ok(())
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
        unsafe { Sandbox::with_opts(opts).run().unwrap(); }
    }
}
