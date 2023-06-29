use crate::error::Result;

use crate::error::Error::WinError;

#[cfg(target_os = "windows")]
use windows::{
    core::{PCSTR, PSTR},
    Win32::Foundation::GetLastError,
    Win32::System::Threading,
    Win32::System::Threading::{CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOA},
};

pub struct Sandbox {
    inner_args: Vec<String>,
}

#[cfg(target_os = "windows")]
impl Sandbox {
    pub fn new(args: Vec<String>) -> Self {
        Sandbox { inner_args: args }
    }

    pub fn run(&mut self) -> Result<()> {
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
            return Err(WinError(unsafe { GetLastError() }));
        }

        unsafe {
            // 唤醒被暂停的进程
            Threading::ResumeThread(information.hThread);
        }
        Ok(())
    }
}
