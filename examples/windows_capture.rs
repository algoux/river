//! linux_capture.rs 的 Windows 对等实现
//!
//! 使用专用读取线程 + 匿名管道可靠地捕获子进程的 stdout/stderr，并支持大小限制。
//!
//! 与 Linux 版本的主要区别：
//! - 无 splice（零拷贝）：数据经过用户空间缓冲区中转
//! - 用读取线程替代 epoll（匿名管道不支持 IOCP）
//! - 用 CreatePipe 匿名管道替代非阻塞匿名管道
//! - 用 TerminateProcess 替代 SIGKILL
//! - 用 CreateProcessW 替代 fork+exec

#[cfg(windows)]
mod imp {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_ALWAYS, CreateFileW, FILE_GENERIC_WRITE, FILE_SHARE_READ, ReadFile, WriteFile,
    };
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, GetExitCodeProcess, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
        STARTUPINFOW, TerminateProcess, WaitForSingleObject,
    };

    // ======================== 配置 ========================
    const EXECUTABLE: &str = "cmd.exe";
    const ARGS: &[&str] = &["/C", "dir /s C:\\Windows\\System32"];
    const STDOUT_FILE: &str = "captured_stdout.bin";
    const STDERR_FILE: &str = "captured_stderr.bin";
    const STDOUT_LIMIT: usize = 10 * 1024 * 1024; // 10 MB
    const STDERR_LIMIT: usize = 5 * 1024 * 1024; // 5 MB
    const BUF_SIZE: u32 = 65536; // 每次读取 64 KB
    const MONITOR_INTERVAL: Duration = Duration::from_millis(100);
    // ===============================================================

    /// 将 Rust 字符串转换为以 null 结尾的宽字符串 (UTF-16)。
    fn to_wide(s: &str) -> Vec<u16> {
        OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// 为 CreateProcessW 构建可变宽字符串命令行。
    fn build_command_line(exe: &str, args: &[&str]) -> Vec<u16> {
        let mut cmd = String::new();
        cmd.push('"');
        cmd.push_str(exe);
        cmd.push('"');
        for arg in args {
            cmd.push(' ');
            if arg.contains(' ') || arg.contains('"') {
                cmd.push('"');
                cmd.push_str(&arg.replace('"', "\\\""));
                cmd.push('"');
            } else {
                cmd.push_str(arg);
            }
        }
        to_wide(&cmd)
    }

    /// 读取线程：从管道句柄读取数据，写入文件句柄，并执行大小限制检查。
    /// 句柄以 usize 传入以满足 Send 约束，在函数内部转换回 HANDLE。
    unsafe fn reader_thread(
        pipe_read_raw: usize,
        file_write_raw: usize,
        label: &'static str,
        bytes_counter: Arc<AtomicUsize>,
        limit: usize,
        kill_flag: Arc<AtomicBool>,
        child_process_raw: usize,
    ) -> usize {
        let pipe_read = pipe_read_raw as HANDLE;
        let file_write = file_write_raw as HANDLE;
        let child_process = child_process_raw as HANDLE;
        let mut buf = vec![0u8; BUF_SIZE as usize];
        let mut total_written: usize = 0;

        loop {
            let mut bytes_read: u32 = 0;
            let ok = unsafe {
                ReadFile(
                    pipe_read,
                    buf.as_mut_ptr(),
                    BUF_SIZE,
                    &mut bytes_read,
                    ptr::null_mut(),
                )
            };

            if ok == 0 || bytes_read == 0 {
                // 管道关闭或出错 → EOF
                break;
            }

            let current = bytes_counter.load(Ordering::Relaxed);
            let remaining = limit.saturating_sub(current);
            let to_write = (bytes_read as usize).min(remaining);

            if to_write > 0 {
                let mut written: u32 = 0;
                unsafe {
                    WriteFile(
                        file_write,
                        buf[..to_write].as_ptr(),
                        to_write as u32,
                        &mut written,
                        ptr::null_mut(),
                    );
                }
                total_written += written as usize;
                bytes_counter.fetch_add(written as usize, Ordering::Relaxed);
            }

            // 检查是否超出限制
            if bytes_counter.load(Ordering::Relaxed) >= limit {
                if !kill_flag.swap(true, Ordering::SeqCst) {
                    eprintln!(
                        "\n⚠️  {} 超出限制 ({} 字节 >= {} 限制)，正在终止子进程",
                        label,
                        bytes_counter.load(Ordering::Relaxed),
                        limit,
                    );
                    unsafe { TerminateProcess(child_process, 1) };
                }
                // 已达限制，排空管道剩余数据后退出
                break;
            }
        }

        unsafe { CloseHandle(pipe_read) };
        total_written
    }

    pub fn run() {
        println!("=== Windows 带限制的输出捕获 ===");
        println!("可执行文件: {}", EXECUTABLE);
        println!("参数: {:?}", ARGS);
        println!("stdout: {} (限制: {} 字节)", STDOUT_FILE, STDOUT_LIMIT);
        println!("stderr: {} (限制: {} 字节)", STDERR_FILE, STDERR_LIMIT);
        println!();

        unsafe {
            // ---- 创建输出文件 ----
            let stdout_file_wide = to_wide(STDOUT_FILE);
            let stderr_file_wide = to_wide(STDERR_FILE);

            let stdout_file = CreateFileW(
                stdout_file_wide.as_ptr(),
                FILE_GENERIC_WRITE,
                FILE_SHARE_READ,
                ptr::null(),
                CREATE_ALWAYS,
                0,
                INVALID_HANDLE_VALUE,
            );
            assert!(
                stdout_file != INVALID_HANDLE_VALUE,
                "CreateFileW stdout 失败"
            );

            let stderr_file = CreateFileW(
                stderr_file_wide.as_ptr(),
                FILE_GENERIC_WRITE,
                FILE_SHARE_READ,
                ptr::null(),
                CREATE_ALWAYS,
                0,
                INVALID_HANDLE_VALUE,
            );
            assert!(
                stderr_file != INVALID_HANDLE_VALUE,
                "CreateFileW stderr 失败"
            );

            // ---- 创建匿名管道（可继承，供子进程使用）----
            let mut sa: windows_sys::Win32::Security::SECURITY_ATTRIBUTES = core::mem::zeroed();
            sa.nLength = size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>() as u32;
            sa.bInheritHandle = 1; // TRUE — 子进程必须能继承管道句柄
            sa.lpSecurityDescriptor = ptr::null_mut();

            let mut stdout_read: HANDLE = INVALID_HANDLE_VALUE;
            let mut stdout_write: HANDLE = INVALID_HANDLE_VALUE;
            let mut stderr_read: HANDLE = INVALID_HANDLE_VALUE;
            let mut stderr_write: HANDLE = INVALID_HANDLE_VALUE;

            assert!(
                CreatePipe(&mut stdout_read, &mut stdout_write, &sa, 0) != 0,
                "CreatePipe stdout 失败"
            );
            assert!(
                CreatePipe(&mut stderr_read, &mut stderr_write, &sa, 0) != 0,
                "CreatePipe stderr 失败"
            );

            // ---- 启动子进程 ----
            let mut cmd_line = build_command_line(EXECUTABLE, ARGS);
            let mut si: STARTUPINFOW = core::mem::zeroed();
            si.cb = size_of::<STARTUPINFOW>() as u32;
            si.dwFlags = STARTF_USESTDHANDLES;
            si.hStdOutput = stdout_write;
            si.hStdError = stderr_write;
            si.hStdInput = INVALID_HANDLE_VALUE;

            let mut pi: PROCESS_INFORMATION = core::mem::zeroed();
            let ok = CreateProcessW(
                ptr::null(),
                cmd_line.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                1, // bInheritHandles = TRUE
                0,
                ptr::null(),
                ptr::null(),
                &si,
                &mut pi,
            );
            assert!(ok != 0, "CreateProcessW 失败");

            // 在父进程中关闭写端（子进程已持有）
            CloseHandle(stdout_write);
            CloseHandle(stderr_write);
            CloseHandle(pi.hThread);

            let child_process = pi.hProcess;

            // ---- 共享状态 ----
            let stdout_bytes = Arc::new(AtomicUsize::new(0));
            let stderr_bytes = Arc::new(AtomicUsize::new(0));
            let kill_flag = Arc::new(AtomicBool::new(false));

            // ---- 启动读取线程 ----
            let child_process_raw = child_process as usize;

            let stdout_reader = {
                let bytes = stdout_bytes.clone();
                let flag = kill_flag.clone();
                let pipe = stdout_read as usize;
                let file = stdout_file as usize;
                #[allow(unused_unsafe)]
                thread::Builder::new()
                    .name("stdout-reader".into())
                    .spawn(move || unsafe {
                        reader_thread(
                            pipe,
                            file,
                            "stdout",
                            bytes,
                            STDOUT_LIMIT,
                            flag,
                            child_process_raw,
                        )
                    })
                    .expect("启动 stdout 读取线程失败")
            };

            let stderr_reader = {
                let bytes = stderr_bytes.clone();
                let flag = kill_flag.clone();
                let pipe = stderr_read as usize;
                let file = stderr_file as usize;
                #[allow(unused_unsafe)]
                thread::Builder::new()
                    .name("stderr-reader".into())
                    .spawn(move || unsafe {
                        reader_thread(
                            pipe,
                            file,
                            "stderr",
                            bytes,
                            STDERR_LIMIT,
                            flag,
                            child_process_raw,
                        )
                    })
                    .expect("启动 stderr 读取线程失败")
            };

            // ---- 监控循环 ----
            let mut last_report = Instant::now();

            loop {
                let wait_result =
                    WaitForSingleObject(child_process, MONITOR_INTERVAL.as_millis() as u32);
                const WAIT_OBJECT_0: u32 = 0;
                let child_exited = wait_result == WAIT_OBJECT_0;

                // 定期输出监控信息
                let now = Instant::now();
                if now.duration_since(last_report) >= MONITOR_INTERVAL || child_exited {
                    let out = stdout_bytes.load(Ordering::Relaxed);
                    let err = stderr_bytes.load(Ordering::Relaxed);
                    eprint!(
                        "\r[实时] stdout: {} / {} B | stderr: {} / {} B",
                        out, STDOUT_LIMIT, err, STDERR_LIMIT,
                    );
                    last_report = now;
                }

                if child_exited {
                    break;
                }
            }

            eprintln!();

            // 等待读取线程完成数据排空
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();

            // 获取退出码
            let mut exit_code: u32 = 0;
            GetExitCodeProcess(child_process, &mut exit_code);
            CloseHandle(child_process);
            CloseHandle(stdout_file);
            CloseHandle(stderr_file);

            let out_total = stdout_bytes.load(Ordering::Relaxed);
            let err_total = stderr_bytes.load(Ordering::Relaxed);

            println!("\n=== 最终结果 ===");
            println!("子进程: 退出码 {}", exit_code);
            println!("stdout: {} 字节 -> {}", out_total, STDOUT_FILE);
            println!("stderr: {} 字节 -> {}", err_total, STDERR_FILE);
            if kill_flag.load(Ordering::Relaxed) {
                println!(
                    "⚠️  已终止: 输出超出限制 (stdout: {} / {}, stderr: {} / {})",
                    out_total, STDOUT_LIMIT, err_total, STDERR_LIMIT,
                );
            } else {
                println!("✅ 正常完成 (未超出限制)");
            }
        }
    }
}

fn main() {
    #[cfg(windows)]
    imp::run();

    #[cfg(not(windows))]
    {
        eprintln!("此示例仅在 Windows 上运行。");
        eprintln!("Linux 请使用 linux_capture.rs。");
        std::process::exit(1);
    }
}
