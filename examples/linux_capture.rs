#[cfg(target_os = "linux")]
mod imp {
    use rustix::event::epoll::{self, CreateFlags, EventData, EventFlags, EventVec};
    use rustix::fd::{AsFd, AsRawFd, OwnedFd};
    use rustix::fs::{Mode, OFlags, open};
    use rustix::io::Errno;
    use rustix::pipe::{PipeFlags, SpliceFlags, pipe_with, splice};
    use rustix::process::{Pid, Signal, WaitOptions, kill_process, waitpid};
    use rustix::time::{ClockId, clock_gettime};
    use std::ffi::CString;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    const BUF_SIZE: usize = 65536;
    const MONITOR_INTERVAL: Duration = Duration::from_millis(100);

    // ======================== 配置 ========================
    const EXECUTABLE: &str = "/bin/dd";
    const ARGS: &[&str] = &["if=/dev/urandom", "bs=1M", "count=1024", "of=/dev/stdout"];
    const STDOUT_FILE: &str = "captured_stdout.bin";
    const STDERR_FILE: &str = "captured_stderr.bin";
    const STDOUT_LIMIT: usize = 10 * 1024 * 1024; // 10 MB
    const STDERR_LIMIT: usize = 5 * 1024 * 1024; // 5 MB
    // =============================================================

    struct StreamCtx {
        pipe_read: OwnedFd,
        file: OwnedFd,
        label: &'static str,
        bytes: Arc<AtomicUsize>,
        limit: usize,
    }

    impl StreamCtx {
        /// 将管道数据 splice 到文件。成功返回 Ok(n)（n > 0），
        /// EOF 返回 Ok(0)，会阻塞时返回 Err(AGAIN)，其他错误返回 Err(_)。
        fn drain(&self) -> Result<usize, Errno> {
            match splice(
                self.pipe_read.as_fd(),
                None,
                self.file.as_fd(),
                None,
                BUF_SIZE,
                SpliceFlags::MOVE | SpliceFlags::MORE | SpliceFlags::NONBLOCK,
            ) {
                Ok(n) => {
                    if n > 0 {
                        self.bytes.fetch_add(n, Ordering::Relaxed);
                    }
                    Ok(n)
                }
                Err(e) => Err(e),
            }
        }

        fn is_over_limit(&self) -> bool {
            self.bytes.load(Ordering::Relaxed) >= self.limit
        }
    }

    pub fn run() {
        println!("=== 带限制的输出捕获 ===");
        println!("可执行文件: {}", EXECUTABLE);
        println!("参数: {:?}", ARGS);
        println!("stdout: {} (限制: {} 字节)", STDOUT_FILE, STDOUT_LIMIT);
        println!("stderr: {} (限制: {} 字节)", STDERR_FILE, STDERR_LIMIT);
        println!();

        // 打开输出文件
        let out_file = open(
            STDOUT_FILE,
            OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC,
            Mode::from_raw_mode(0o644),
        )
        .expect("打开 stdout 文件失败");

        let err_file = open(
            STDERR_FILE,
            OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC,
            Mode::from_raw_mode(0o644),
        )
        .expect("打开 stderr 文件失败");

        // 创建非阻塞管道: (读端, 写端)
        let (stdout_read, stdout_write) =
            pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK).expect("创建 stdout 管道失败");
        let (stderr_read, stderr_write) =
            pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK).expect("创建 stderr 管道失败");

        // 通过 libc 进行 fork + exec
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            panic!("fork 失败");
        }

        if pid == 0 {
            // ---- 子进程 ----
            unsafe {
                libc::fcntl(stdout_write.as_raw_fd(), libc::F_SETFL, 0);
                libc::fcntl(stderr_write.as_raw_fd(), libc::F_SETFL, 0);
                libc::dup2(stdout_write.as_raw_fd(), libc::STDOUT_FILENO);
                libc::dup2(stderr_write.as_raw_fd(), libc::STDERR_FILENO);
            }
            drop(stdout_read);
            drop(stdout_write);
            drop(stderr_read);
            drop(stderr_write);
            drop(out_file);
            drop(err_file);

            // 构建 argv: [executable, args..., NULL]
            let exe_cstr = CString::new(EXECUTABLE).unwrap();
            let mut c_args: Vec<CString> = vec![exe_cstr.clone()];
            for a in ARGS {
                c_args.push(CString::new(*a).unwrap());
            }
            let c_arg_ptrs: Vec<*const libc::c_char> = c_args
                .iter()
                .map(|a| a.as_ptr())
                .chain(std::iter::once(std::ptr::null()))
                .collect();

            unsafe {
                libc::execvp(exe_cstr.as_ptr(), c_arg_ptrs.as_ptr());
                libc::perror(c"execvp".as_ptr());
                libc::_exit(127);
            }
        }

        // ---- 父进程 ----
        drop(stdout_write);
        drop(stderr_write);

        let stdout_bytes = Arc::new(AtomicUsize::new(0));
        let stderr_bytes = Arc::new(AtomicUsize::new(0));

        let stdout_ctx = StreamCtx {
            pipe_read: stdout_read,
            file: out_file,
            label: "stdout",
            bytes: stdout_bytes.clone(),
            limit: STDOUT_LIMIT,
        };
        let stderr_ctx = StreamCtx {
            pipe_read: stderr_read,
            file: err_file,
            label: "stderr",
            bytes: stderr_bytes.clone(),
            limit: STDERR_LIMIT,
        };

        // 创建 epoll
        let epfd = epoll::create(CreateFlags::CLOEXEC).expect("epoll_create 失败");

        epoll::add(
            &epfd,
            stdout_ctx.pipe_read.as_fd(),
            EventData::new_u64(0),
            EventFlags::IN | EventFlags::ET,
        )
        .expect("epoll 添加 stdout 失败");

        epoll::add(
            &epfd,
            stderr_ctx.pipe_read.as_fd(),
            EventData::new_u64(1),
            EventFlags::IN | EventFlags::ET,
        )
        .expect("epoll 添加 stderr 失败");

        let streams: [&StreamCtx; 2] = [&stdout_ctx, &stderr_ctx];
        let mut active_streams = 2u32;
        let mut last_report = clock_gettime(ClockId::Monotonic);
        let mut event_list = EventVec::with_capacity(2);
        let mut limit_exceeded = false;
        let mut exceeded_stream: Option<&str> = None;

        let child_pid = Pid::from_raw(pid).expect("无效的子进程 pid");

        while active_streams > 0 {
            epoll::wait(&epfd, &mut event_list, 100).expect("epoll_wait 失败");

            for event in &event_list {
                let idx = event.data.u64() as usize;
                let ctx = streams[idx];
                let flags = event.flags;

                if flags.contains(EventFlags::ERR) || flags.contains(EventFlags::HUP) {
                    while let Ok(1..) = ctx.drain() {}
                    let _ = epoll::delete(&epfd, ctx.pipe_read.as_fd());
                    active_streams -= 1;
                    continue;
                }

                if flags.contains(EventFlags::IN) {
                    loop {
                        match ctx.drain() {
                            Ok(1..) => {
                                // 每次成功 splice 后检查限制
                                if ctx.is_over_limit() && !limit_exceeded {
                                    limit_exceeded = true;
                                    exceeded_stream = Some(ctx.label);
                                    eprintln!(
                                        "\n⚠️  {} 超出限制 ({} 字节 >= {} 限制)，向 pid {} 发送 SIGKILL",
                                        ctx.label,
                                        ctx.bytes.load(Ordering::Relaxed),
                                        ctx.limit,
                                        pid
                                    );
                                    let _ = kill_process(child_pid, Signal::Kill);
                                }
                                continue;
                            }
                            Ok(0) => {
                                let _ = epoll::delete(&epfd, ctx.pipe_read.as_fd());
                                active_streams -= 1;
                                break;
                            }
                            Err(Errno::AGAIN) => break,
                            Err(_) => break,
                        }
                    }
                }
            }

            // 如果已终止子进程，在管道排空后退出循环
            if limit_exceeded && active_streams == 0 {
                break;
            }

            // 定期监控输出
            let now = clock_gettime(ClockId::Monotonic);
            let elapsed_ns = (now.tv_sec - last_report.tv_sec) as u64 * 1_000_000_000
                + (now.tv_nsec as u64).saturating_sub(last_report.tv_nsec as u64);
            if elapsed_ns >= MONITOR_INTERVAL.as_nanos() as u64 || active_streams == 0 {
                let out = stdout_bytes.load(Ordering::Relaxed);
                let err = stderr_bytes.load(Ordering::Relaxed);
                eprint!(
                    "\r[实时] stdout: {} / {} B | stderr: {} / {} B",
                    out, STDOUT_LIMIT, err, STDERR_LIMIT
                );
                last_report = now;
            }
        }

        eprintln!();

        // 回收子进程
        let wait_result = waitpid(Some(child_pid), WaitOptions::empty());
        let exit_info = match wait_result {
            Ok(Some(status)) => {
                if status.exited() {
                    format!("正常退出，退出码 {}", status.exit_status().unwrap_or(0))
                } else if status.signaled() {
                    format!(
                        "被信号 {} 终止",
                        status.terminating_signal().map_or(-1, |s| s as i32)
                    )
                } else {
                    "未知状态".to_string()
                }
            }
            Ok(None) => "子进程尚未终止".to_string(),
            Err(e) => format!("waitpid 错误: {:?}", e),
        };

        let out_total = stdout_bytes.load(Ordering::Relaxed);
        let err_total = stderr_bytes.load(Ordering::Relaxed);

        println!("\n=== 最终结果 ===");
        println!("子进程: {}", exit_info);
        println!("stdout: {} 字节 -> {}", out_total, STDOUT_FILE);
        println!("stderr: {} 字节 -> {}", err_total, STDERR_FILE);
        if limit_exceeded {
            println!(
                "⚠️  已终止: {} 超出限制 (写入 {} 字节，限制为 {})",
                exceeded_stream.unwrap_or("未知"),
                if exceeded_stream == Some("stdout") {
                    out_total
                } else {
                    err_total
                },
                if exceeded_stream == Some("stdout") {
                    STDOUT_LIMIT
                } else {
                    STDERR_LIMIT
                }
            );
        } else {
            println!("✅ 正常完成 (未超出限制)");
        }
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    imp::run();

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("此示例仅在 Linux 上运行。");
        eprintln!("Windows 请使用 windows_capture.rs。");
        std::process::exit(1);
    }
}
