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
    
    // ======================== Configuration ========================
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
        /// Splice pipe → file. Returns Ok(n) with n > 0 on success,
        /// Ok(0) on EOF, Err(AGAIN) if would block, Err(_) on error.
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
        println!("=== Capture with Limit ===");
        println!("Executable: {}", EXECUTABLE);
        println!("Args: {:?}", ARGS);
        println!("stdout: {} (limit: {} bytes)", STDOUT_FILE, STDOUT_LIMIT);
        println!("stderr: {} (limit: {} bytes)", STDERR_FILE, STDERR_LIMIT);
        println!();
    
        // Open output files
        let out_file = open(
            STDOUT_FILE,
            OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC,
            Mode::from_raw_mode(0o644),
        )
        .expect("open stdout file");
    
        let err_file = open(
            STDERR_FILE,
            OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC,
            Mode::from_raw_mode(0o644),
        )
        .expect("open stderr file");
    
        // Create non-blocking pipes: (read_end, write_end)
        let (stdout_read, stdout_write) =
            pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK).expect("pipe2 stdout");
        let (stderr_read, stderr_write) =
            pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK).expect("pipe2 stderr");
    
        // fork + exec via libc
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            panic!("fork failed");
        }
    
        if pid == 0 {
            // ---- Child process ----
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
    
            // Build argv: [executable, args..., NULL]
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
                libc::perror(b"execvp\0".as_ptr() as *const _);
                libc::_exit(127);
            }
        }
    
        // ---- Parent process ----
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
    
        // Create epoll
        let epfd = epoll::create(CreateFlags::CLOEXEC).expect("epoll_create");
    
        epoll::add(
            &epfd,
            stdout_ctx.pipe_read.as_fd(),
            EventData::new_u64(0),
            EventFlags::IN | EventFlags::ET,
        )
        .expect("epoll add stdout");
    
        epoll::add(
            &epfd,
            stderr_ctx.pipe_read.as_fd(),
            EventData::new_u64(1),
            EventFlags::IN | EventFlags::ET,
        )
        .expect("epoll add stderr");
    
        let streams: [&StreamCtx; 2] = [&stdout_ctx, &stderr_ctx];
        let mut active_streams = 2u32;
        let mut last_report = clock_gettime(ClockId::Monotonic);
        let mut event_list = EventVec::with_capacity(2);
        let mut limit_exceeded = false;
        let mut exceeded_stream: Option<&str> = None;
    
        let child_pid = Pid::from_raw(pid).expect("invalid child pid");
    
        while active_streams > 0 {
            epoll::wait(&epfd, &mut event_list, 100).expect("epoll_wait");
    
            for event in &event_list {
                let idx = event.data.u64() as usize;
                let ctx = streams[idx];
                let flags = event.flags;
    
                if flags.contains(EventFlags::ERR) || flags.contains(EventFlags::HUP) {
                    loop {
                        match ctx.drain() {
                            Ok(1..) => continue,
                            _ => break,
                        }
                    }
                    let _ = epoll::delete(&epfd, ctx.pipe_read.as_fd());
                    active_streams -= 1;
                    continue;
                }
    
                if flags.contains(EventFlags::IN) {
                    loop {
                        match ctx.drain() {
                            Ok(1..) => {
                                // Check limit after each successful splice
                                if ctx.is_over_limit() && !limit_exceeded {
                                    limit_exceeded = true;
                                    exceeded_stream = Some(ctx.label);
                                    eprintln!(
                                        "\n⚠️  {} limit exceeded ({} bytes >= {} limit), sending SIGKILL to pid {}",
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
    
            // If we killed the child, break out once pipes are drained
            if limit_exceeded && active_streams == 0 {
                break;
            }
    
            // Periodic monitoring
            let now = clock_gettime(ClockId::Monotonic);
            let elapsed_ns = (now.tv_sec - last_report.tv_sec) as u64 * 1_000_000_000
                + (now.tv_nsec as u64).saturating_sub(last_report.tv_nsec as u64);
            if elapsed_ns >= MONITOR_INTERVAL.as_nanos() as u64 || active_streams == 0 {
                let out = stdout_bytes.load(Ordering::Relaxed);
                let err = stderr_bytes.load(Ordering::Relaxed);
                eprint!(
                    "\r[realtime] stdout: {} / {} B | stderr: {} / {} B",
                    out, STDOUT_LIMIT, err, STDERR_LIMIT
                );
                last_report = now;
            }
        }
    
        eprintln!();
    
        // Reap child
        let wait_result = waitpid(Some(child_pid), WaitOptions::empty());
        let exit_info = match wait_result {
            Ok(Some(status)) => {
                if status.exited() {
                    format!("exited with code {}", status.exit_status().unwrap_or(0))
                } else if status.signaled() {
                    format!(
                        "killed by signal {}",
                        status.terminating_signal().map_or(-1, |s| s as i32)
                    )
                } else {
                    "unknown status".to_string()
                }
            }
            Ok(None) => "child not yet terminated".to_string(),
            Err(e) => format!("waitpid error: {:?}", e),
        };
    
        let out_total = stdout_bytes.load(Ordering::Relaxed);
        let err_total = stderr_bytes.load(Ordering::Relaxed);
    
        println!("\n=== Final ===");
        println!("Child: {}", exit_info);
        println!("stdout: {} bytes -> {}", out_total, STDOUT_FILE);
        println!("stderr: {} bytes -> {}", err_total, STDERR_FILE);
        if limit_exceeded {
            println!(
                "⚠️  Terminated: {} exceeded limit (wrote {} bytes, limit was {})",
                exceeded_stream.unwrap_or("unknown"),
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
            println!("✅ Completed normally (no limit exceeded)");
        }
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    imp::run();

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("This example only runs on Linux.");
        eprintln!("For Windows, use windows_capture.rs instead.");
        std::process::exit(1);
    }
}
