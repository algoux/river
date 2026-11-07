//! Windows equivalent of linux_capture.rs
//!
//! Captures stdout/stderr of a child process with size limits,
//! using dedicated reader threads + anonymous pipes for reliable capture.
//!
//! Key differences from the Linux version:
//! - No splice (zero-copy): data goes through user-space buffers
//! - Reader threads replace epoll (anonymous pipes don't support IOCP)
//! - Anonymous pipes (CreatePipe) replace non-blocking anonymous pipes
//! - TerminateProcess replaces SIGKILL
//! - CreateProcessW replaces fork+exec

#[cfg(windows)]
mod imp {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, ReadFile, WriteFile, CREATE_ALWAYS, FILE_GENERIC_WRITE, FILE_SHARE_READ,
    };
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, GetExitCodeProcess, TerminateProcess, WaitForSingleObject,
        PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
    };

    // ======================== Configuration ========================
    const EXECUTABLE: &str = "cmd.exe";
    const ARGS: &[&str] = &["/C", "dir /s C:\\Windows\\System32"];
    const STDOUT_FILE: &str = "captured_stdout.bin";
    const STDERR_FILE: &str = "captured_stderr.bin";
    const STDOUT_LIMIT: usize = 10 * 1024 * 1024; // 10 MB
    const STDERR_LIMIT: usize = 5 * 1024 * 1024; // 5 MB
    const BUF_SIZE: u32 = 65536; // 64 KB per read
    const MONITOR_INTERVAL: Duration = Duration::from_millis(100);
    // ===============================================================

    /// Convert a Rust string to a null-terminated wide string (UTF-16).
    fn to_wide(s: &str) -> Vec<u16> {
        OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// Build a mutable wide-string command line for CreateProcessW.
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

    /// Reader thread: reads from pipe handle, writes to file handle, enforces limit.
    /// Takes handles as usize to satisfy Send bound; converts back inside.
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
                // Pipe closed or error → EOF
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

            // Check limit
            if bytes_counter.load(Ordering::Relaxed) >= limit {
                if !kill_flag.swap(true, Ordering::SeqCst) {
                    eprintln!(
                        "\n⚠️  {} limit exceeded ({} bytes >= {} limit), terminating child",
                        label,
                        bytes_counter.load(Ordering::Relaxed),
                        limit,
                    );
                    unsafe { TerminateProcess(child_process, 1) };
                }
                // Drain remaining pipe data up to limit (already at limit, skip)
                break;
            }
        }

        unsafe { CloseHandle(pipe_read) };
        total_written
    }

    pub fn run() {
        println!("=== Windows Capture with Limit ===");
        println!("Executable: {}", EXECUTABLE);
        println!("Args: {:?}", ARGS);
        println!("stdout: {} (limit: {} bytes)", STDOUT_FILE, STDOUT_LIMIT);
        println!("stderr: {} (limit: {} bytes)", STDERR_FILE, STDERR_LIMIT);
        println!();

        unsafe {
            // ---- Create output files ----
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
                "CreateFileW stdout failed"
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
                "CreateFileW stderr failed"
            );

            // ---- Create anonymous pipes (inheritable for child) ----
            let mut sa: windows_sys::Win32::Security::SECURITY_ATTRIBUTES = core::mem::zeroed();
            sa.nLength = size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>() as u32;
            sa.bInheritHandle = 1; // TRUE — critical for child to inherit pipe handles
            sa.lpSecurityDescriptor = ptr::null_mut();

            let mut stdout_read: HANDLE = INVALID_HANDLE_VALUE;
            let mut stdout_write: HANDLE = INVALID_HANDLE_VALUE;
            let mut stderr_read: HANDLE = INVALID_HANDLE_VALUE;
            let mut stderr_write: HANDLE = INVALID_HANDLE_VALUE;

            assert!(
                CreatePipe(&mut stdout_read, &mut stdout_write, &sa, 0) != 0,
                "CreatePipe stdout failed"
            );
            assert!(
                CreatePipe(&mut stderr_read, &mut stderr_write, &sa, 0) != 0,
                "CreatePipe stderr failed"
            );

            // ---- Spawn child process ----
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
            assert!(ok != 0, "CreateProcessW failed");

            // Close write ends in parent (child owns them now)
            CloseHandle(stdout_write);
            CloseHandle(stderr_write);
            CloseHandle(pi.hThread);

            let child_process = pi.hProcess;

            // ---- Shared state ----
            let stdout_bytes = Arc::new(AtomicUsize::new(0));
            let stderr_bytes = Arc::new(AtomicUsize::new(0));
            let kill_flag = Arc::new(AtomicBool::new(false));

            // ---- Spawn reader threads ----
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
                    .expect("spawn stdout reader")
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
                    .expect("spawn stderr reader")
            };

            // ---- Monitoring loop ----
            let mut last_report = Instant::now();

            loop {
                let wait_result = WaitForSingleObject(child_process, MONITOR_INTERVAL.as_millis() as u32);
                const WAIT_OBJECT_0: u32 = 0;
                let child_exited = wait_result == WAIT_OBJECT_0;

                // Periodic monitoring
                let now = Instant::now();
                if now.duration_since(last_report) >= MONITOR_INTERVAL || child_exited {
                    let out = stdout_bytes.load(Ordering::Relaxed);
                    let err = stderr_bytes.load(Ordering::Relaxed);
                    eprint!(
                        "\r[realtime] stdout: {} / {} B | stderr: {} / {} B",
                        out, STDOUT_LIMIT, err, STDERR_LIMIT,
                    );
                    last_report = now;
                }

                if child_exited {
                    break;
                }
            }

            eprintln!();

            // Wait for reader threads to finish draining
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();

            // Get exit code
            let mut exit_code: u32 = 0;
            GetExitCodeProcess(child_process, &mut exit_code);
            CloseHandle(child_process);
            CloseHandle(stdout_file);
            CloseHandle(stderr_file);

            let out_total = stdout_bytes.load(Ordering::Relaxed);
            let err_total = stderr_bytes.load(Ordering::Relaxed);

            println!("\n=== Final ===");
            println!("Child: exited with code {}", exit_code);
            println!("stdout: {} bytes -> {}", out_total, STDOUT_FILE);
            println!("stderr: {} bytes -> {}", err_total, STDERR_FILE);
            if kill_flag.load(Ordering::Relaxed) {
                println!(
                    "⚠️  Terminated: output exceeded limit (stdout: {} / {}, stderr: {} / {})",
                    out_total, STDOUT_LIMIT, err_total, STDERR_LIMIT,
                );
            } else {
                println!("✅ Completed normally (no limit exceeded)");
            }
        }
    }
}

fn main() {
    #[cfg(windows)]
    imp::run();

    #[cfg(not(windows))]
    {
        eprintln!("This example only runs on Windows.");
        eprintln!("For Linux, use linux_capture.rs instead.");
        std::process::exit(1);
    }
}
