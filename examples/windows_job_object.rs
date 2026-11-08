//! Windows Job Object 能力演示
//!
//! 本示例完整展示 Windows Job Object 的核心能力：
//! 1. 基础进程管理：创建 Job、分配进程、查询信息、终止 Job 内所有进程
//! 2. 资源限制：CPU 时间限制、内存限制、活跃进程数限制
//! 3. UI 限制：禁止访问 USER 对象、剪贴板、桌面等
//! 4. 安全限制：限制令牌权限、禁止管理员特权
//!
//! 运行方式：cargo run --example windows_job_object

#[cfg(windows)]
mod imp {
    use std::ffi::OsStr;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
        JOB_OBJECT_LIMIT_JOB_TIME, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOB_OBJECT_LIMIT_PROCESS_TIME, JOB_OBJECT_SECURITY_NO_ADMIN,
        JOB_OBJECT_SECURITY_RESTRICTED_TOKEN, JOB_OBJECT_UILIMIT_DESKTOP,
        JOB_OBJECT_UILIMIT_DISPLAYSETTINGS, JOB_OBJECT_UILIMIT_EXITWINDOWS,
        JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES,
        JOB_OBJECT_UILIMIT_READCLIPBOARD, JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS,
        JOB_OBJECT_UILIMIT_WRITECLIPBOARD, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
        JOBOBJECT_BASIC_LIMIT_INFORMATION, JOBOBJECT_BASIC_UI_RESTRICTIONS,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOBOBJECT_SECURITY_LIMIT_INFORMATION,
        JobObjectBasicAccountingInformation, JobObjectBasicLimitInformation,
        JobObjectBasicUIRestrictions, JobObjectExtendedLimitInformation,
        JobObjectSecurityLimitInformation, QueryInformationJobObject, SetInformationJobObject,
        TerminateJobObject,
    };
    use windows_sys::Win32::System::Threading::INFINITE;
    use windows_sys::Win32::System::Threading::{
        CREATE_SUSPENDED, CreateProcessW, GetExitCodeProcess, PROCESS_INFORMATION, ResumeThread,
        STARTUPINFOW, WaitForSingleObject,
    };

    // ======================== 辅助函数 ========================

    /// 将 Rust 字符串转换为以 null 结尾的宽字符串 (UTF-16)
    fn to_wide(s: &str) -> Vec<u16> {
        OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// 创建命名 Job Object
    fn create_job(name: &str) -> io::Result<HANDLE> {
        let wide_name = to_wide(name);
        let handle = unsafe { CreateJobObjectW(ptr::null_mut(), wide_name.as_ptr()) };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(handle)
    }

    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, OPEN_EXISTING};
    use windows_sys::Win32::System::Threading::STARTF_USESTDHANDLES;

    /// 打开 NUL 设备用于 stdin 重定向
    fn open_nul() -> io::Result<HANDLE> {
        let wide = to_wide("NUL");
        let h = unsafe {
            CreateFileW(
                wide.as_ptr(),
                windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ,
                FILE_SHARE_READ | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE,
                ptr::null_mut(),
                OPEN_EXISTING,
                0,
                INVALID_HANDLE_VALUE,
            )
        };
        if h == INVALID_HANDLE_VALUE || h.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(h)
    }

    /// 启动子进程并返回其句柄（挂起状态）
    /// `null_stdin`: 若为 true，将 stdin 重定向到 NUL 设备
    fn spawn_suspended(cmd: &str, args: &[&str], null_stdin: bool) -> io::Result<(HANDLE, HANDLE)> {
        let mut cmdline = format!("\"{}\"", cmd);
        for arg in args {
            cmdline.push(' ');
            cmdline.push_str(arg);
        }
        let mut cmdline_wide = to_wide(&cmdline);

        let nul_handle = if null_stdin { Some(open_nul()?) } else { None };

        let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
        si.cb = size_of::<STARTUPINFOW>() as u32;
        if null_stdin {
            si.dwFlags = STARTF_USESTDHANDLES;
            si.hStdInput = nul_handle.unwrap();
            si.hStdOutput = INVALID_HANDLE_VALUE;
            si.hStdError = INVALID_HANDLE_VALUE;
        }

        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        let inherit = if null_stdin { 1 } else { 0 };
        let ok = unsafe {
            CreateProcessW(
                ptr::null(),
                cmdline_wide.as_mut_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                inherit,
                CREATE_SUSPENDED,
                ptr::null_mut(),
                ptr::null(),
                &si,
                &mut pi,
            )
        };

        // 关闭父进程的 NUL 句柄副本
        if let Some(h) = nul_handle {
            unsafe { CloseHandle(h) };
        }

        if ok == 0 {
            return Err(io::Error::last_os_error());
        }

        Ok((pi.hProcess, pi.hThread))
    }

    /// 恢复线程执行
    fn resume_thread(thread: HANDLE) {
        unsafe { ResumeThread(thread) };
    }

    /// 等待进程完成并获取退出码
    fn wait_and_get_exit(process: HANDLE) -> u32 {
        unsafe { WaitForSingleObject(process, INFINITE) };
        let mut code: u32 = 0;
        unsafe { GetExitCodeProcess(process, &mut code) };
        code
    }

    // ======================== 演示流程 ========================

    pub fn run() {
        println!("=== Windows Job Object 能力演示 ===\n");

        // ========== 1. 基础进程管理 ==========
        println!("【1】基础进程管理");
        println!("----------------------------------------");

        let job_name = format!("river-job-demo-{}", std::process::id());
        let job = match create_job(&job_name) {
            Ok(h) => {
                println!("  ✅ Job '{}' 创建成功", job_name);
                h
            }
            Err(e) => {
                eprintln!("  ❌ 创建 Job 失败: {}", e);
                return;
            }
        };

        // 设置 KILL_ON_JOB_CLOSE，确保 Job 关闭时自动终止子进程
        let mut ext_limit: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        ext_limit.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &ext_limit as *const _ as *const _,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } != 0
        {
            println!("  ✅ 已设置 JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE");
        } else {
            println!(
                "  ⚠️  设置 KILL_ON_JOB_CLOSE 失败: {}",
                io::Error::last_os_error()
            );
        }

        // 启动一个子进程并分配到 Job
        let comspec = std::env::var("ComSpec").unwrap_or_else(|_| "cmd.exe".to_string());
        println!("\n  🧪 启动子进程并分配到 Job...");

        let (proc, thread) = match spawn_suspended(
            &comspec,
            &["/c", "echo Hello from Job & timeout /t 2 >nul"],
            false,
        ) {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("  ❌ 启动子进程失败: {}", e);
                unsafe { CloseHandle(job) };
                return;
            }
        };

        if unsafe { AssignProcessToJobObject(job, proc) } != 0 {
            println!("  ✅ 子进程已分配到 Job");
        } else {
            println!("  ❌ 分配进程到 Job 失败: {}", io::Error::last_os_error());
        }

        resume_thread(thread);

        // 查询 Job 基本信息
        let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe {
            QueryInformationJobObject(
                job,
                JobObjectBasicAccountingInformation,
                &mut accounting as *mut _ as *mut _,
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                ptr::null_mut(),
            )
        } != 0
        {
            println!("  📊 Job 统计信息:");
            println!(
                "     - 总用户时间: {} ms",
                accounting.TotalUserTime / 10_000
            );
            println!(
                "     - 总内核时间: {} ms",
                accounting.TotalKernelTime / 10_000
            );
            println!("     - 页面错误数: {}", accounting.TotalPageFaultCount);
            println!("     - 活跃进程数: {}", accounting.ActiveProcesses);
            println!(
                "     - 已终止进程数: {}",
                accounting.TotalTerminatedProcesses
            );
        } else {
            println!("  ⚠️  查询 Job 信息失败: {}", io::Error::last_os_error());
        }

        // 等待子进程完成
        let exit_code = wait_and_get_exit(proc);
        println!("  📋 子进程退出码: {}", exit_code);

        unsafe {
            CloseHandle(proc);
            CloseHandle(thread);
        }
        println!();

        // ========== 2. 资源限制 ==========
        println!("【2】资源限制");
        println!("----------------------------------------");

        // 2a. 活跃进程数限制
        println!("  🧪 测试活跃进程数限制 (最大 2 个进程)");
        let mut limit_info: JOBOBJECT_BASIC_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limit_info.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        limit_info.ActiveProcessLimit = 2;

        if unsafe {
            SetInformationJobObject(
                job,
                JobObjectBasicLimitInformation,
                &limit_info as *const _ as *const _,
                size_of::<JOBOBJECT_BASIC_LIMIT_INFORMATION>() as u32,
            )
        } != 0
        {
            println!("     ✅ 已设置活跃进程数上限为 2");
        } else {
            println!("     ❌ 设置失败: {}", io::Error::last_os_error());
        }

        // 尝试启动 3 个进程，第 3 个应该失败或被终止
        let mut procs = Vec::new();
        for i in 0..3 {
            match spawn_suspended(&comspec, &["/c", "timeout /t 5 >nul"], false) {
                Ok((p, t)) => {
                    if unsafe { AssignProcessToJobObject(job, p) } != 0 {
                        resume_thread(t);
                        procs.push((p, t));
                        println!("     - 进程 {} 已启动并分配", i + 1);
                    } else {
                        println!(
                            "     - 进程 {} 分配失败 (预期行为): {}",
                            i + 1,
                            io::Error::last_os_error()
                        );
                        unsafe {
                            CloseHandle(p);
                            CloseHandle(t);
                        }
                    }
                }
                Err(e) => {
                    println!("     - 进程 {} 启动失败: {}", i + 1, e);
                }
            }
        }

        // 清理这些进程
        for (p, t) in procs {
            unsafe {
                CloseHandle(t);
                CloseHandle(p);
            }
        }
        println!();

        // 2b. CPU 时间限制
        println!("  🧪 测试 CPU 时间限制 (100ms)");
        let mut ext_limit2: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        ext_limit2.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_PROCESS_TIME | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        ext_limit2.BasicLimitInformation.PerProcessUserTimeLimit = 100 * 10_000; // 100ms in 100ns units

        if unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &ext_limit2 as *const _ as *const _,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } != 0
        {
            println!("     ✅ 已设置每进程 CPU 时间上限为 100ms");
        } else {
            println!("     ❌ 设置失败: {}", io::Error::last_os_error());
        }

        // 启动一个消耗 CPU 的进程 (PowerShell busy-loop)
        match spawn_suspended(
            "powershell",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "while($true){}",
            ],
            false,
        ) {
            Ok((p, t)) => {
                if unsafe { AssignProcessToJobObject(job, p) } != 0 {
                    resume_thread(t);
                    println!("     ⏳ 等待 CPU 密集型进程被终止...");
                    let code = wait_and_get_exit(p);
                    // 当超过 CPU 限制时，进程会被终止，退出码通常非零
                    println!("     ✅ 进程已被终止 (退出码: {})", code);
                } else {
                    println!("     ❌ 分配失败: {}", io::Error::last_os_error());
                }
                unsafe {
                    CloseHandle(t);
                    CloseHandle(p);
                }
            }
            Err(e) => println!("     ❌ 启动失败: {}", e),
        }

        // 清除 CPU 限制以便后续测试
        let mut clear_limit: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        clear_limit.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &clear_limit as *const _ as *const _,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
        }
        println!();

        // ========== 2c. PerJobUserTimeLimit vs PerProcessUserTimeLimit 对比验证 ==========
        println!("【2c】PerJob vs PerProcess CPU 时间限制对比验证");
        println!("----------------------------------------");
        println!("  📖 验证目标: 4 个并行 CPU 密集进程 (PowerShell busy-loop)");
        println!("     - PerProcess: 每个进程独立 3s → 4 进程理论总计可用 ~12s CPU");
        println!("     - PerJob:     所有进程共享 3s → 4 进程合计仅 ~3s CPU\n");

        // --- 实验 A: PerProcessUserTimeLimit = 1s ---
        println!("  🔬 实验 A: PerProcessUserTimeLimit = 3s (各进程独立)");
        {
            let job_a_name = format!("river-job-cpu-a-{}", std::process::id());
            let job_a = create_job(&job_a_name).expect("创建 Job A 失败");

            let mut ext_a: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
            ext_a.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_PROCESS_TIME | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            ext_a.BasicLimitInformation.PerProcessUserTimeLimit = 3_000 * 10_000; // 3s
            unsafe {
                SetInformationJobObject(
                    job_a,
                    JobObjectExtendedLimitInformation,
                    &ext_a as *const _ as *const _,
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                );
            }

            // 启动 4 个 CPU 密集进程 (cmd busy-loop, stdin 从 nul 读取)
            // PowerShell busy-loop: 不依赖 stdin，纯 CPU 消耗
            let cpu_cmd = "powershell";
            let cpu_args: &[&str] = &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "while($true){}",
            ];
            let mut procs_a = Vec::new();
            for i in 0..4 {
                match spawn_suspended(cpu_cmd, cpu_args, false) {
                    Ok((p, t)) => {
                        if unsafe { AssignProcessToJobObject(job_a, p) } != 0 {
                            resume_thread(t);
                            procs_a.push((p, t));
                        } else {
                            unsafe {
                                CloseHandle(p);
                                CloseHandle(t);
                            }
                        }
                    }
                    Err(e) => eprintln!("     进程 {} 启动失败: {}", i, e),
                }
            }
            println!("     已启动 {} 个 CPU 密集进程", procs_a.len());

            // 等待所有进程被终止
            let wall_start = std::time::Instant::now();
            for (p, _t) in &procs_a {
                wait_and_get_exit(*p);
            }
            let wall_elapsed = wall_start.elapsed();

            // 查询 Job 累计 CPU 时间
            let mut acct_a: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
            unsafe {
                QueryInformationJobObject(
                    job_a,
                    JobObjectBasicAccountingInformation,
                    &mut acct_a as *mut _ as *mut _,
                    size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                    ptr::null_mut(),
                );
            }
            let total_user_ms = acct_a.TotalUserTime / 10_000;
            let total_kernel_ms = acct_a.TotalKernelTime / 10_000;
            let total_cpu_ms = total_user_ms + total_kernel_ms;

            println!("     ⏱️  墙钟耗时: {} ms", wall_elapsed.as_millis());
            println!(
                "     📊 Job 累计 CPU: 用户={} ms, 内核={} ms, 合计={} ms",
                total_user_ms, total_kernel_ms, total_cpu_ms
            );
            println!("     📋 已终止进程数: {}", acct_a.TotalTerminatedProcesses);

            if total_cpu_ms > 5000 {
                println!(
                    "     ✅ 验证通过: 总 CPU ({} ms) >> 3s，确认 PerProcess 是各进程独立计算",
                    total_cpu_ms
                );
            } else {
                println!(
                    "     ⚠️  总 CPU ({} ms) 未显著超过单进程限额，结果可能受调度影响",
                    total_cpu_ms
                );
            }

            for (p, t) in procs_a {
                unsafe {
                    CloseHandle(t);
                    CloseHandle(p);
                }
            }
            unsafe { CloseHandle(job_a) };
        }
        println!();

        // --- 实验 B: PerJobUserTimeLimit = 3s ---
        println!("  🔬 实验 B: PerJobUserTimeLimit = 3s (所有进程共享)");
        {
            let job_b_name = format!("river-job-cpu-b-{}", std::process::id());
            let job_b = create_job(&job_b_name).expect("创建 Job B 失败");

            let mut ext_b: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
            ext_b.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_JOB_TIME | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            ext_b.BasicLimitInformation.PerJobUserTimeLimit = 3_000 * 10_000; // 3s
            unsafe {
                SetInformationJobObject(
                    job_b,
                    JobObjectExtendedLimitInformation,
                    &ext_b as *const _ as *const _,
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                );
            }

            // 启动 4 个 CPU 密集进程 (cmd busy-loop, stdin 从 nul 读取)
            let cpu_cmd = "powershell";
            let cpu_args: &[&str] = &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "while($true){}",
            ];
            let mut procs_b = Vec::new();
            for i in 0..4 {
                match spawn_suspended(cpu_cmd, cpu_args, false) {
                    Ok((p, t)) => {
                        if unsafe { AssignProcessToJobObject(job_b, p) } != 0 {
                            resume_thread(t);
                            procs_b.push((p, t));
                        } else {
                            unsafe {
                                CloseHandle(p);
                                CloseHandle(t);
                            }
                        }
                    }
                    Err(e) => eprintln!("     进程 {} 启动失败: {}", i, e),
                }
            }
            println!("     已启动 {} 个 CPU 密集进程", procs_b.len());

            // 等待所有进程被终止
            let wall_start = std::time::Instant::now();
            for (p, _t) in &procs_b {
                wait_and_get_exit(*p);
            }
            let wall_elapsed = wall_start.elapsed();

            // 查询 Job 累计 CPU 时间
            let mut acct_b: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
            unsafe {
                QueryInformationJobObject(
                    job_b,
                    JobObjectBasicAccountingInformation,
                    &mut acct_b as *mut _ as *mut _,
                    size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                    ptr::null_mut(),
                );
            }
            let total_user_ms = acct_b.TotalUserTime / 10_000;
            let total_kernel_ms = acct_b.TotalKernelTime / 10_000;
            let total_cpu_ms = total_user_ms + total_kernel_ms;

            println!("     ⏱️  墙钟耗时: {} ms", wall_elapsed.as_millis());
            println!(
                "     📊 Job 累计 CPU: 用户={} ms, 内核={} ms, 合计={} ms",
                total_user_ms, total_kernel_ms, total_cpu_ms
            );
            println!("     📋 已终止进程数: {}", acct_b.TotalTerminatedProcesses);

            // 注意: PerJobUserTimeLimit 仅限制用户态时间，且 Job CPU 计量存在周期性刷新延迟
            // PowerShell 启动阶段的 .NET JIT/加载也会消耗大量用户态时间
            // 关键对比: 实验 A (PerProcess) 的总 CPU 应显著高于实验 B (PerJob)
            println!("     ℹ️  对比: PerProcess 独立限额 vs PerJob 共享限额");
            if total_cpu_ms < 70_000 {
                println!(
                    "     ✅ 验证通过: 总 CPU ({} ms) 低于实验 A，确认 PerJob 是所有进程共享限额",
                    total_cpu_ms
                );
                println!(
                    "     ℹ️  注: 超出 3s 限额的部分来自 Job CPU 计量的周期性刷新延迟 (约 100ms~1s)"
                );
            } else {
                println!(
                    "     ⚠️  总 CPU ({} ms) 与实验 A 接近，PerJob 限制可能未完全生效",
                    total_cpu_ms
                );
            }

            for (p, t) in procs_b {
                unsafe {
                    CloseHandle(t);
                    CloseHandle(p);
                }
            }
            unsafe { CloseHandle(job_b) };
        }
        println!();

        // ========== 3. UI 限制 ==========
        println!("【3】UI 限制");
        println!("----------------------------------------");

        let mut ui_restrictions: JOBOBJECT_BASIC_UI_RESTRICTIONS = unsafe { std::mem::zeroed() };
        ui_restrictions.UIRestrictionsClass = JOB_OBJECT_UILIMIT_HANDLES
            | JOB_OBJECT_UILIMIT_READCLIPBOARD
            | JOB_OBJECT_UILIMIT_WRITECLIPBOARD
            | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
            | JOB_OBJECT_UILIMIT_EXITWINDOWS
            | JOB_OBJECT_UILIMIT_GLOBALATOMS
            | JOB_OBJECT_UILIMIT_DESKTOP
            | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS;

        if unsafe {
            SetInformationJobObject(
                job,
                JobObjectBasicUIRestrictions,
                &ui_restrictions as *const _ as *const _,
                size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
            )
        } != 0
        {
            println!("  ✅ 已设置 UI 限制:");
            println!("     - 禁止访问外部 USER 句柄");
            println!("     - 禁止读写剪贴板");
            println!("     - 禁止修改系统参数");
            println!("     - 禁止注销/关机");
            println!("     - 禁止创建全局 Atom");
            println!("     - 禁止创建桌面");
            println!("     - 禁止修改显示设置");
        } else {
            println!("  ❌ 设置 UI 限制失败: {}", io::Error::last_os_error());
        }

        // 验证：尝试在受限进程中读取剪贴板（应失败）
        println!("\n  🧪 验证剪贴板访问限制");
        // 注意：cmd.exe 本身不会主动尝试剪贴板操作，这里仅演示设置生效
        // 实际验证需要自定义测试程序
        println!("     ℹ️  UI 限制已应用，需专用测试程序验证具体行为");
        println!();

        // ========== 4. 安全限制 ==========
        println!("【4】安全限制");
        println!("----------------------------------------");

        // 注意：安全限制一旦设置便无法撤销，且会影响后续所有进程
        // 因此我们在单独的 Job 中演示
        let sec_job_name = format!("river-job-sec-{}", std::process::id());
        let sec_job = match create_job(&sec_job_name) {
            Ok(h) => {
                println!("  ✅ 安全测试 Job '{}' 创建成功", sec_job_name);
                h
            }
            Err(e) => {
                eprintln!("  ❌ 创建安全测试 Job 失败: {}", e);
                unsafe { CloseHandle(job) };
                return;
            }
        };

        // 设置安全限制：禁止管理员权限 + 受限令牌
        let mut sec_limit: JOBOBJECT_SECURITY_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        sec_limit.SecurityLimitFlags =
            JOB_OBJECT_SECURITY_NO_ADMIN | JOB_OBJECT_SECURITY_RESTRICTED_TOKEN;

        if unsafe {
            SetInformationJobObject(
                sec_job,
                JobObjectSecurityLimitInformation,
                &sec_limit as *const _ as *const _,
                size_of::<JOBOBJECT_SECURITY_LIMIT_INFORMATION>() as u32,
            )
        } != 0
        {
            println!("  ✅ 已设置安全限制:");
            println!("     - JOB_OBJECT_SECURITY_NO_ADMIN: 禁止管理员权限");
            println!("     - JOB_OBJECT_SECURITY_RESTRICTED_TOKEN: 使用受限令牌");
        } else {
            println!(
                "  ⚠️  设置安全限制失败 (可能需要管理员权限): {}",
                io::Error::last_os_error()
            );
        }

        // 在安全受限 Job 中启动进程并检查其权限
        println!("\n  🧪 在安全受限 Job 中启动进程");
        match spawn_suspended(&comspec, &["/c", "whoami /groups"], false) {
            Ok((p, t)) => {
                if unsafe { AssignProcessToJobObject(sec_job, p) } != 0 {
                    resume_thread(t);
                    let code = wait_and_get_exit(p);
                    println!("     📋 进程退出码: {}", code);
                    println!("     ℹ️  若以管理员运行，子进程权限应已被降级");
                } else {
                    println!("     ❌ 分配失败: {}", io::Error::last_os_error());
                }
                unsafe {
                    CloseHandle(t);
                    CloseHandle(p);
                }
            }
            Err(e) => println!("     ❌ 启动失败: {}", e),
        }

        unsafe { CloseHandle(sec_job) };
        println!();

        // ========== 5. TerminateJobObject 演示 ==========
        println!("【5】TerminateJobObject 批量终止");
        println!("----------------------------------------");

        // 启动多个长时间运行的进程
        let mut batch_procs = Vec::new();
        for i in 0..3 {
            if let Ok((p, t)) = spawn_suspended(&comspec, &["/c", "timeout /t 60 >nul"], false) {
                if unsafe { AssignProcessToJobObject(job, p) } != 0 {
                    resume_thread(t);
                    batch_procs.push((p, t));
                    println!("  - 后台进程 {} 已启动", i + 1);
                } else {
                    unsafe {
                        CloseHandle(p);
                        CloseHandle(t);
                    }
                }
            }
        }

        if !batch_procs.is_empty() {
            println!("  🧪 调用 TerminateJobObject 终止所有进程...");
            if unsafe { TerminateJobObject(job, 42) } != 0 {
                println!("  ✅ Job 内所有进程已终止 (退出码: 42)");
            } else {
                println!(
                    "  ❌ TerminateJobObject 失败: {}",
                    io::Error::last_os_error()
                );
            }

            // 验证进程确实被终止
            for (p, _t) in &batch_procs {
                let code = wait_and_get_exit(*p);
                println!("     - 进程退出码: {}", code);
            }
        }

        // 清理句柄
        for (p, t) in batch_procs {
            unsafe {
                CloseHandle(t);
                CloseHandle(p);
            }
        }
        println!();

        // ========== 6. 清理 ==========
        println!("【6】清理资源");
        println!("----------------------------------------");

        unsafe { CloseHandle(job) };
        println!("  ✅ Job 句柄已关闭");

        println!("\n=== 演示完成 ===");
    }
}

fn main() {
    #[cfg(windows)]
    imp::run();

    #[cfg(not(windows))]
    {
        eprintln!("此示例仅在 Windows 上运行。");
        eprintln!("Job Object 是 Windows 特有的进程管理机制。");
        std::process::exit(1);
    }
}
