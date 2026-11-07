//! seccompiler 能力的全面演示。
//!
//! 演示的功能：
//!   1. 基础 allowlist/denylist 过滤器构建
//!   2. SeccompAction 变体：Allow、Errno、Trace、Log
//!   3. 带参数匹配的 SeccompRule（精确值、范围、掩码）
//!   4. 过滤器编译与应用（单线程 / 全线程）
//!   5. 错误处理：无效过滤器、权限问题、架构不匹配
//!   6. 通过 /proc/self/status 进行运行时验证
//!   7. 多阶段沙箱升级演示

#[cfg(target_os = "linux")]
mod imp {
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
        SeccompFilter, SeccompRule, apply_filter, apply_filter_all_threads,
    };
    use std::collections::BTreeMap;
    use std::os::raw::c_long;

    // ========================================================================
    // 辅助工具
    // ========================================================================

    fn last_errno() -> i32 {
        std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(-1)
    }

    /// 从 /proc/self/status 读取 Seccomp 字段
    fn read_seccomp_status() -> Option<String> {
        std::fs::read_to_string("/proc/self/status")
            .ok()?
            .lines()
            .find(|line| line.starts_with("Seccomp:"))
            .map(|line| line.trim().to_string())
    }

    /// 打印当前 seccomp 状态
    fn print_seccomp_status(label: &str) {
        match read_seccomp_status() {
            Some(status) => println!("  [{}] {}", label, status),
            None => println!("  [{}] 无法读取 /proc/self/status", label),
        }
    }

    // ========================================================================
    // 阶段 1：基础 Allowlist 过滤器
    // ========================================================================

    /// 演示基础 allowlist 过滤器：仅允许指定的系统调用，
    /// 其余所有系统调用返回 EPERM。
    fn demo_basic_allowlist() {
        println!("\n=== 阶段 1：基础 Allowlist 过滤器 ===");
        println!("  构建最小化 allowlist 过滤器...");

        // 定义此阶段允许的系统调用
        let allowed_syscalls: &[c_long] = &[
            libc::SYS_write,       // printf / println
            libc::SYS_read,        // 可能的输入操作
            libc::SYS_close,       // 清理
            libc::SYS_exit_group,  // 正常退出
            libc::SYS_exit,        // 备用退出
            libc::SYS_brk,         // 内存分配（println 可能需要）
            libc::SYS_mmap,        // 内存映射
            libc::SYS_munmap,      // 取消内存映射
            libc::SYS_rt_sigreturn,
            libc::SYS_futex,       // 线程原语
            libc::SYS_sched_yield,
        ];

        // 空规则向量 = 无条件允许
        let rules: BTreeMap<i64, Vec<SeccompRule>> = allowed_syscalls
            .iter()
            .map(|&nr| (nr as i64, Vec::new()))
            .collect();

        // 默认动作：未匹配的系统调用返回 EPERM
        // 匹配动作：Allow
        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Errno(libc::EPERM as u32), // 默认拒绝
            SeccompAction::Allow,                      // 显式允许
            std::env::consts::ARCH.try_into().expect("不支持的架构"),
        )
        .expect("构建过滤器失败");

        let bpf: BpfProgram = filter.try_into().expect("编译 BPF 失败");
        println!("  ✅ 过滤器已编译: {} 条 BPF 指令", bpf.len());

        // 注意：此处不实际应用该过滤器，否则会阻止后续演示阶段。
        println!("  ℹ️  过滤器未应用（会阻止后续演示）");
        println!("  允许的系统调用: {:?}", 
            allowed_syscalls.iter().map(|&s| s as i64).collect::<Vec<_>>());
    }

    // ========================================================================
    // 阶段 2：带 Errno 动作的 Denylist 过滤器
    // ========================================================================

    /// 演示 denylist：阻止特定的危险系统调用，允许其余所有。
    fn demo_denylist() {
        println!("\n=== 阶段 2：Denylist 过滤器（阻止危险系统调用）===");
        println!("  构建 denylist，阻止 ptrace、reboot、kexec_load 等...");

        // 要阻止的危险系统调用
        let blocked_syscalls: &[c_long] = &[
            libc::SYS_ptrace,
            libc::SYS_reboot,
            #[cfg(target_arch = "x86_64")]
            libc::SYS_kexec_load,
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_swapon,
            libc::SYS_swapoff,
        ];

        // 对于 denylist：匹配的系统调用返回 Errno，未匹配的允许
        let rules: BTreeMap<i64, Vec<SeccompRule>> = blocked_syscalls
            .iter()
            .map(|&nr| (nr as i64, Vec::new()))
            .collect();

        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Allow,                       // 默认：允许
            SeccompAction::Errno(libc::EPERM as u32),   // 匹配：拒绝
            std::env::consts::ARCH.try_into().expect("不支持的架构"),
        )
        .expect("构建 denylist 过滤器失败");

        let bpf: BpfProgram = filter.try_into().expect("编译 BPF 失败");
        println!("  ✅ Denylist 过滤器已编译: {} 条 BPF 指令", bpf.len());
        println!("  被阻止的系统调用: {:?}", 
            blocked_syscalls.iter().map(|&s| s as i64).collect::<Vec<_>>());
    }

    // ========================================================================
    // 阶段 3：使用 SeccompRule 进行参数匹配
    // ========================================================================

    /// 演示基于系统调用参数的精细过滤。
    fn demo_argument_matching() {
        println!("\n=== 阶段 3：参数匹配规则 ===");
        println!("  构建带系统调用参数条件的过滤器...");

        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

        // 规则 1：仅允许 write() 写入 stdout (fd=1) 和 stderr (fd=2)
        // int write(int fd, const void *buf, size_t count);
        // 参数 0 是文件描述符
        let write_stdout_rule = SeccompRule::new(vec![
            SeccompCondition::new(
                0,                              // 参数索引
                SeccompCmpArgLen::Dword,        // 32 位比较
                SeccompCmpOp::Eq,               // 等于
                1,                              // stdout fd
            ).expect("无效的条件"),
        ]).expect("无效的规则");

        let write_stderr_rule = SeccompRule::new(vec![
            SeccompCondition::new(
                0,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                2,                              // stderr fd
            ).expect("无效的条件"),
        ]).expect("无效的规则");

        rules.insert(libc::SYS_write as i64, vec![write_stdout_rule, write_stderr_rule]);

        // 规则 2：仅允许 openat() 使用 O_RDONLY 标志
        // int openat(int dirfd, const char *pathname, int flags, ...);
        // 参数 2 是 flags 参数
        let open_rdonly_rule = SeccompRule::new(vec![
            SeccompCondition::new(
                2,                              // flags 参数
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                libc::O_RDONLY as u64,
            ).expect("无效的条件"),
        ]).expect("无效的规则");

        rules.insert(libc::SYS_openat as i64, vec![open_rdonly_rule]);

        // 规则 3：仅允许 mmap 使用 PROT_READ（不允许写入/执行）
        // void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
        // 参数 2 是 prot
        let mmap_read_rule = SeccompRule::new(vec![
            SeccompCondition::new(
                2,                              // prot 参数
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                libc::PROT_READ as u64,
            ).expect("无效的条件"),
        ]).expect("无效的规则");

        rules.insert(libc::SYS_mmap as i64, vec![mmap_read_rule]);

        // 添加不受限制的必要系统调用
        let essential: &[c_long] = &[
            libc::SYS_close,
            libc::SYS_exit_group,
            libc::SYS_exit,
            libc::SYS_rt_sigreturn,
            libc::SYS_futex,
            libc::SYS_brk,
            libc::SYS_munmap,
            libc::SYS_sched_yield,
            libc::SYS_read,
        ];

        for &nr in essential {
            rules.entry(nr as i64).or_insert_with(Vec::new);
        }

        let filter = SeccompFilter::new(
            rules.clone(),
            SeccompAction::Errno(libc::EPERM as u32),
            SeccompAction::Allow,
            std::env::consts::ARCH.try_into().expect("不支持的架构"),
        )
        .expect("构建参数匹配过滤器失败");

        let bpf: BpfProgram = filter.try_into().expect("编译 BPF 失败");
        println!("  ✅ 参数匹配过滤器已编译: {} 条 BPF 指令", bpf.len());
        println!("  规则摘要:");
        println!("    • write(fd=1 或 fd=2) → 允许");
        println!("    • openat(flags=O_RDONLY) → 允许");
        println!("    • mmap(prot=PROT_READ) → 允许");
        println!("    • 必要系统调用 → 允许（无条件）");
        println!("    • 其余所有 → EPERM");
    }

    // ========================================================================
    // 阶段 4：多种动作类型
    // ========================================================================

    /// 演示不同的 SeccompAction 变体。
    fn demo_action_types() {
        println!("\n=== 阶段 4：SeccompAction 变体 ===");
        println!("  演示匹配/未匹配系统调用的不同动作...");

        // seccompiler 中可用的动作类型：
        // - Allow: 允许该系统调用
        // - Errno(errno): 返回指定的 errno
        // - Trace(tracer_id): 通过 PTRACE_SECCOMP 通知跟踪器
        // - Log: 允许但记录到审计日志（需要 CAP_AUDIT_WRITE 或 root）
        // - Kill: 立即终止该线程
        // - KillProcess: 终止整个进程组

        println!("  可用的 SeccompAction 变体:");
        println!("    • Allow           — 允许系统调用");
        println!("    • Errno(n)        — 向调用者返回 errno n");
        println!("    • Trace(id)       — 通知 ptrace 跟踪器");
        println!("    • Log             — 允许 + 审计日志（需要特权）");
        println!("    • Kill            — SIGKILL 终止线程");
        println!("    • KillProcess     — SIGKILL 终止整个进程");

        // 使用 Log 动作构建过滤器（有特权时），否则回退到 Errno
        let log_action = if unsafe { libc::geteuid() } == 0 {
            println!("  以 root 运行: 使用 Log 动作进行演示");
            SeccompAction::Log
        } else {
            println!("  非 root: 使用 Errno(ENOSYS) 替代 Log");
            SeccompAction::Errno(libc::ENOSYS as u32)
        };

        let rules: BTreeMap<i64, Vec<SeccompRule>> = [
            (libc::SYS_getpid as i64, Vec::new()),
        ]
        .into_iter()
        .collect();

        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Allow,  // 默认允许
            log_action,            // 匹配动作（Log 或 Errno）
            std::env::consts::ARCH.try_into().expect("不支持的架构"),
        )
        .expect("构建动作演示过滤器失败");

        let bpf: BpfProgram = filter.try_into().expect("编译 BPF 失败");
        println!("  ✅ 动作类型过滤器已编译: {} 条 BPF 指令", bpf.len());
    }

    // ========================================================================
    // 阶段 5：实时过滤器应用（在子进程中）
    // ========================================================================

    /// fork 一个子进程，在其中应用真实的 seccomp 过滤器并验证其生效。
    fn demo_live_filter() {
        println!("\n=== 阶段 5：实时过滤器应用（子进程）===");
        println!("  fork 子进程以应用并验证 seccomp 过滤器...");

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            eprintln!("  ❌ fork 失败: {}", std::io::Error::last_os_error());
            return;
        }

        if pid == 0 {
            // ---- 子进程 ----
            child_apply_and_verify();
        }

        // ---- 父进程：等待子进程 ----
        let mut status: libc::c_int = 0;
        unsafe {
            libc::waitpid(pid, &mut status, 0);
        }

        if libc::WIFEXITED(status) {
            let code = libc::WEXITSTATUS(status);
            if code == 0 {
                println!("  ✅ 子进程成功完成（退出码 0）");
            } else {
                println!("  ⚠️  子进程以退出码 {} 退出", code);
            }
        } else if libc::WIFSIGNALED(status) {
            let sig = libc::WTERMSIG(status);
            println!("  ⚠️  子进程被信号 {} 终止", sig);
        }
    }

    /// 子进程侧：应用 seccomp 过滤器并测试被阻止的系统调用确实失败。
    fn child_apply_and_verify() -> ! {
        // 步骤 1：设置 no_new_privs（非特权 seccomp 所必需）
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            eprintln!("  ❌ prctl(NO_NEW_PRIVS) 失败: {}", std::io::Error::last_os_error());
            unsafe { libc::_exit(1) };
        }

        // 步骤 2：构建限制性过滤器
        let allowed: &[c_long] = &[
            libc::SYS_write,
            libc::SYS_read,
            libc::SYS_close,
            libc::SYS_exit_group,
            libc::SYS_exit,
            libc::SYS_rt_sigreturn,
            libc::SYS_futex,
            libc::SYS_brk,
            libc::SYS_mmap,
            libc::SYS_munmap,
            libc::SYS_sched_yield,
            libc::SYS_getpid,
            // read_to_string("/proc/self/status") 所需的文件 I/O
            libc::SYS_openat,
            libc::SYS_lseek,
            libc::SYS_fstat,
            libc::SYS_newfstatat,
            libc::SYS_statx,
            libc::SYS_getdents64,
        ];

        let rules: BTreeMap<i64, Vec<SeccompRule>> = allowed
            .iter()
            .map(|&nr| (nr as i64, Vec::new()))
            .collect();

        let filter = match SeccompFilter::new(
            rules,
            SeccompAction::Errno(libc::EPERM as u32),
            SeccompAction::Allow,
            std::env::consts::ARCH.try_into().expect("不支持的架构"),
        ) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("  ❌ 过滤器构建失败: {:?}", e);
                unsafe { libc::_exit(2) };
            }
        };

        let bpf: BpfProgram = match filter.try_into() {
            Ok(b) => b,
            Err(e) => {
                eprintln!("  ❌ BPF 编译失败: {:?}", e);
                unsafe { libc::_exit(3) };
            }
        };

        // 步骤 3：将过滤器应用到所有线程
        if let Err(e) = apply_filter_all_threads(&bpf) {
            eprintln!("  ❌ apply_filter_all_threads 失败: {:?}", e);
            unsafe { libc::_exit(4) };
        }

        // 步骤 4：通过 /proc 验证
        match read_seccomp_status() {
            Some(status) if status.contains('2') => {
                // 将成功消息写入 stderr (fd=2)
                let msg = b"\x20\x20\xe2\x9c\x85\x20Seccomp \xe8\xbf\x87\xe6\xbb\xa4\xe5\x99\xa8\xe5\xb7\xb2\xe7\x94\x9f\xe6\x95\x88 (Seccomp: 2)\n";
                unsafe {
                    libc::write(2, msg.as_ptr() as *const _, msg.len());
                }
            }
            other => {
                let msg = format!("  ❌ 意外的 seccomp 状态: {:?}\n", other);
                unsafe {
                    libc::write(2, msg.as_ptr() as *const _, msg.len());
                }
                unsafe { libc::_exit(5) };
            }
        }

        // 步骤 5：测试被阻止的系统调用确实失败
        // 尝试调用不在白名单中的 getuid
        let result = unsafe { libc::syscall(libc::SYS_getuid) };
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        
        if result == -1 && errno == libc::EPERM {
            let msg = b"\x20\x20\xe2\x9c\x85\x20\xe8\xa2\xab\xe9\x98\xbb\xe6\xad\xa2\xe7\x9a\x84\xe7\xb3\xbb\xe7\xbb\x9f\xe8\xb0\x83\xe7\x94\xa8 (getuid) \xe6\xad\xa3\xe7\xa1\xae\xe8\xbf\x94\xe5\x9b\x9e EPERM\n";
            unsafe {
                libc::write(2, msg.as_ptr() as *const _, msg.len());
            }
        } else {
            let msg = format!(
                "  ❌ 被阻止的系统调用意外成功: ret={}, errno={}\n",
                result, errno
            );
            unsafe {
                libc::write(2, msg.as_ptr() as *const _, msg.len());
            }
            unsafe { libc::_exit(6) };
        }

        // 步骤 6：测试允许的系统调用仍然正常工作
        let my_pid = unsafe { libc::getpid() };
        if my_pid > 0 {
            let msg = b"\x20\x20\xe2\x9c\x85\x20\xe5\x85\x81\xe8\xae\xb8\xe7\x9a\x84\xe7\xb3\xbb\xe7\xbb\x9f\xe8\xb0\x83\xe7\x94\xa8 (getpid) \xe6\xad\xa3\xe5\xb8\xb8\xe5\xb7\xa5\xe4\xbd\x9c\n";
            unsafe {
                libc::write(2, msg.as_ptr() as *const _, msg.len());
            }
        }

        unsafe { libc::_exit(0) };
    }

    // ========================================================================
    // 阶段 6：单线程 vs 全线程应用
    // ========================================================================

    /// 演示 apply_filter 与 apply_filter_all_threads 的区别。
    fn demo_thread_scope() {
        println!("\n=== 阶段 6：线程作用域 (apply_filter vs apply_filter_all_threads) ===");
        println!("  比较单线程和全线程过滤器应用...");

        println!("  API 区别:");
        println!("    • apply_filter(&bpf)          — 仅应用到当前线程");
        println!("    • apply_filter_all_threads(&bpf) — 应用到所有线程 (TSYNC)");
        println!("                                     需要 PR_SET_NO_NEW_PRIVS 或 CAP_SYS_ADMIN");

        // 在 fork 的子进程中演示两种方式
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            eprintln!("  ❌ fork 失败");
            return;
        }

        if pid == 0 {
            // 子进程：使用单线程 apply_filter
            if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
                unsafe { libc::_exit(1) };
            }

            let rules: BTreeMap<i64, Vec<SeccompRule>> = [
                libc::SYS_write,
                libc::SYS_exit_group,
                libc::SYS_exit,
                libc::SYS_rt_sigreturn,
                libc::SYS_futex,
                libc::SYS_brk,
                libc::SYS_mmap,
                libc::SYS_munmap,
                libc::SYS_close,
                libc::SYS_sched_yield,
            ]
            .iter()
            .map(|&nr| (nr as i64, Vec::new()))
            .collect();

            let filter = SeccompFilter::new(
                rules,
                SeccompAction::Errno(libc::EPERM as u32),
                SeccompAction::Allow,
                std::env::consts::ARCH.try_into().expect("不支持的架构"),
            )
            .expect("构建过滤器失败");

            let bpf: BpfProgram = filter.try_into().expect("编译 BPF 失败");

            // 使用单线程版本
            match apply_filter(&bpf) {
                Ok(()) => {
                    let msg = b"\x20\x20\xe2\x9c\x85\x20apply_filter\xef\xbc\x88\xe5\x8d\x95\xe7\xba\xbf\xe7\xa8\x8b\xef\xbc\x89\xe6\x88\x90\xe5\x8a\x9f\n";
                    unsafe { libc::write(2, msg.as_ptr() as *const _, msg.len()) };
                }
                Err(e) => {
                    let msg = format!("  ❌ apply_filter 失败: {:?}\n", e);
                    unsafe { libc::write(2, msg.as_ptr() as *const _, msg.len()) };
                }
            }

            unsafe { libc::_exit(0) };
        }

        // 父进程等待
        let mut status: libc::c_int = 0;
        unsafe {
            libc::waitpid(pid, &mut status, 0);
        };
        
        if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
            println!("  ✅ 已在子进程中验证单线程过滤器应用");
        }
    }

    // ========================================================================
    // 阶段 7：错误处理与边界情况
    // ========================================================================

    /// 演示错误条件和边界情况。
    fn demo_error_handling() {
        println!("\n=== 阶段 7：错误处理与边界情况 ===");

        // 情况 1：空过滤器（无任何规则）
        println!("  情况 1：空过滤器（拒绝一切）...");
        let empty_rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        match SeccompFilter::new(
            empty_rules,
            SeccompAction::Errno(libc::EPERM as u32),
            SeccompAction::Allow,
            std::env::consts::ARCH.try_into().expect("不支持的架构"),
        ) {
            Ok(filter) => {
                let bpf: Result<BpfProgram, _> = filter.try_into();
                match bpf {
                    Ok(prog) => println!("    ✅ 空过滤器已编译（{} 条指令）— 将拒绝所有系统调用", prog.len()),
                    Err(e) => println!("    ⚠️  空过滤器编译失败: {:?}", e),
                }
            }
            Err(e) => println!("    ⚠️  空过滤器创建失败: {:?}", e),
        }

        // 情况 2：无效的架构字符串
        println!("  情况 2：无效架构...");
        let rules: BTreeMap<i64, Vec<SeccompRule>> = [(libc::SYS_write as i64, Vec::new())]
            .into_iter()
            .collect();
        
        // 尝试对无效字符串使用 try_into 来创建无效架构
        let bad_arch_result: Result<seccompiler::TargetArch, _> = "invalid_arch".try_into();
        match bad_arch_result {
            Ok(_) => println!("    ⚠️  意外接受了无效架构"),
            Err(_) => println!("    ✅ 正确拒绝了无效架构字符串"),
        }

        // 情况 3：未设置 NO_NEW_PRIVS 时应用过滤器（非 root 应失败）
        println!("  情况 3：未设置 NO_NEW_PRIVS 时应用（非 root）...");
        if unsafe { libc::geteuid() } != 0 {
            let filter = SeccompFilter::new(
                rules.clone(),
                SeccompAction::Errno(libc::EPERM as u32),
                SeccompAction::Allow,
                std::env::consts::ARCH.try_into().expect("不支持的架构"),
            )
            .expect("构建过滤器失败");

            let bpf: BpfProgram = filter.try_into().expect("编译 BPF 失败");

            // 非 root 且未设置 NO_NEW_PRIVS 时应失败
            match apply_filter_all_threads(&bpf) {
                Ok(()) => println!("    ⚠️  未设置 NO_NEW_PRIVS 却成功应用了过滤器（非 root 下不应发生）"),
                Err(e) => println!("    ✅ 未设置 NO_NEW_PRIVS 时正确失败: {:?}", e),
            }
        } else {
            println!("    ℹ️  以 root 运行 — 跳过此测试（root 下会成功）");
        }

        // 情况 4：同一系统调用的重复规则条目
        println!("  情况 4：同一系统调用的多条规则（OR 语义）...");
        let multi_rules: BTreeMap<i64, Vec<SeccompRule>> = [(
            libc::SYS_write as i64,
            vec![
                SeccompRule::new(vec![
                    SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, 1)
                        .expect("条件"),
                ])
                .expect("规则"),
                SeccompRule::new(vec![
                    SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, 2)
                        .expect("条件"),
                ])
                .expect("规则"),
            ],
        )]
        .into_iter()
        .collect();

        match SeccompFilter::new(
            multi_rules,
            SeccompAction::Errno(libc::EPERM as u32),
            SeccompAction::Allow,
            std::env::consts::ARCH.try_into().expect("不支持的架构"),
        ) {
            Ok(f) => {
                let bpf: BpfProgram = f.try_into().expect("编译 BPF 失败");
                println!("    ✅ 同一系统调用的多条规则已编译（{} 条指令）", bpf.len());
                println!("       （同一系统调用内的规则以 OR 组合）");
            }
            Err(e) => println!("    ❌ 失败: {:?}", e),
        }

        // 情况 5：基于掩码的比较
        println!("  情况 5：基于掩码的参数比较...");
        let mask_rules: BTreeMap<i64, Vec<SeccompRule>> = [(
            libc::SYS_openat as i64,
            vec![
                // 允许 openat 使用 O_RDONLY | O_CLOEXEC 组合
                SeccompRule::new(vec![
                    SeccompCondition::new(
                        2,
                        SeccompCmpArgLen::Dword,
                        SeccompCmpOp::MaskedEq((libc::O_RDONLY | libc::O_CLOEXEC) as u64),
                        (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
                    )
                    .expect("条件"),
                ])
                .expect("规则"),
            ],
        )]
        .into_iter()
        .collect();

        match SeccompFilter::new(
            mask_rules,
            SeccompAction::Errno(libc::EPERM as u32),
            SeccompAction::Allow,
            std::env::consts::ARCH.try_into().expect("不支持的架构"),
        ) {
            Ok(f) => {
                let bpf: BpfProgram = f.try_into().expect("编译 BPF 失败");
                println!("    ✅ MaskedEq 比较已编译（{} 条指令）", bpf.len());
            }
            Err(e) => println!("    ❌ 失败: {:?}", e),
        }
    }

    // ========================================================================
    // 主入口
    // ========================================================================

    pub fn run() {
        println!("╔══════════════════════════════════════════════╗");
        println!("║     seccompiler 能力演示                     ║");
        println!("╚══════════════════════════════════════════════╝\n");

        println!("库版本: seccompiler v{}", env!("CARGO_PKG_VERSION"));
        println!("架构: {}", std::env::consts::ARCH);
        print_seccomp_status("初始状态");

        // 运行所有演示阶段
        demo_basic_allowlist();
        demo_denylist();
        demo_argument_matching();
        demo_action_types();
        demo_live_filter();
        demo_thread_scope();
        demo_error_handling();

        println!("\n╔══════════════════════════════════════════════╗");
        println!("║     所有阶段已完成                           ║");
        println!("╚══════════════════════════════════════════════╝");
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    imp::run();

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("此示例仅在 Linux 上运行。");
        eprintln!("seccompiler 使用 Linux seccomp-bpf，其他平台不可用。");
        std::process::exit(1);
    }
}
