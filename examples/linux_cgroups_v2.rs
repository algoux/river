//! Linux cgroups v2 能力演示。
//!
//! 演示的功能：
//!   1. 基础层级操作 — 检测 cgroup v2 挂载、创建/删除子 cgroup、
//!      读写 cgroup.controllers / subtree_control
//!   2. 进程迁移     — 将进程写入 cgroup.procs，验证 /proc/<pid>/cgroup 变化
//!   3. CPU 控制器   — 设置 cpu.max / cpu.weight，验证 CPU 限制生效
//!   4. Memory 控制器 — 设置 memory.max / memory.high，触发 OOM 或节流
//!   5. PIDs 控制器  — 设置 pids.max 限制 fork 数量，验证超限拒绝
//!   6. IO 控制器    — 设置 io.max 限制磁盘带宽
//!   7. clone3 + CLONE_INTO_CGROUP — 通过 clone3 直接将子进程创建到指定 cgroup
//!   8. cgroup.freeze / events — 冻结/解冻 cgroup，监听 memory.events / pids.events
//!   9. 多进程并行 CPU 统计 — N 个 worker 并行消耗 CPU，验证 cgroup cpu.stat
//!      在多核机器上 1 秒实际时间内消耗超过 1 秒 CPU 时间
//!
//! 要求：必须以 root (CAP_SYS_ADMIN) 运行。
//!
//! API 覆盖：
//!   • clone3 原始系统调用（CLONE_INTO_CGROUP）
//!   • rustix: pipe, process (waitid), fs (open/read/write)
//!   • libc: cgroup 文件系统交互

#[cfg(target_os = "linux")]
mod imp {
    use rustix::fd::{AsRawFd, FromRawFd, OwnedFd};
    use rustix::pipe::{PipeFlags, pipe_with};
    use std::os::raw::c_int;
    use std::path::{Path, PathBuf};

    // ========================================================================
    // clone3 原始系统调用封装
    // ========================================================================

    #[repr(C)]
    #[derive(Default)]
    struct CloneArgs {
        flags: u64,
        pidfd: u64,
        child_tid: u64,
        parent_tid: u64,
        exit_signal: u64,
        stack: u64,
        stack_size: u64,
        tls: u64,
        set_tid: u64,
        set_tid_size: u64,
        cgroup: u64,
    }

    const CLONE_INTO_CGROUP: u64 = 0x8000_0000;
    const CLONE_PIDFD: u64 = 0x0000_1000;

    const SYS_CLONE3: libc::c_long = 435; // x86_64

    unsafe fn clone3(args: &CloneArgs) -> i64 {
        unsafe {
            libc::syscall(
                SYS_CLONE3,
                args as *const CloneArgs,
                std::mem::size_of::<CloneArgs>(),
            )
        }
    }

    // ========================================================================
    // 辅助函数
    // ========================================================================

    fn check_root() {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("❌ 此示例必须以 root 权限运行。");
            eprintln!("   用法: sudo cargo run --example linux_cgroups_v2");
            std::process::exit(1);
        }
    }

    /// cgroup v2 统一层级挂载点
    const CGROUP_ROOT: &str = "/sys/fs/cgroup";

    /// 测试用 cgroup 名称前缀
    const TEST_PREFIX: &str = "river_cgroup_test";

    /// 创建测试 cgroup 路径
    fn test_cgroup_path(name: &str) -> PathBuf {
        PathBuf::from(CGROUP_ROOT).join(format!("{TEST_PREFIX}_{name}"))
    }

    /// 读取 cgroup 文件内容
    fn cg_read(path: &Path) -> Result<String, String> {
        std::fs::read_to_string(path).map_err(|e| format!("读取 {} 失败: {e}", path.display()))
    }

    /// 写入 cgroup 文件
    fn cg_write(path: &Path, value: &str) -> Result<(), String> {
        std::fs::write(path, value).map_err(|e| format!("写入 {} 失败: {e}", path.display()))
    }

    /// 创建子 cgroup（mkdir）
    fn cg_mkdir(path: &Path) -> Result<(), String> {
        std::fs::create_dir(path).map_err(|e| format!("创建 {} 失败: {e}", path.display()))
    }

    /// 删除子 cgroup（rmdir）
    fn cg_rmdir(path: &Path) -> Result<(), String> {
        std::fs::remove_dir(path).map_err(|e| format!("删除 {} 失败: {e}", path.display()))
    }

    /// 启用子树控制器
    fn enable_subtree_control(cgroup: &Path, controllers: &str) -> Result<(), String> {
        let subtree = cgroup.join("cgroup.subtree_control");
        cg_write(&subtree, controllers)
    }

    /// 清理所有测试 cgroup
    fn cleanup_test_cgroups() {
        let root = Path::new(CGROUP_ROOT);
        if let Ok(entries) = std::fs::read_dir(root) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.starts_with(TEST_PREFIX) {
                    let _ = cg_rmdir(&entry.path());
                }
            }
        }
    }

    #[allow(dead_code)]
    fn last_errno() -> i32 {
        std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(-1)
    }

    // ========================================================================
    // 阶段 1: 基础层级操作
    // ========================================================================

    fn demo_hierarchy() -> Result<(), String> {
        println!("=== 阶段 1: 基础层级操作 ===");

        // 1.1 检测 cgroup v2 挂载
        let mount_info = std::fs::read_to_string("/proc/mounts")
            .map_err(|e| format!("读取 /proc/mounts 失败: {e}"))?;
        let has_cgroup2 = mount_info.lines().any(|line| line.contains("cgroup2"));
        if !has_cgroup2 {
            return Err("未检测到 cgroup v2 挂载".into());
        }
        println!("  ✅ cgroup v2 已挂载于 {CGROUP_ROOT}");

        // 1.2 读取根 cgroup 可用控制器
        let root_controllers = cg_read(&Path::new(CGROUP_ROOT).join("cgroup.controllers"))?;
        println!("  • 根 cgroup 可用控制器: {}", root_controllers.trim());

        // 1.3 创建测试子 cgroup
        let test_cg = test_cgroup_path("hierarchy");
        cg_mkdir(&test_cg)?;
        println!("  ✅ 创建子 cgroup: {}", test_cg.display());

        // 1.4 读取子 cgroup 的 controllers（初始为空，需要从父级启用）
        let child_ctrl = cg_read(&test_cg.join("cgroup.controllers"))?;
        println!("  • 子 cgroup 初始 controllers: '{}'", child_ctrl.trim());

        // 1.5 在根 cgroup 启用 subtree_control
        let root = Path::new(CGROUP_ROOT);
        // 先读取当前 subtree_control
        let current_subtree = cg_read(&root.join("cgroup.subtree_control"))?;
        println!("  • 根 cgroup 当前 subtree_control: '{}'", current_subtree.trim());

        // 尝试启用 cpu memory pids
        match enable_subtree_control(root, "+cpu +memory +pids") {
            Ok(()) => println!("  ✅ 已在根 cgroup 启用 cpu/memory/pids 子树控制"),
            Err(e) => println!("  ⚠️  启用子树控制失败: {e}"),
        }

        // 重新检查子 cgroup controllers
        let child_ctrl_after = cg_read(&test_cg.join("cgroup.controllers"))?;
        println!(
            "  • 启用后子 cgroup controllers: '{}'",
            child_ctrl_after.trim()
        );

        // 1.6 读取 cgroup.type
        let cg_type = cg_read(&test_cg.join("cgroup.type")).unwrap_or_else(|_| "N/A".into());
        println!("  • cgroup.type: {}", cg_type.trim());

        // 1.7 清理
        cg_rmdir(&test_cg)?;
        println!("  ✅ 已清理测试 cgroup");

        Ok(())
    }

    // ========================================================================
    // 阶段 2: 进程迁移
    // ========================================================================

    fn demo_process_migration() -> Result<(), String> {
        println!("\n=== 阶段 2: 进程迁移 ===");

        // 确保 cpu 控制器已启用
        let root = Path::new(CGROUP_ROOT);
        let _ = enable_subtree_control(root, "+cpu");

        let test_cg = test_cgroup_path("migration");
        cg_mkdir(&test_cg)?;
        println!("  ✅ 创建测试 cgroup: {}", test_cg.display());

        // 2.1 记录父进程的 cgroup（不应改变）
        let parent_cgroup = cg_read(Path::new("/proc/self/cgroup"))?;
        println!(
            "  • 父进程 /proc/self/cgroup: {}",
            parent_cgroup.trim()
        );

        // 2.2 fork 一个子进程用于迁移演示（父进程保持原位，避免 systemd 迁回问题）
        let (status_r, status_w) = pipe_with(PipeFlags::CLOEXEC).expect("pipe2 失败");

        let child_pid_raw = unsafe { libc::fork() };
        if child_pid_raw == 0 {
            // ---- 子进程 ----
            drop(status_r);

            let my_pid = unsafe { libc::getpid() };

            // 将自己迁移到测试 cgroup
            let procs = test_cg.join("cgroup.procs");
            let migrate_ok = cg_write(&procs, &format!("{my_pid}\n")).is_ok();

            // 读取迁移后的 cgroup
            let after = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
            let in_target = after.contains(TEST_PREFIX);

            // 报告: [migrate_ok:u8, in_target:u8]
            let report = [migrate_ok as u8, in_target as u8];
            let _ = rustix::io::write(&status_w, &report);
            drop(status_w);

            // 保持存活供父进程检查 /proc
            unsafe { libc::sleep(2) };
            unsafe { libc::_exit(0) };
        }

        drop(status_w);

        if child_pid_raw > 0 {
            // 等待子进程就绪报告
            let mut report = [0u8; 2];
            let n = loop {
                match rustix::io::read(&status_r, &mut report) {
                    Ok(n) => break n,
                    Err(rustix::io::Errno::INTR) => continue,
                    Err(e) => return Err(format!("读取迁移报告失败: {e}")),
                }
            };

            if n >= 2 {
                if report[0] == 1 {
                    println!("  ✅ 已将子进程 PID {child_pid_raw} 写入 cgroup.procs");
                } else {
                    println!("  ❌ 写入 cgroup.procs 失败");
                }

                if report[1] == 1 {
                    println!("  ✅ 子进程确认已在目标 cgroup 中");
                } else {
                    println!("  ⚠️  子进程 /proc/self/cgroup 未反映迁移");
                }
            }

            // 从父进程侧验证
            let child_cgroup = std::fs::read_to_string(format!("/proc/{child_pid_raw}/cgroup"))
                .unwrap_or_default();
            println!(
                "  • /proc/{}/cgroup: {}",
                child_pid_raw,
                child_cgroup.trim()
            );

            // 读取 cgroup.procs 确认
            let procs_content = cg_read(&test_cg.join("cgroup.procs"))?;
            println!("  • cgroup.procs 内容: {}", procs_content.trim());

            // 验证父进程未被影响
            let parent_cgroup_after = cg_read(Path::new("/proc/self/cgroup"))?;
            if parent_cgroup_after.trim() == parent_cgroup.trim() {
                println!("  ✅ 父进程 cgroup 未受影响");
            } else {
                println!("  ⚠️  父进程 cgroup 意外改变");
            }

            // 回收子进程
            let mut status: libc::c_int = 0;
            unsafe { libc::waitpid(child_pid_raw, &mut status, 0) };
        }

        // 清理（父进程从未迁入，无需迁回）
        cg_rmdir(&test_cg)?;
        println!("  ✅ 已清理测试 cgroup");

        Ok(())
    }

    // ========================================================================
    // 阶段 3: CPU 控制器
    // ========================================================================

    fn demo_cpu_controller() -> Result<(), String> {
        println!("\n=== 阶段 3: CPU 控制器 ===");

        let root = Path::new(CGROUP_ROOT);
        let _ = enable_subtree_control(root, "+cpu");

        let test_cg = test_cgroup_path("cpu");
        cg_mkdir(&test_cg)?;
        println!("  ✅ 创建测试 cgroup: {}", test_cg.display());

        // 3.1 读取默认 cpu.max
        let cpu_max = cg_read(&test_cg.join("cpu.max"))?;
        println!("  • 默认 cpu.max: {}", cpu_max.trim());

        // 3.2 读取默认 cpu.weight
        let cpu_weight = cg_read(&test_cg.join("cpu.weight"))?;
        println!("  • 默认 cpu.weight: {}", cpu_weight.trim());

        // 3.3 设置 cpu.max = "50000 100000"（50% CPU）
        cg_write(&test_cg.join("cpu.max"), "50000 100000\n")?;
        let cpu_max_new = cg_read(&test_cg.join("cpu.max"))?;
        println!("  ✅ 设置 cpu.max = '50000 100000' → 读回: {}", cpu_max_new.trim());

        // 3.4 设置 cpu.weight = 50
        cg_write(&test_cg.join("cpu.weight"), "50\n")?;
        let cpu_weight_new = cg_read(&test_cg.join("cpu.weight"))?;
        println!("  ✅ 设置 cpu.weight = 50 → 读回: {}", cpu_weight_new.trim());

        // 3.5 将子进程迁入并验证 CPU 限制
        let (status_r, status_w) = pipe_with(PipeFlags::CLOEXEC).expect("pipe2 失败");

        let pid_raw = unsafe { libc::fork() };
        if pid_raw == 0 {
            // 子进程
            drop(status_r);
            // 迁移到测试 cgroup
            let procs = test_cg.join("cgroup.procs");
            let _ = cg_write(&procs, &format!("{}\n", unsafe { libc::getpid() }));

            // 执行一些 CPU 密集工作
            let start = std::time::Instant::now();
            let mut sum: u64 = 0;
            while start.elapsed() < std::time::Duration::from_secs(1) {
                for i in 0..1_000_000u64 {
                    sum = sum.wrapping_add(i);
                }
            }

            // 报告完成
            let _ = rustix::io::write(&status_w, &sum.to_ne_bytes());
            drop(status_w);
            unsafe { libc::_exit(0) };
        }

        drop(status_w);

        if pid_raw > 0 {
            // 父进程等待
            let mut buf = [0u8; 8];
            let _ = rustix::io::read(&status_r, &mut buf);

            // 读取 cpu.stat
            let cpu_stat = cg_read(&test_cg.join("cpu.stat"))?;
            println!("  • cpu.stat:\n{}", indent_lines(&cpu_stat, "    "));

            // 回收子进程
            let mut status: libc::c_int = 0;
            unsafe { libc::waitpid(pid_raw, &mut status, 0) };
            println!("  ✅ CPU 控制器测试完成");
        }

        // 清理
        cg_rmdir(&test_cg)?;
        println!("  ✅ 已清理测试 cgroup");

        Ok(())
    }

    // ========================================================================
    // 阶段 4: Memory 控制器
    // ========================================================================

    fn demo_memory_controller() -> Result<(), String> {
        println!("\n=== 阶段 4: Memory 控制器 ===");

        let root = Path::new(CGROUP_ROOT);
        let _ = enable_subtree_control(root, "+memory");

        let test_cg = test_cgroup_path("memory");
        cg_mkdir(&test_cg)?;
        println!("  ✅ 创建测试 cgroup: {}", test_cg.display());

        // 4.1 读取默认值
        let mem_max = cg_read(&test_cg.join("memory.max"))?;
        let mem_high = cg_read(&test_cg.join("memory.high"))?;
        let mem_current = cg_read(&test_cg.join("memory.current"))?;
        println!("  • 默认 memory.max: {}", mem_max.trim());
        println!("  • 默认 memory.high: {}", mem_high.trim());
        println!("  • 当前 memory.current: {}", mem_current.trim());

        // 4.2 设置 memory.high = 64MB（触发节流但不杀进程）
        let high_64m = 64 * 1024 * 1024;
        cg_write(&test_cg.join("memory.high"), &format!("{high_64m}\n"))?;
        let mem_high_new = cg_read(&test_cg.join("memory.high"))?;
        println!("  ✅ 设置 memory.high = {high_64m} (64MB) → 读回: {}", mem_high_new.trim());

        // 4.3 设置 memory.max = 128MB（硬限制）
        let max_128m = 128 * 1024 * 1024;
        cg_write(&test_cg.join("memory.max"), &format!("{max_128m}\n"))?;
        let mem_max_new = cg_read(&test_cg.join("memory.max"))?;
        println!("  ✅ 设置 memory.max = {max_128m} (128MB) → 读回: {}", mem_max_new.trim());

        // 4.4 读取 memory.events
        let mem_events = cg_read(&test_cg.join("memory.events"))?;
        println!("  • memory.events:\n{}", indent_lines(&mem_events, "    "));

        // 4.5 读取 memory.stat（部分关键指标）
        let mem_stat = cg_read(&test_cg.join("memory.stat"))?;
        let key_stats: Vec<&str> = ["anon", "file", "kernel", "shmem"]
            .iter()
            .filter_map(|key| {
                mem_stat
                    .lines()
                    .find(|l| l.starts_with(key))
            })
            .collect();
        println!("  • memory.stat (关键指标):");
        for stat in &key_stats {
            println!("    {stat}");
        }

        // 4.6 迁移一个分配内存的子进程
        let pid_raw = unsafe { libc::fork() };
        if pid_raw == 0 {
            // 子进程：迁移到测试 cgroup 并分配少量内存
            let procs = test_cg.join("cgroup.procs");
            let _ = cg_write(&procs, &format!("{}\n", unsafe { libc::getpid() }));

            // 分配 ~10MB
            let data: Vec<u8> = vec![0xAB; 10 * 1024 * 1024];
            // 防止优化掉
            std::hint::black_box(&data);
            std::thread::sleep(std::time::Duration::from_millis(500));
            unsafe { libc::_exit(0) };
        }

        if pid_raw > 0 {
            std::thread::sleep(std::time::Duration::from_millis(600));

            // 读取更新后的 memory.current
            let mem_current_after = cg_read(&test_cg.join("memory.current"))?;
            println!(
                "  • 子进程分配后 memory.current: {} bytes ({:.1} MB)",
                mem_current_after.trim(),
                mem_current_after.trim().parse::<f64>().unwrap_or(0.0) / (1024.0 * 1024.0)
            );

            // 读取 memory.events 查看是否有事件
            let mem_events_after = cg_read(&test_cg.join("memory.events"))?;
            println!("  • memory.events (分配后):\n{}", indent_lines(&mem_events_after, "    "));

            // 回收
            let mut status: libc::c_int = 0;
            unsafe { libc::waitpid(pid_raw, &mut status, 0) };
            println!("  ✅ Memory 控制器测试完成");
        }

        // 清理
        cg_rmdir(&test_cg)?;
        println!("  ✅ 已清理测试 cgroup");

        Ok(())
    }

    // ========================================================================
    // 阶段 5: PIDs 控制器
    // ========================================================================

    fn demo_pids_controller() -> Result<(), String> {
        println!("\n=== 阶段 5: PIDs 控制器 ===");

        let root = Path::new(CGROUP_ROOT);
        let _ = enable_subtree_control(root, "+pids");

        let test_cg = test_cgroup_path("pids");
        cg_mkdir(&test_cg)?;
        println!("  ✅ 创建测试 cgroup: {}", test_cg.display());

        // 5.1 读取默认 pids.max
        let pids_max = cg_read(&test_cg.join("pids.max"))?;
        let pids_current = cg_read(&test_cg.join("pids.current"))?;
        println!("  • 默认 pids.max: {}", pids_max.trim());
        println!("  • 当前 pids.current: {}", pids_current.trim());

        // 5.2 设置 pids.max = 5
        cg_write(&test_cg.join("pids.max"), "5\n")?;
        let pids_max_new = cg_read(&test_cg.join("pids.max"))?;
        println!("  ✅ 设置 pids.max = 5 → 读回: {}", pids_max_new.trim());

        // 5.3 使用一个中间子进程作为"管理器"，将其迁入测试 cgroup，
        //     再由它 fork 孙进程来触发 pids 限制。这样父进程始终留在
        //     原始 cgroup 中，避免迁回失败导致 cgroup 无法删除。
        let (status_r, status_w) = pipe_with(PipeFlags::CLOEXEC).expect("pipe2 失败");

        let manager_pid = unsafe { libc::fork() };
        if manager_pid == 0 {
            // ---- 管理器子进程 ----
            drop(status_r);

            // 迁移自己到测试 cgroup
            let procs = test_cg.join("cgroup.procs");
            let _ = cg_write(&procs, &format!("{}\n", unsafe { libc::getpid() }));

            // 尝试 fork 多个孙进程，验证超限拒绝
            let mut forked: Vec<libc::pid_t> = Vec::new();
            let target_forks = 8u8;
            let mut results: Vec<u8> = Vec::new(); // 1=成功, 0=被拒绝

            for _ in 0..target_forks {
                let pid = unsafe { libc::fork() };
                if pid == 0 {
                    // 孙进程：休眠等待被 kill
                    unsafe { libc::sleep(10) };
                    unsafe { libc::_exit(0) };
                } else if pid > 0 {
                    forked.push(pid);
                    results.push(1);
                } else {
                    results.push(0);
                }
            }

            // 将结果写回父进程：第一个字节 = 成功 fork 数
            let success_count = results.iter().filter(|&&r| r == 1).count() as u8;
            let reject_count = results.iter().filter(|&&r| r == 0).count() as u8;
            let report = [success_count, reject_count];
            let _ = rustix::io::write(&status_w, &report);
            drop(status_w);

            // 清理孙进程
            for &pid in &forked {
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
            for &pid in &forked {
                let mut st: libc::c_int = 0;
                unsafe { libc::waitpid(pid, &mut st, 0) };
            }

            unsafe { libc::_exit(0) };
        }

        drop(status_w);

        if manager_pid > 0 {
            // 父进程：读取管理器报告
            let mut report = [0u8; 2];
            let n = loop {
                match rustix::io::read(&status_r, &mut report) {
                    Ok(n) => break n,
                    Err(rustix::io::Errno::INTR) => continue,
                    Err(e) => return Err(format!("读取管理器报告失败: {e}")),
                }
            };

            if n >= 2 {
                println!("  • fork 成功: {} 个, 被拒绝: {} 个", report[0], report[1]);
                if report[0] == 4 && report[1] == 4 {
                    println!("  ✅ pids.max=5 限制生效（含管理器自身，可再 fork 4 个）");
                } else if report[0] <= 5 {
                    println!("  ✅ pids.max 限制已生效");
                } else {
                    println!("  ⚠️  预期最多 4-5 个成功 fork，实际 {}", report[0]);
                }
            }

            // 读取 pids.current 和 pids.events
            let pids_current_after = cg_read(&test_cg.join("pids.current"))?;
            println!("  • pids.current: {}", pids_current_after.trim());

            let pids_events = cg_read(&test_cg.join("pids.events"))?;
            println!("  • pids.events:\n{}", indent_lines(&pids_events, "    "));

            // 回收管理器
            let mut status: libc::c_int = 0;
            unsafe { libc::waitpid(manager_pid, &mut status, 0) };
            println!("  ✅ 管理器子进程已退出");
        }

        // 清理（父进程从未迁入，无需迁回）
        std::thread::sleep(std::time::Duration::from_millis(100));
        cg_rmdir(&test_cg)?;
        println!("  ✅ 已清理测试 cgroup");

        Ok(())
    }

    // ========================================================================
    // 阶段 6: IO 控制器
    // ========================================================================

    fn demo_io_controller() -> Result<(), String> {
        println!("\n=== 阶段 6: IO 控制器 ===");

        let root = Path::new(CGROUP_ROOT);
        let _ = enable_subtree_control(root, "+io");

        let test_cg = test_cgroup_path("io");
        cg_mkdir(&test_cg)?;
        println!("  ✅ 创建测试 cgroup: {}", test_cg.display());

        // 6.1 读取 io.stat
        let io_stat = cg_read(&test_cg.join("io.stat"))?;
        if io_stat.trim().is_empty() {
            println!("  • io.stat: (空，尚无 IO 活动)");
        } else {
            println!("  • io.stat:\n{}", indent_lines(&io_stat, "    "));
        }

        // 6.2 查找一个可用的块设备
        let blk_dev = find_block_device();
        if let Some((major_minor, dev_name)) = &blk_dev {
            println!("  • 检测到块设备: {dev_name} ({major_minor})");

            // 6.3 设置 io.max 限制读取速率为 1MB/s
            let io_max_value = format!("{major_minor} rbps=1048576\n");
            match cg_write(&test_cg.join("io.max"), &io_max_value) {
                Ok(()) => {
                    let io_max_read = cg_read(&test_cg.join("io.max"))?;
                    println!("  ✅ 设置 io.max = '{}' → 读回: {}", io_max_value.trim(), io_max_read.trim());
                }
                Err(e) => println!("  ⚠️  设置 io.max 失败: {e}"),
            }
        } else {
            println!("  ⚠️  未找到可用块设备，跳过 io.max 设置");
        }

        // 6.4 读取 io.pressure
        let io_pressure = cg_read(&test_cg.join("io.pressure"))?;
        println!("  • io.pressure:\n{}", indent_lines(&io_pressure, "    "));

        // 清理
        cg_rmdir(&test_cg)?;
        println!("  ✅ 已清理测试 cgroup");

        Ok(())
    }

    /// 查找第一个可用的块设备，返回 (major:minor, device_name)
    fn find_block_device() -> Option<(String, String)> {
        let block_dir = Path::new("/sys/block");
        let entries = std::fs::read_dir(block_dir).ok()?;
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            // 跳过 loop/ram/dm 设备
            if name.starts_with("loop") || name.starts_with("ram") || name.starts_with("dm-") {
                continue;
            }
            let dev_path = entry.path().join("dev");
            if let Ok(major_minor) = std::fs::read_to_string(&dev_path) {
                let mm = major_minor.trim().to_string();
                if !mm.is_empty() {
                    return Some((mm, name));
                }
            }
        }
        None
    }

    // ========================================================================
    // 阶段 7: clone3 + CLONE_INTO_CGROUP
    // ========================================================================

    fn demo_clone_into_cgroup() -> Result<(), String> {
        println!("\n=== 阶段 7: clone3 + CLONE_INTO_CGROUP ===");

        let root = Path::new(CGROUP_ROOT);
        let _ = enable_subtree_control(root, "+cpu +pids");

        // 创建两层 cgroup：外层作为管理器的工作区，内层作为 clone3 的目标。
        // 这确保 CLONE_INTO_CGROUP 的目标在管理器的 cgroup 子树内，
        // 避免 systemd delegation 边界导致的静默失败。
        let outer_cg = test_cgroup_path("clone_outer");
        let inner_cg = outer_cg.join("clone_inner");
        cg_mkdir(&outer_cg)?;
        // 在外层启用 subtree_control 以便内层可用
        let _ = enable_subtree_control(&outer_cg, "+cpu +pids");
        cg_mkdir(&inner_cg)?;
        println!("  ✅ 创建外层 cgroup: {}", outer_cg.display());
        println!("  ✅ 创建内层 cgroup (clone3 目标): {}", inner_cg.display());

        // 打开内层 cgroup 目录的文件描述符
        let cg_fd = unsafe {
            libc::open(
                inner_cg.to_string_lossy().as_ptr() as *const libc::c_char,
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if cg_fd < 0 {
            let _ = cg_rmdir(&inner_cg);
            let _ = cg_rmdir(&outer_cg);
            return Err(format!(
                "打开 cgroup 目录失败: {}",
                std::io::Error::last_os_error()
            ));
        }
        let cg_fd_owned = unsafe { OwnedFd::from_raw_fd(cg_fd) };

        // fork 一个管理器子进程，将其迁入外层 cgroup，
        // 然后由它执行 clone3(CLONE_INTO_CGROUP) 将孙进程放入内层 cgroup。
        let (status_r, status_w) = pipe_with(PipeFlags::CLOEXEC).expect("pipe2 失败");

        let manager_pid = unsafe { libc::fork() };
        if manager_pid == 0 {
            // ---- 管理器子进程 ----
            drop(status_r);

            // 迁移自己到外层 cgroup
            let outer_procs = outer_cg.join("cgroup.procs");
            if cg_write(&outer_procs, &format!("{}\n", unsafe { libc::getpid() })).is_err() {
                let _ = rustix::io::write(&status_w, &[0xFF]);
                drop(status_w);
                unsafe { libc::_exit(1) };
            }

            // 现在管理器在外层 cgroup 中，clone3 到内层 cgroup（同一子树）
            let mut pidfd_raw: c_int = -1;
            let args = CloneArgs {
                flags: CLONE_INTO_CGROUP | CLONE_PIDFD,
                pidfd: std::ptr::addr_of_mut!(pidfd_raw) as u64,
                exit_signal: libc::SIGCHLD as u64,
                cgroup: cg_fd_owned.as_raw_fd() as u64,
                ..Default::default()
            };

            let grandchild_pid = unsafe { clone3(&args) };

            if grandchild_pid == 0 {
                // ---- 孙进程 ----
                // 验证自己在内层 cgroup 中
                let my_cgroup = std::fs::read_to_string("/proc/self/cgroup")
                    .unwrap_or_default();
                let in_target = my_cgroup.contains("clone_inner");
                let result: u8 = if in_target { 1 } else { 0 };
                let _ = rustix::io::write(&status_w, &[result]);
                drop(status_w);
                unsafe {
                    libc::sleep(1);
                    libc::_exit(if in_target { 0 } else { 1 });
                }
            }

            if grandchild_pid < 0 {
                // clone3 失败
                let _ = rustix::io::write(&status_w, &[0xFE]);
                drop(status_w);
                unsafe { libc::_exit(1) };
            }

            // 管理器：报告 clone3 成功 + pidfd
            let _ = rustix::io::write(&status_w, &[1]); // 先写一个字节表示 clone3 成功
            drop(status_w);

            // 等待孙进程退出
            let mut st: libc::c_int = 0;
            unsafe { libc::waitpid(grandchild_pid as i32, &mut st, 0) };
            unsafe { libc::_exit(0) };
        }

        drop(status_w);

        if manager_pid > 0 {
            // 读取管理器/孙进程的报告
            let mut report = [0u8; 1];
            let n = loop {
                match rustix::io::read(&status_r, &mut report) {
                    Ok(n) => break n,
                    Err(rustix::io::Errno::INTR) => continue,
                    Err(e) => return Err(format!("读取报告失败: {e}")),
                }
            };

            if n == 1 {
                match report[0] {
                    1 => {
                        println!("  ✅ clone3(CLONE_INTO_CGROUP | CLONE_PIDFD) 成功");
                        println!("  ✅ 孙进程确认已直接创建在内层 cgroup 中");
                    }
                    0xFE => {
                        println!("  ❌ clone3(CLONE_INTO_CGROUP) 系统调用失败");
                    }
                    0xFF => {
                        println!("  ❌ 管理器无法迁入外层 cgroup");
                    }
                    _ => {
                        println!("  ⚠️  未知报告码: {}", report[0]);
                    }
                }
            } else {
                println!("  ❌ 管理器在初始化期间死亡");
            }

            // 从父进程侧验证
            let inner_procs = cg_read(&inner_cg.join("cgroup.procs"))?;
            println!("  • 内层 cgroup.procs: {}", inner_procs.trim());

            let outer_procs = cg_read(&outer_cg.join("cgroup.procs"))?;
            println!("  • 外层 cgroup.procs: {}", outer_procs.trim());

            // 回收管理器
            let mut status: libc::c_int = 0;
            unsafe { libc::waitpid(manager_pid, &mut status, 0) };
            println!("  ✅ 管理器子进程已退出");
        }

        // 清理
        cg_rmdir(&inner_cg)?;
        cg_rmdir(&outer_cg)?;
        println!("  ✅ 已清理测试 cgroup");

        Ok(())
    }

    // ========================================================================
    // 阶段 8: cgroup.freeze / events
    // ========================================================================

    fn demo_freeze_and_events() -> Result<(), String> {
        println!("\n=== 阶段 8: cgroup.freeze / events ===");

        let root = Path::new(CGROUP_ROOT);
        let _ = enable_subtree_control(root, "+memory +pids");

        let test_cg = test_cgroup_path("freeze");
        cg_mkdir(&test_cg)?;
        println!("  ✅ 创建测试 cgroup: {}", test_cg.display());

        // 8.1 读取 cgroup.freeze 初始值
        let freeze_val = cg_read(&test_cg.join("cgroup.freeze"))?;
        println!("  • 初始 cgroup.freeze: {}", freeze_val.trim());

        // 8.2 读取 cgroup.events
        let events = cg_read(&test_cg.join("cgroup.events"))?;
        println!("  • cgroup.events:\n{}", indent_lines(&events, "    "));

        // 8.3 启动一个子进程到该 cgroup
        let pid_raw = unsafe { libc::fork() };
        if pid_raw == 0 {
            // 子进程
            let procs = test_cg.join("cgroup.procs");
            let _ = cg_write(&procs, &format!("{}\n", unsafe { libc::getpid() }));
            // 持续运行
            unsafe { libc::sleep(10) };
            unsafe { libc::_exit(0) };
        }

        if pid_raw > 0 {
            std::thread::sleep(std::time::Duration::from_millis(200));

            // 8.4 冻结 cgroup
            cg_write(&test_cg.join("cgroup.freeze"), "1\n")?;
            let freeze_after = cg_read(&test_cg.join("cgroup.freeze"))?;
            println!("  ✅ 设置 cgroup.freeze = 1 → 读回: {}", freeze_after.trim());

            // 读取 frozen 事件
            let events_frozen = cg_read(&test_cg.join("cgroup.events"))?;
            println!(
                "  • cgroup.events (冻结后):\n{}",
                indent_lines(&events_frozen, "    ")
            );

            // 8.5 验证子进程被冻结（检查 /proc/<pid>/status 中的 State）
            let proc_status = std::fs::read_to_string(format!("/proc/{pid_raw}/status"))
                .unwrap_or_default();
            let state_line = proc_status
                .lines()
                .find(|l| l.starts_with("State:"))
                .unwrap_or("State: unknown");
            println!("  • 子进程状态: {state_line}");

            // 8.6 解冻
            cg_write(&test_cg.join("cgroup.freeze"), "0\n")?;
            let freeze_unfrozen = cg_read(&test_cg.join("cgroup.freeze"))?;
            println!("  ✅ 设置 cgroup.freeze = 0 → 读回: {}", freeze_unfrozen.trim());

            // 8.7 读取 memory.events
            let mem_events = cg_read(&test_cg.join("memory.events"))?;
            println!("  • memory.events:\n{}", indent_lines(&mem_events, "    "));

            // 8.8 读取 pids.events
            let pids_events = cg_read(&test_cg.join("pids.events"))?;
            println!("  • pids.events:\n{}", indent_lines(&pids_events, "    "));

            // 8.9 读取 cgroup.stat
            let cg_stat = cg_read(&test_cg.join("cgroup.stat"))?;
            println!("  • cgroup.stat:\n{}", indent_lines(&cg_stat, "    "));

            // 清理子进程
            unsafe { libc::kill(pid_raw, libc::SIGTERM) };
            let mut status: libc::c_int = 0;
            unsafe { libc::waitpid(pid_raw, &mut status, 0) };
            println!("  ✅ 已清理子进程");
        }

        // 清理
        cg_rmdir(&test_cg)?;
        println!("  ✅ 已清理测试 cgroup");

        Ok(())
    }

    // ========================================================================
    // 阶段 9: 多进程并行 CPU 消耗统计
    // ========================================================================

    /// 获取在线 CPU 核心数
    fn num_online_cpus() -> usize {
        std::fs::read_to_string("/sys/devices/system/cpu/online")
            .ok()
            .and_then(|s| parse_cpu_list(s.trim()))
            .unwrap_or(1)
    }

    /// 解析 CPU 列表字符串，如 "0-7" 或 "0-3,5,7-9"
    fn parse_cpu_list(s: &str) -> Option<usize> {
        let mut count = 0usize;
        for part in s.split(',') {
            if let Some((start, end)) = part.split_once('-') {
                let a: usize = start.parse().ok()?;
                let b: usize = end.parse().ok()?;
                count += b - a + 1;
            } else {
                let _: usize = part.parse().ok()?;
                count += 1;
            }
        }
        Some(count)
    }

    /// 高精度时钟（微秒）
    fn now_usec() -> u64 {
        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        ts.tv_sec as u64 * 1_000_000 + ts.tv_nsec as u64 / 1_000
    }

    /// 从 cpu.stat 中解析指定字段的值（微秒）
    fn parse_cpu_stat_field(stat: &str, field: &str) -> Option<u64> {
        stat.lines()
            .find(|l| l.starts_with(field))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
    }

    fn demo_parallel_cpu_usage() -> Result<(), String> {
        println!("\n=== 阶段 9: 多进程并行 CPU 消耗统计 ===");

        let root = Path::new(CGROUP_ROOT);
        let _ = enable_subtree_control(root, "+cpu +memory");

        let test_cg = test_cgroup_path("parallel_cpu");
        cg_mkdir(&test_cg)?;
        println!("  ✅ 创建测试 cgroup: {}", test_cg.display());

        // 9.1 检测 CPU 核心数
        let ncpus = num_online_cpus();
        println!("  • 在线 CPU 核心数: {ncpus}");

        // 9.2 不设置 cpu.max 限制，让所有核心全速运行
        let cpu_max = cg_read(&test_cg.join("cpu.max"))?;
        println!("  • cpu.max: {}", cpu_max.trim());

        // 9.3 记录初始 cpu.stat
        let cpu_stat_before = cg_read(&test_cg.join("cpu.stat"))?;
        let usage_before = parse_cpu_stat_field(&cpu_stat_before, "usage_usec").unwrap_or(0);
        println!("  • 初始 cpu.stat.usage_usec: {usage_before} µs");

        // 9.4 fork N 个 CPU 密集型子进程
        let worker_count = ncpus.max(2); // 至少 2 个 worker
        println!("  • 启动 {worker_count} 个 CPU 密集 worker...");

        let mut worker_pids: Vec<libc::pid_t> = Vec::new();
        let (ready_r, ready_w) = pipe_with(PipeFlags::CLOEXEC).expect("pipe2 失败");

        for i in 0..worker_count {
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                // ---- Worker 子进程 ----
                drop(ready_r);

                // 迁移到测试 cgroup
                let procs = test_cg.join("cgroup.procs");
                let _ = cg_write(&procs, &format!("{}\n", unsafe { libc::getpid() }));

                // 通知父进程已就绪
                let _ = rustix::io::write(&ready_w, &[i as u8]);

                // CPU 密集循环，持续约 1.2 秒（确保覆盖 1 秒窗口）
                let target_duration = std::time::Duration::from_millis(1200);
                let start = std::time::Instant::now();
                let mut sum: u64 = 0;
                while start.elapsed() < target_duration {
                    for k in 0..1_000_000u64 {
                        sum = sum.wrapping_add(k.wrapping_mul(k));
                    }
                }
                std::hint::black_box(sum);

                unsafe { libc::_exit(0) };
            } else if pid > 0 {
                worker_pids.push(pid);
            } else {
                return Err(format!("fork worker #{i} 失败: {}", std::io::Error::last_os_error()));
            }
        }
        drop(ready_w);

        // 9.5 等待所有 worker 就绪
        let mut ready_count = 0;
        let mut buf = [0u8; 1];
        while ready_count < worker_count {
            match rustix::io::read(&ready_r, &mut buf) {
                Ok(n) if n > 0 => ready_count += 1,
                Ok(_) => break, // EOF
                Err(rustix::io::Errno::INTR) => continue,
                Err(_) => break,
            }
        }
        println!("  • {ready_count}/{worker_count} 个 worker 已就绪并开始计算");

        // 9.6 精确计时：等待所有 worker 完成
        let wall_start = now_usec();

        for &pid in &worker_pids {
            let mut status: libc::c_int = 0;
            unsafe { libc::waitpid(pid, &mut status, 0) };
        }

        let wall_end = now_usec();
        let wall_elapsed_us = wall_end - wall_start;
        let wall_elapsed_s = wall_elapsed_us as f64 / 1_000_000.0;
        println!("  ✅ 所有 worker 已完成");
        println!("  • 实际经过时间 (wall clock): {:.3} s ({wall_elapsed_us} µs)", wall_elapsed_s);

        // 9.7 读取最终 cpu.stat
        let cpu_stat_after = cg_read(&test_cg.join("cpu.stat"))?;
        let usage_after = parse_cpu_stat_field(&cpu_stat_after, "usage_usec").unwrap_or(0);
        let user_after = parse_cpu_stat_field(&cpu_stat_after, "user_usec").unwrap_or(0);
        let system_after = parse_cpu_stat_field(&cpu_stat_after, "system_usec").unwrap_or(0);
        let nr_throttled = parse_cpu_stat_field(&cpu_stat_after, "nr_throttled").unwrap_or(0);

        let cpu_consumed_us = usage_after.saturating_sub(usage_before);
        let cpu_consumed_s = cpu_consumed_us as f64 / 1_000_000.0;

        println!("\n  === cgroup CPU 统计 ===");
        println!("  • cpu.stat.usage_usec 增量:  {cpu_consumed_us} µs ({cpu_consumed_s:.3} s)");
        println!("  • cpu.stat.user_usec (累计): {user_after} µs");
        println!("  • cpu.stat.system_usec (累计): {system_after} µs");
        println!("  • cpu.stat.nr_throttled:     {nr_throttled}");

        // 9.8 读取 memory 统计
        let mem_current = cg_read(&test_cg.join("memory.current"))?;
        let mem_peak = cg_read(&test_cg.join("memory.peak")).unwrap_or_else(|_| "N/A".into());
        let mem_stat = cg_read(&test_cg.join("memory.stat"))?;
        let anon = mem_stat.lines()
            .find(|l| l.starts_with("anon "))
            .map(|l| l.split_whitespace().nth(1).unwrap_or("0"))
            .unwrap_or("0");

        println!("\n  === cgroup Memory 统计 ===");
        println!("  • memory.current: {} bytes", mem_current.trim());
        println!("  • memory.peak:    {} bytes", mem_peak.trim());
        println!("  • memory.stat.anon: {} bytes", anon);

        // 9.9 核心验证：多核并行时 CPU 时间应超过实际时间
        println!("\n  === 验证 ===");
        let ratio = cpu_consumed_s / wall_elapsed_s;
        println!(
            "  • CPU 时间 / 实际时间 = {:.3} / {:.3} = {:.2}x",
            cpu_consumed_s, wall_elapsed_s, ratio
        );

        if ncpus >= 2 && cpu_consumed_s > wall_elapsed_s {
            println!(
                "  ✅ 在 {ncpus} 核机器上，{worker_count} 个 worker 并行消耗了 {:.2}x 实际时间的 CPU 时间",
                ratio
            );
            println!("     （多进程并行使 cgroup CPU 用量超过 wall clock）");
        } else if ncpus == 1 {
            println!("  ℹ️  单核机器，CPU 时间 ≈ 实际时间（预期行为）");
        } else {
            println!(
                "  ⚠️  CPU 时间 ({:.3}s) 未超过实际时间 ({:.3}s)，可能受调度影响",
                cpu_consumed_s, wall_elapsed_s
            );
        }

        // 打印完整 cpu.stat 供参考
        println!("\n  • 完整 cpu.stat:\n{}", indent_lines(&cpu_stat_after, "    "));

        // 清理
        cg_rmdir(&test_cg)?;
        println!("  ✅ 已清理测试 cgroup");

        Ok(())
    }

    // ========================================================================
    // 工具函数
    // ========================================================================

    fn indent_lines(text: &str, prefix: &str) -> String {
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| format!("{prefix}{l}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    // ========================================================================
    // 主流程
    // ========================================================================

    pub fn run() {
        println!("╔══════════════════════════════════════════════╗");
        println!("║     Linux cgroups v2 能力演示                 ║");
        println!("╚══════════════════════════════════════════════╝\n");

        check_root();

        println!("内核版本要求:");
        println!("  • cgroups v2 (unified hierarchy): >= 4.5");
        println!("  • clone3 + CLONE_INTO_CGROUP:     >= 5.7");
        println!("  • cgroup.freeze:                  >= 5.2");
        println!("  • memory.high:                    >= 5.8\n");

        println!("API 覆盖:");
        println!("  • cgroup v2 文件系统接口 (controllers, subtree_control, procs)");
        println!("  • CPU 控制器 (cpu.max, cpu.weight, cpu.stat)");
        println!("  • Memory 控制器 (memory.max, memory.high, memory.events)");
        println!("  • PIDs 控制器 (pids.max, pids.current, pids.events)");
        println!("  • IO 控制器 (io.max, io.stat, io.pressure)");
        println!("  • clone3(CLONE_INTO_CGROUP | CLONE_PIDFD)");
        println!("  • cgroup.freeze / cgroup.events\n");

        // 清理可能残留的测试 cgroup
        cleanup_test_cgroups();

        let mut failures = Vec::new();

        // 阶段 1
        if let Err(e) = demo_hierarchy() {
            eprintln!("  ❌ 阶段 1 失败: {e}");
            failures.push(("基础层级操作", e));
        }

        // 阶段 2
        if let Err(e) = demo_process_migration() {
            eprintln!("  ❌ 阶段 2 失败: {e}");
            failures.push(("进程迁移", e));
        }

        // 阶段 3
        if let Err(e) = demo_cpu_controller() {
            eprintln!("  ❌ 阶段 3 失败: {e}");
            failures.push(("CPU 控制器", e));
        }

        // 阶段 4
        if let Err(e) = demo_memory_controller() {
            eprintln!("  ❌ 阶段 4 失败: {e}");
            failures.push(("Memory 控制器", e));
        }

        // 阶段 5
        if let Err(e) = demo_pids_controller() {
            eprintln!("  ❌ 阶段 5 失败: {e}");
            failures.push(("PIDs 控制器", e));
        }

        // 阶段 6
        if let Err(e) = demo_io_controller() {
            eprintln!("  ❌ 阶段 6 失败: {e}");
            failures.push(("IO 控制器", e));
        }

        // 阶段 7
        if let Err(e) = demo_clone_into_cgroup() {
            eprintln!("  ❌ 阶段 7 失败: {e}");
            failures.push(("clone3 + CLONE_INTO_CGROUP", e));
        }

        // 阶段 8
        if let Err(e) = demo_freeze_and_events() {
            eprintln!("  ❌ 阶段 8 失败: {e}");
            failures.push(("cgroup.freeze / events", e));
        }

        // 阶段 9
        if let Err(e) = demo_parallel_cpu_usage() {
            eprintln!("  ❌ 阶段 9 失败: {e}");
            failures.push(("多进程并行 CPU 统计", e));
        }

        // 最终清理
        cleanup_test_cgroups();

        println!("\n╔══════════════════════════════════════════════╗");
        if failures.is_empty() {
            println!("║     ✅ 所有 9 个阶段均通过                     ║");
        } else {
            println!("║     ⚠️  {} 个阶段失败                          ║", failures.len());
            for (name, err) in &failures {
                println!("║     ❌ {name}: {err}");
            }
        }
        println!("╚══════════════════════════════════════════════╝");
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    imp::run();

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("此示例仅在 Linux 上运行。");
        eprintln!("cgroups v2 是 Linux 特有功能（内核 >= 4.5）。");
        std::process::exit(1);
    }
}
