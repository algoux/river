//! Linux pivot_root 系统调用能力演示。
//!
//! 演示完整的容器化根文件系统切换流程：
//!   1. clone3(CLONE_NEWNS | CLONE_NEWPID) 创建新的 mount + PID namespace
//!   2. 在新 namespace 中挂载 tmpfs 作为新根目录
//!   3. 在新根中创建必要的子目录 (/proc, /dev, /.oldroot)
//!   4. 调用 pivot_root 切换根文件系统
//!   5. umount2(MNT_DETACH) 卸载旧根
//!   6. 验证隔离性：检查 /、/proc、进程 PID
//!
//! pivot_root(new_root, put_old) 的语义：
//!   - new_root: 必须是当前 namespace 中的一个挂载点
//!   - put_old: 必须在 new_root 之下，旧根会被移动到这里
//!   - 调用后进程的 cwd 不变，但 / 指向 new_root
//!   - 通常需要配合 chdir("/") 和 umount2(put_old, MNT_DETACH)
//!
//! 要求：必须以 root (CAP_SYS_ADMIN) 运行。
//!
//! API 覆盖：
//!   • clone3 原始系统调用（CLONE_NEWNS + CLONE_NEWPID）
//!   • libc: mount, umount2, pivot_root (via syscall), mkdir, chdir
//!   • rustix: pipe (CLOEXEC 握手), process (waitid)

#[cfg(target_os = "linux")]
mod imp {
    use rustix::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
    use rustix::pipe::{PipeFlags, pipe_with};
    use rustix::process::{Pid, WaitId, WaitidOptions, waitid};
    use std::os::raw::c_int;

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

    const CLONE_NEWPID: u64 = 0x2000_0000;
    const CLONE_NEWNS: u64 = 0x0002_0000;
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
            eprintln!("   用法: sudo cargo run --example linux_pivot_root");
            std::process::exit(1);
        }
    }

    /// 读取 /proc/self/ns/<ns_type> 的 inode 号
    fn read_ns_inode(ns_type: &str) -> Option<u64> {
        let path = format!("/proc/self/ns/{ns_type}");
        std::fs::read_link(&path).ok().and_then(|link| {
            let s = link.to_string_lossy();
            s.split(':')
                .nth(1)
                .and_then(|n| n.trim_end_matches(']').parse().ok())
        })
    }

    // ========================================================================
    // pivot_root 核心逻辑（在子进程中执行）
    // ========================================================================

    /// 子进程入口：执行完整的 pivot_root 流程
    fn child_pivot_root_entry(status_w: OwnedFd) -> ! {
        let result = match do_pivot_root_work() {
            Ok(()) => 0i32,
            Err(errno) => errno,
        };

        let _ = rustix::io::write(&status_w, &result.to_ne_bytes());
        drop(status_w);

        // 保持存活供父进程检查 /proc
        unsafe {
            libc::sleep(3);
            libc::_exit(if result == 0 { 0 } else { 1 });
        }
    }

    /// 完整的 pivot_root 工作流程
    fn do_pivot_root_work() -> Result<(), i32> {
        println!("  [child] === pivot_root 流程开始 ===");

        // ---- 步骤 1: 准备新根目录并挂载 tmpfs ----
        // pivot_root 要求 new_root 是一个挂载点，所以我们需要
        // 先创建一个目录，然后将 tmpfs 挂载到它上面
        // 关键：必须在 mount --make-rprivate 之前完成挂载，否则在某些环境下
        // （如 WSL overlay）路径可能变得不可访问
        let new_root = "/mnt/pivot_newroot";
        println!("  [child] 步骤 1: 准备新根目录 {new_root}");

        // 确保 /mnt 存在
        let c_mnt = std::ffi::CString::new("/mnt").unwrap();
        unsafe { libc::mkdir(c_mnt.as_ptr(), 0o755) }; // 忽略错误，可能已存在

        // 创建新根目录
        let c_new_root = std::ffi::CString::new(new_root).unwrap();
        if unsafe { libc::mkdir(c_new_root.as_ptr(), 0o755) } != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EEXIST) {
                println!("  [child] ❌ mkdir {new_root} 失败: {err}");
                return Err(err.raw_os_error().unwrap_or(-1));
            }
        }
        println!("  [child] ✅ 新根目录已创建");

        // 立即挂载 tmpfs 到新根目录（在 make-rprivate 之前）
        println!("  [child] 步骤 1b: 挂载 tmpfs 到 {new_root}");
        let ret = unsafe {
            libc::mount(
                c"tmpfs".as_ptr(),
                c_new_root.as_ptr(),
                c"tmpfs".as_ptr(),
                0,
                c"size=64M".as_ptr() as *const libc::c_void,
            )
        };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            println!("  [child] ❌ mount tmpfs {new_root} 失败: {err}");
            return Err(err.raw_os_error().unwrap_or(-1));
        }
        println!("  [child] ✅ tmpfs 已挂载到 {new_root}");

        // ---- 步骤 2: 使挂载事件变为私有 ----
        // 避免挂载传播到父 namespace
        println!("  [child] 步骤 2: mount --make-rprivate /");
        let ret = unsafe {
            libc::mount(
                c"none".as_ptr(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            )
        };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            println!("  [child] ⚠️  mount --make-rprivate / 失败: {err}");
            return Err(err.raw_os_error().unwrap_or(-1));
        }
        println!("  [child] ✅ mount propagation 设为 private");

        // ---- 步骤 3: 在新根中创建必要目录 ----
        println!("  [child] 步骤 3: 创建新根内的子目录");
        let subdirs = ["/proc", "/dev", "/.oldroot"];
        for subdir in &subdirs {
            let full_path = format!("{new_root}{subdir}");
            let c_path = std::ffi::CString::new(full_path.as_str()).unwrap();
            if unsafe { libc::mkdir(c_path.as_ptr(), 0o755) } != 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::EEXIST) {
                    println!("  [child] ⚠️  mkdir {full_path} 失败: {err}");
                }
            }
        }
        println!("  [child] ✅ 子目录创建完成: {:?}", subdirs);

        // ---- 步骤 4: 调用 pivot_root ----
        println!("  [child] 步骤 4: 调用 pivot_root");
        let old_root_in_new = format!("{new_root}/.oldroot");
        let c_new_root = std::ffi::CString::new(new_root).unwrap();
        let c_old_root = std::ffi::CString::new(old_root_in_new.as_str()).unwrap();

        let ret = unsafe {
            libc::syscall(
                libc::SYS_pivot_root,
                c_new_root.as_ptr(),
                c_old_root.as_ptr(),
            )
        };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            println!("  [child] ❌ pivot_root(\"{new_root}\", \"{old_root_in_new}\") 失败: {err}");
            return Err(err.raw_os_error().unwrap_or(-1));
        }
        println!("  [child] ✅ pivot_root 成功！");

        // ---- 步骤 5: chdir 到新根 ----
        println!("  [child] 步骤 5: chdir(\"/\")");
        if unsafe { libc::chdir(c"/".as_ptr()) } != 0 {
            let err = std::io::Error::last_os_error();
            println!("  [child] ❌ chdir(/) 失败: {err}");
            return Err(err.raw_os_error().unwrap_or(-1));
        }
        println!("  [child] ✅ 当前工作目录已切换到新根");

        // ---- 步骤 6: umount2 卸载旧根 ----
        println!("  [child] 步骤 6: umount2(\"/.oldroot\", MNT_DETACH)");
        let ret = unsafe { libc::umount2(c"/.oldroot".as_ptr(), libc::MNT_DETACH) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            println!("  [child] ❌ umount2 /.oldroot 失败: {err}");
            return Err(err.raw_os_error().unwrap_or(-1));
        }
        println!("  [child] ✅ 旧根已卸载");

        // 删除旧根挂载点目录
        unsafe {
            libc::rmdir(c"/.oldroot".as_ptr());
        }

        // ---- 步骤 7: 验证隔离性 ----
        println!("  [child] 步骤 7: 验证隔离性");
        verify_isolation()?;

        println!("  [child] === pivot_root 流程完成 ===");
        Ok(())
    }

    /// 验证 pivot_root 后的隔离性
    fn verify_isolation() -> Result<(), i32> {
        // 验证 1: 检查根目录内容
        println!("  [child] 验证 1: 检查根目录内容");
        match std::fs::read_dir("/") {
            Ok(entries) => {
                let names: Vec<String> = entries
                    .filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .collect();
                println!("  [child]   / 目录内容: {:?}", names);

                // 新根应该只有我们创建的目录 (proc, dev)
                // 不应该有 host 的文件系统 (etc, usr, var 等)
                let has_host_dirs = names
                    .iter()
                    .any(|n| matches!(n.as_str(), "etc" | "usr" | "var" | "home" | "bin" | "lib"));
                if has_host_dirs {
                    println!("  [child] ⚠️  根目录仍包含宿主文件系统目录！");
                } else {
                    println!("  [child] ✅ 根目录已隔离，不含宿主文件系统");
                }
            }
            Err(e) => {
                println!("  [child] ⚠️  无法读取根目录: {e}");
            }
        }

        // 验证 2: 检查 PID（应该是新 PID namespace 中的 PID 1）
        println!("  [child] 验证 2: 检查 PID namespace");
        let pid = unsafe { libc::getpid() };
        println!("  [child]   getpid() = {pid}");
        if pid == 1 {
            println!("  [child] ✅ 在新 PID namespace 中为 init (PID=1)");
        } else {
            println!("  [child] ℹ️  PID={pid}（非 1，但仍在新 namespace 中）");
        }

        // 验证 3: 挂载 procfs 并检查
        println!("  [child] 验证 3: 挂载 /proc 并检查");
        let ret = unsafe {
            libc::mount(
                c"proc".as_ptr(),
                c"/proc".as_ptr(),
                c"proc".as_ptr(),
                0,
                std::ptr::null(),
            )
        };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            println!("  [child] ⚠️  mount /proc 失败: {err}");
        } else {
            println!("  [child] ✅ /proc 已挂载");

            // 读取 /proc/self/status 验证
            if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
                for line in status.lines().take(5) {
                    println!("  [child]   /proc/self/status: {line}");
                }
            }

            // 列出 /proc 下可见的进程
            if let Ok(entries) = std::fs::read_dir("/proc") {
                let pids: Vec<String> = entries
                    .filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .filter(|n| n.chars().all(|c| c.is_ascii_digit()))
                    .collect();
                println!("  [child]   /proc 中可见的 PID: {:?}", pids);
                if pids.len() <= 2 {
                    println!("  [child] ✅ PID namespace 隔离良好（仅少量进程可见）");
                }
            }
        }

        // 验证 4: 写入测试文件
        println!("  [child] 验证 4: 在新根中写入测试文件");
        match std::fs::write("/test_marker.txt", "pivot_root_test_ok") {
            Ok(()) => {
                println!("  [child] ✅ 成功写入 /test_marker.txt");
                if let Ok(content) = std::fs::read_to_string("/test_marker.txt") {
                    println!("  [child]   内容: {content}");
                }
                let _ = std::fs::remove_file("/test_marker.txt");
            }
            Err(e) => {
                println!("  [child] ⚠️  写入测试文件失败: {e}");
            }
        }

        Ok(())
    }

    // ========================================================================
    // 父进程侧握手与等待
    // ========================================================================

    fn await_child_ready(status_r: &OwnedFd, pid: i32) {
        let mut buf = [0u8; 4];
        let n = loop {
            match rustix::io::read(status_r, &mut buf) {
                Ok(n) => break n,
                Err(rustix::io::Errno::INTR) => continue,
                Err(e) => panic!("读取状态失败: {e}"),
            }
        };

        match n {
            0 => {
                eprintln!("  ❌ 子进程在初始化期间死亡（EOF）");
                std::process::exit(1);
            }
            4 => {
                let errno = i32::from_ne_bytes(buf);
                if errno != 0 {
                    eprintln!(
                        "  ❌ 子进程初始化失败: {}",
                        std::io::Error::from_raw_os_error(errno)
                    );
                    std::process::exit(1);
                }
            }
            _ => panic!("状态管道短读: {n} / 4 字节"),
        }

        // 从 /proc 验证 namespace 信息
        print_proc_ns_info(pid);
    }

    fn print_proc_ns_info(pid: i32) {
        let ns_dir = format!("/proc/{pid}/ns");
        let parent_ns_dir = "/proc/self/ns";

        let ns_types = ["pid", "mnt"];
        let mut diffs = Vec::new();

        for ns in &ns_types {
            let child_link = std::fs::read_link(format!("{ns_dir}/{ns}")).ok();
            let parent_link = std::fs::read_link(format!("{parent_ns_dir}/{ns}")).ok();
            if child_link != parent_link {
                diffs.push(*ns);
            }
        }

        if !diffs.is_empty() {
            println!(
                "  • /proc/{pid}/ns 确认: 以下 namespace 与父进程不同: {:?}",
                diffs
            );
        } else {
            println!("  ⚠️  /proc/{pid}/ns 未检测到 namespace 差异");
        }
    }

    fn wait_for_child(pidfd: &OwnedFd, _child_pid: Pid) {
        println!("  等待子进程退出...");
        match waitid(WaitId::PidFd(pidfd.as_fd()), WaitidOptions::EXITED) {
            Ok(Some(status)) => {
                if status.exited() {
                    let code = status.exit_status().unwrap_or(0);
                    if code == 0 {
                        println!("  ✅ 子进程正常退出 (code=0)");
                    } else {
                        println!("  ⚠️  子进程退出码={code}");
                    }
                } else if status.killed() {
                    println!(
                        "  ⚠️  子进程被信号 {} 终止",
                        status.terminating_signal().unwrap_or(0)
                    );
                }
            }
            Ok(None) => println!("  ⚠️  waitid 返回 None"),
            Err(e) => eprintln!("  ❌ waitid 失败: {e:?}"),
        }
    }

    // ========================================================================
    // 主流程
    // ========================================================================

    pub fn run() {
        println!("╔══════════════════════════════════════════════╗");
        println!("║     Linux pivot_root 能力演示                 ║");
        println!("╚══════════════════════════════════════════════╝\n");

        check_root();

        println!("内核版本要求:");
        println!("  • clone3:               >= 5.3");
        println!("  • pivot_root:           >= 2.3.41");
        println!("  • Mount namespace:      >= 2.4.19");
        println!("  • PID namespace:        >= 2.6.24\n");

        println!("API 覆盖:");
        println!("  • clone3(CLONE_NEWNS | CLONE_NEWPID | CLONE_PIDFD)");
        println!("  • pivot_root 系统调用 (via libc::syscall)");
        println!("  • mount (tmpfs, proc, MS_PRIVATE)");
        println!("  • umount2(MNT_DETACH)");
        println!("  • CLOEXEC 状态管道握手协议\n");

        // 记录父进程的 namespace inode 用于对比
        println!("=== 父进程 Namespace Inodes ===");
        for ns in &["pid", "mnt"] {
            if let Some(inode) = read_ns_inode(ns) {
                println!("  {ns:>5}: [{inode}]");
            }
        }
        println!();

        // 清理可能残留的测试目录
        let _ = std::fs::remove_dir_all("/mnt/pivot_newroot");

        // 执行 pivot_root 测试
        println!("=== pivot_root 完整流程测试 ===");

        let (status_r, status_w) = pipe_with(PipeFlags::CLOEXEC).expect("pipe2(O_CLOEXEC) 失败");

        let mut pidfd_raw: c_int = -1;
        let args = CloneArgs {
            flags: CLONE_NEWNS | CLONE_NEWPID | CLONE_PIDFD,
            pidfd: std::ptr::addr_of_mut!(pidfd_raw) as u64,
            exit_signal: libc::SIGCHLD as u64,
            ..Default::default()
        };

        let pid_raw = unsafe { clone3(&args) };

        if pid_raw == 0 {
            // ---- 子进程 ----
            drop(status_r);
            child_pivot_root_entry(status_w);
        }

        if pid_raw < 0 {
            let err = std::io::Error::last_os_error();
            eprintln!(
                "❌ clone3 失败: {} (errno {})",
                err,
                err.raw_os_error().unwrap_or(0)
            );
            std::process::exit(1);
        }

        assert!(pidfd_raw >= 0, "clone3 返回 pid 但未写入 pidfd");
        let child_pid = Pid::from_raw(pid_raw as i32).expect("无效 pid");
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd_raw) };

        drop(status_w);
        await_child_ready(&status_r, pid_raw as i32);

        println!(
            "✅ clone3 成功: pid={:?}, pidfd={}",
            child_pid,
            pidfd.as_raw_fd()
        );

        wait_for_child(&pidfd, child_pid);

        // 清理
        let _ = std::fs::remove_dir_all("/mnt/pivot_newroot");

        println!("\n=== 测试已完成 ===");
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    imp::run();

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("此示例仅在 Linux 上运行。");
        eprintln!("pivot_root 是 Linux 特有系统调用。");
        std::process::exit(1);
    }
}
