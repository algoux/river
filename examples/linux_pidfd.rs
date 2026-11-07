//! Linux pidfd 能力演示，使用 rustix + 原始 clone3 系统调用。
//!
//! 演示的功能：
//!   1. clone3(CLONE_PIDFD) — 原子创建子进程并获取 pidfd（无 TOCTOU 风险）
//!      → 原始系统调用（rustix 0.38 尚未支持）
//!   2. pidfd_send_signal   — 通过 pidfd 发送信号（rustix 原生支持）
//!   3. waitid(P_PIDFD)     — 通过 rustix 的 WaitId::PidFd 等待 pidfd
//!   4. 沙箱握手协议        — CLOEXEC 状态管道：完成时写入 4 字节 errno，
//!      EOF 表示子进程在初始化期间死亡；父进程随后重新检查 /proc 中的
//!      Seccomp: 2 字段，而非信任子进程的自报告
//!
//! 仅 clone3 使用原始系统调用；seccomp 过滤器由 seccompiler 构建。

#[cfg(target_os = "linux")]
mod imp {
    use rustix::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
    use rustix::pipe::{PipeFlags, pipe_with};
    use rustix::process::{
        Pid, Signal, WaitId, WaitidOptions, pidfd_send_signal, waitid,
    };
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompFilter, SeccompRule, apply_filter_all_threads,
    };
    use std::collections::BTreeMap;
    use std::os::raw::c_int;

    // ========================================================================
    // clone3 原始系统调用封装（rustix 0.38 尚未支持）
    // ========================================================================

    /// 内核 `struct clone_args` 布局，用于 clone3。
    #[repr(C)]
    #[derive(Default)]
    struct CloneArgs {
        flags: u64,
        pidfd: u64,       // 输出：设置 CLONE_PIDFD 时写入 pidfd
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

    const CLONE_PIDFD: u64 = 0x0000_1000;
    const SYS_CLONE3: libc::c_long = 435; // x86_64 系统调用号

    /// 调用 `clone3(args, size)` — 父进程返回子进程 pid，子进程返回 0。
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
    // 演示阶段
    // ========================================================================

    /// 阶段 1：clone3 + CLONE_PIDFD — 在创建子进程时原子获取 pidfd，
    /// 并使用 CLOEXEC 状态管道作为沙箱就绪握手协议。
    ///
    /// 子进程：SIG_IGN → no_new_privs → rlimits → seccomp，然后写入 4 字节
    /// errno（0 = 已就绪）并关闭管道。收到 EOF 而非数据意味着子进程在
    /// 初始化期间死亡。父进程在收到确认前不向子进程发送任何内容，
    /// 因此旧的 100ms sleep 所掩盖的竞态条件不会发生。
    ///
    /// 若 clone3(CLONE_PIDFD) 不可用，直接终止程序。
    ///
    /// 返回 (pidfd, child_pid)。子进程休眠 3 秒后以退出码 42 退出。
    fn demo_clone3_pidfd() -> (OwnedFd, Pid) {
        println!("=== 阶段 1：clone3(CLONE_PIDFD) + 沙箱握手 ===");
        println!("  尝试通过 clone3 原子获取 pidfd...");

        // 在创建子进程之前创建管道，以便子进程继承；CLOEXEC 防止其泄漏
        // 到子进程后续可能 exec 的任何载荷中。
        let (status_r, status_w) = pipe_with(PipeFlags::CLOEXEC).expect("pipe2(O_CLOEXEC) 失败");

        // 输出槽位：使用 CLONE_PIDFD 时内核会在此处写入 4 字节 pidfd，
        // 因此 args.pidfd 必须指向可写内存。将其保持为默认值 0 会导致
        // clone3 因 EFAULT 失败，这并不能证明内核不支持 clone3。
        let mut pidfd_raw: c_int = -1;
        let args = CloneArgs {
            flags: CLONE_PIDFD,
            pidfd: std::ptr::addr_of_mut!(pidfd_raw) as u64,
            exit_signal: libc::SIGCHLD as u64,
            ..Default::default()
        };

        let pid_raw = unsafe { clone3(&args) };

        if pid_raw == 0 {
            // ---- 子进程 ----
            drop(status_r);
            child_main(status_w);
        }

        if pid_raw < 0 {
            let err = std::io::Error::last_os_error();
            eprintln!(
                "  ❌ clone3(CLONE_PIDFD) 失败: {} (errno {})",
                err,
                err.raw_os_error().unwrap_or(0)
            );
            eprintln!("  此示例要求内核 >= 5.5 且支持 clone3(CLONE_PIDFD)。");
            std::process::exit(1);
        }

        // ---- 父进程（clone3 成功）----
        assert!(
            pidfd_raw >= 0,
            "clone3 返回了子进程 pid 但未将 pidfd 写入输出槽位"
        );
        let child_pid = Pid::from_raw(pid_raw as i32).expect("clone3 返回无效的 pid");
        // SAFETY: 内核刚刚为此进程安装了一个全新的 pidfd
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd_raw) };

        drop(status_w); // 从此只有子进程可以持有写端
        await_sandbox_ready(&status_r, pid_raw as i32);

        println!(
            "  ✅ clone3(CLONE_PIDFD) 成功: 子进程 pid={:?}, pidfd={}",
            child_pid,
            pidfd.as_raw_fd()
        );

        (pidfd, child_pid)
    }

    /// 子进程侧：应用沙箱，报告结果，然后执行"工作"。
    /// 此函数不会返回——调用者绝不能恢复父进程路径。
    fn child_main(status_w: OwnedFd) -> ! {
        let code = match apply_sandbox() {
            Ok(()) => 0,
            Err(errno) => errno,
        };

        let reported = rustix::io::write(&status_w, &code.to_ne_bytes()).is_ok();
        drop(status_w);

        if !reported {
            // 确认消息丢失必须表现为死亡（EOF），绝不能表现为仍在启动中的子进程。
            unsafe { libc::_exit(127) };
        }

        // "工作"：保持存活足够长时间供阶段 2 发送信号，然后以退出码 42 退出。
        unsafe {
            libc::sleep(3);
            libc::_exit(42);
        }
    }

    /// 父进程无法代替子进程执行的所有操作，按正确顺序排列。
    /// 返回第一个失败步骤的 errno。
    fn apply_sandbox() -> Result<(), i32> {
        // 从一开始就忽略信号：阶段 2 的 SIGUSR1 不会再与初始化产生竞态。
        if unsafe { libc::signal(libc::SIGUSR1, libc::SIG_IGN) } == libc::SIG_ERR {
            return Err(last_errno());
        }

        // 在无 CAP_SYS_ADMIN 时加载 seccomp 过滤器的先决条件。
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(last_errno());
        }

        // 其他父进程无法代为降低的限制放在此处。
        let no_core = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core) } != 0 {
            return Err(last_errno());
        }

        // 最后应用 seccomp：从此之后只有白名单中的系统调用可用。
        let bpf = build_seccomp_filter()?;
        apply_filter_all_threads(&bpf).map_err(|_| libc::EPERM)?;
        Ok(())
    }

    /// 默认拒绝的过滤器。空规则向量表示"无条件允许"；
    /// 每个条目都是过滤器生效后子进程仍需要的系统调用，
    /// 包括握手本身使用的系统调用（write/close/exit_group）。
    fn build_seccomp_filter() -> Result<BpfProgram, i32> {
        let allow: &[libc::c_long] = &[
            libc::SYS_write,           // 就绪确认
            libc::SYS_close,           // 关闭状态管道
            libc::SYS_exit_group,      // _exit(42) / _exit(127)
            libc::SYS_exit,
            libc::SYS_clock_nanosleep, // glibc sleep()
            libc::SYS_nanosleep,
            libc::SYS_restart_syscall,
            libc::SYS_rt_sigreturn,    // 从信号处理程序返回
            libc::SYS_futex,
            libc::SYS_sched_yield,
        ];
        let rules: BTreeMap<i64, Vec<SeccompRule>> =
            allow.iter().map(|&nr| (nr as i64, Vec::new())).collect();

        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Errno(libc::EPERM as u32),
            SeccompAction::Allow,
            std::env::consts::ARCH
                .try_into()
                .map_err(|_| libc::EINVAL)?,
        )
        .map_err(|_| libc::EINVAL)?;
        filter.try_into().map_err(|_| libc::EINVAL)
    }

    /// 握手的父进程侧：阻塞等待状态，然后从内核视角验证沙箱，
    /// 而非信任子进程的自报告。
    fn await_sandbox_ready(status_r: &OwnedFd, pid: i32) {
        let mut buf = [0u8; 4];
        let n = loop {
            match rustix::io::read(status_r, &mut buf) {
                Ok(n) => break n,
                Err(rustix::io::Errno::INTR) => continue,
                Err(e) => panic!("读取沙箱状态失败: {e}"),
            }
        };

        match n {
            0 => {
                eprintln!("  ❌ 子进程在沙箱初始化期间死亡（状态管道收到 EOF）");
                std::process::exit(1);
            }
            4 => {
                let errno = i32::from_ne_bytes(buf);
                if errno != 0 {
                    eprintln!(
                        "  ❌ 沙箱初始化失败: {}",
                        std::io::Error::from_raw_os_error(errno)
                    );
                    std::process::exit(1);
                }
                println!("  ✅ 子进程报告沙箱已就绪 (errno=0)");
            }
            _ => panic!("状态管道短读: {n} / 4 字节"),
        }

        match std::fs::read_to_string(format!("/proc/{pid}/status")) {
            Ok(status) => {
                let field = |name: &str| {
                    status
                        .lines()
                        .find(|line| line.starts_with(name))
                        .map(|line| line.trim().to_string())
                        .unwrap_or_else(|| format!("{name} <缺失>"))
                };
                println!(
                    "  • 内核视角: {} | {}",
                    field("Seccomp:"),
                    field("NoNewPrivs:")
                );
                if !field("Seccomp:").contains('2') {
                    eprintln!("  ❌ /proc 未报告 Seccomp: 2 — 过滤器未生效");
                    std::process::exit(1);
                }
            }
            Err(e) => eprintln!("  ⚠️  无法验证 /proc/{pid}/status: {e}"),
        }
    }

    fn last_errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
    }

    /// 阶段 2：通过 rustix 的 pidfd_send_signal 向子进程发送 SIGUSR1。
    fn demo_pidfd_send_signal(pidfd: &impl AsFd, child_pid: Pid) {
        println!("\n=== 阶段 2：pidfd_send_signal (rustix) ===");

        match pidfd_send_signal(pidfd, Signal::Usr1) {
            Ok(()) => println!(
                "  ✅ 已通过 pidfd 向 pid {:?} 发送 SIGUSR1（安全，无 PID 复用风险）",
                child_pid
            ),
            Err(e) => eprintln!("  ❌ pidfd_send_signal(SIGUSR1) 失败: {:?}", e),
        }

        // 短暂暂停，确保子进程在下一阶段仍然存活
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    /// 阶段 3：通过 rustix 的 waitid + WaitId::PidFd 回收子进程。
    fn demo_waitid_pidfd(pidfd: &impl AsFd, child_pid: Pid) {
        println!("\n=== 阶段 3：waitid(WaitId::PidFd) via rustix ===");

        // 先进行非阻塞轮询，检查子进程是否已退出
        let already_reaped = match waitid(
            WaitId::PidFd(pidfd.as_fd()),
            WaitidOptions::NOHANG | WaitidOptions::EXITED,
        ) {
            Ok(Some(status)) => {
                println!("  非阻塞轮询: 子进程已退出");
                print_waitid_status(&status);
                true // 已被此调用回收
            }
            Ok(None) => {
                println!("  非阻塞轮询: 子进程仍在运行");
                false
            }
            Err(e) => {
                eprintln!("  非阻塞 waitid 错误: {:?}", e);
                false
            }
        };

        if already_reaped {
            println!("  ℹ️  子进程已被非阻塞 waitid 回收，跳过阻塞等待");
            return;
        }

        // 阻塞等待退出
        println!("  阻塞等待子进程退出...");
        match waitid(
            WaitId::PidFd(pidfd.as_fd()),
            WaitidOptions::EXITED,
        ) {
            Ok(Some(status)) => {
                println!("  ✅ waitid(P_PIDFD) 已回收 pid {:?}:", child_pid);
                print_waitid_status(&status);
            }
            Ok(None) => {
                println!("  ⚠️  waitid 返回 None（阻塞调用不应出现此情况）");
            }
            Err(e) => {
                eprintln!("  ❌ waitid(P_PIDFD) 失败: {:?}", e);
            }
        }
    }

    fn print_waitid_status(status: &rustix::process::WaitidStatus) {
        if status.exited() {
            println!(
                "     → 正常退出，退出码 {}",
                status.exit_status().unwrap_or(0)
            );
        } else if status.killed() {
            println!(
                "     → 被信号 {} 终止",
                status.terminating_signal().unwrap_or(0)
            );
        } else if status.dumped() {
            println!(
                "     → 被信号 {} 终止并生成 core dump",
                status.terminating_signal().unwrap_or(0)
            );
        } else if status.stopped() {
            println!(
                "     → 被信号 {} 停止",
                status.stopping_signal().unwrap_or(0)
            );
        } else if status.continued() {
            println!("     → 已继续运行");
        } else {
            println!("     → 未知状态");
        }
    }

    pub fn run() {
        println!("╔══════════════════════════════════════════════╗");
        println!("║     Linux pidfd 能力演示                     ║");
        println!("╚══════════════════════════════════════════════╝\n");
        println!("内核版本要求:");
        println!("  • pidfd_send_signal:    >= 5.1");
        println!("  • clone3 + CLONE_PIDFD: >= 5.5");
        println!("  • waitid(P_PIDFD):      >= 5.4\n");
        println!("API 覆盖范围:");
        println!("  • rustix: pidfd_send_signal, waitid(WaitId::PidFd)");
        println!("  • 原始系统调用: clone3（rustix 0.38 尚未支持）");
        println!("  • seccompiler: 子进程安装的 seccomp 过滤器 (TSYNC)\n");

        // 阶段 1：clone3 + CLONE_PIDFD
        let (pidfd, child_pid) = demo_clone3_pidfd();

        // 阶段 2：pidfd_send_signal
        demo_pidfd_send_signal(&pidfd, child_pid);

        // 阶段 3：waitid(P_PIDFD) via rustix
        demo_waitid_pidfd(&pidfd, child_pid);

        println!("\n=== 所有阶段已完成 ===");
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    imp::run();

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("此示例仅在 Linux 上运行。");
        eprintln!("pidfd 是 Linux 特有功能（内核 >= 5.3）。");
        std::process::exit(1);
    }
}
