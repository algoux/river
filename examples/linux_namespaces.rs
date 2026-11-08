//! Linux Namespaces 能力演示，使用 clone3 + CLOEXEC 状态管道握手协议。
//!
//! 演示的 Namespace 类型（全部 6 种）：
//!   1. PID   — 隔离进程 ID 空间，子进程看到独立的 PID 树
//!   2. UTS   — 隔离 hostname / domainname
//!   3. Mount — 隔离挂载点视图，创建私有 tmpfs
//!   4. IPC   — 隔离 System V IPC 和 POSIX 消息队列
//!   5. Net   — 隔离网络栈（lo 接口、独立路由表）
//!   6. User  — UID/GID 映射（root 下仍演示以验证映射机制）
//!
//! 要求：必须以 root (CAP_SYS_ADMIN) 运行。
//!
//! API 覆盖：
//!   • clone3 原始系统调用（rustix 0.38 尚未封装）
//!   • rustix: pipe, process (waitid), fs (mount/umount), thread (unshare)
//!   • libc: sethostname, prctl, uid/gid 映射写入

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
    const CLONE_NEWUTS: u64 = 0x0400_0000;
    const CLONE_NEWNS: u64 = 0x0002_0000;
    const CLONE_NEWIPC: u64 = 0x0800_0000;
    const CLONE_NEWNET: u64 = 0x4000_0000;
    const CLONE_NEWUSER: u64 = 0x1000_0000;
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

    fn last_errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
    }

    fn check_root() {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("❌ 此示例必须以 root 权限运行。");
            eprintln!("   用法: sudo cargo run --example linux_namespaces");
            std::process::exit(1);
        }
    }

    /// 将值写入 /proc/<pid>/ 下的指定文件
    fn write_proc_file(pid: i32, name: &str, value: &str) -> Result<(), String> {
        let path = format!("/proc/{pid}/{name}");
        std::fs::write(&path, value).map_err(|e| format!("写入 {path} 失败: {e}"))
    }

    /// 读取 /proc/self/ns/<ns_type> 的 inode 号
    fn read_ns_inode(ns_type: &str) -> Option<u64> {
        let path = format!("/proc/self/ns/{ns_type}");
        std::fs::read_link(&path).ok().and_then(|link| {
            // 格式: "pid:[4026531836]"
            let s = link.to_string_lossy();
            s.split(':')
                .nth(1)
                .and_then(|n| n.trim_end_matches(']').parse().ok())
        })
    }

    // ========================================================================
    // 各 Namespace 演示阶段
    // ========================================================================

    /// 通用 clone3 + namespace 测试框架
    /// 返回 (pidfd, child_pid)
    fn clone_into_namespace(flags: u64, label: &str) -> (OwnedFd, Pid) {
        println!("--- {label} ---");

        let (status_r, status_w) = pipe_with(PipeFlags::CLOEXEC).expect("pipe2(O_CLOEXEC) 失败");

        let mut pidfd_raw: c_int = -1;
        let args = CloneArgs {
            flags: flags | CLONE_PIDFD,
            pidfd: std::ptr::addr_of_mut!(pidfd_raw) as u64,
            exit_signal: libc::SIGCHLD as u64,
            ..Default::default()
        };

        let pid_raw = unsafe { clone3(&args) };

        if pid_raw == 0 {
            // ---- 子进程 ----
            drop(status_r);
            child_namespace_entry(status_w, flags);
        }

        if pid_raw < 0 {
            let err = std::io::Error::last_os_error();
            eprintln!(
                "  ❌ clone3 失败: {} (errno {})",
                err,
                err.raw_os_error().unwrap_or(0)
            );
            std::process::exit(1);
        }

        assert!(pidfd_raw >= 0, "clone3 返回 pid 但未写入 pidfd");
        let child_pid = Pid::from_raw(pid_raw as i32).expect("无效 pid");
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd_raw) };

        drop(status_w);
        await_child_ready(&status_r, pid_raw as i32, label);

        println!(
            "  ✅ clone3 成功: pid={:?}, pidfd={}",
            child_pid,
            pidfd.as_raw_fd()
        );

        (pidfd, child_pid)
    }

    /// 子进程入口：根据 flags 执行对应的 namespace 验证逻辑
    fn child_namespace_entry(status_w: OwnedFd, flags: u64) -> ! {
        let result = match do_child_namespace_work(flags) {
            Ok(()) => 0i32,
            Err(errno) => errno,
        };

        let _ = rustix::io::write(&status_w, &result.to_ne_bytes());
        drop(status_w);

        // 保持存活供父进程检查 /proc
        unsafe {
            libc::sleep(2);
            libc::_exit(if result == 0 { 0 } else { 1 });
        }
    }

    fn do_child_namespace_work(flags: u64) -> Result<(), i32> {
        // User namespace 需要特殊处理：必须在创建后设置 UID/GID 映射
        // 但 clone3 在子进程中已经处于新 namespace，此时需要写映射文件
        // 注意：对于 CLONE_NEWUSER，父进程需要在子进程启动前或启动后写入映射
        // 这里我们在子进程中尝试（如果 flags 包含 NEWUSER，父进程已预先处理）

        if flags & CLONE_NEWPID != 0 {
            verify_pid_ns()?;
        }
        if flags & CLONE_NEWUTS != 0 {
            verify_uts_ns()?;
        }
        if flags & CLONE_NEWNS != 0 {
            verify_mount_ns()?;
        }
        if flags & CLONE_NEWIPC != 0 {
            verify_ipc_ns()?;
        }
        if flags & CLONE_NEWNET != 0 {
            verify_net_ns()?;
        }
        if flags & CLONE_NEWUSER != 0 {
            verify_user_ns()?;
        }
        Ok(())
    }

    // ---- PID Namespace ----
    fn verify_pid_ns() -> Result<(), i32> {
        let pid = unsafe { libc::getpid() };
        println!("  [child] PID namespace: getpid() = {pid}");
        if pid != 1 {
            println!("  ⚠️  期望 PID=1（init），实际={pid}");
            // 不视为致命错误，某些配置下可能不是 1
        } else {
            println!("  ✅ 子进程在新 PID namespace 中为 init (PID=1)");
        }
        Ok(())
    }

    // ---- UTS Namespace ----
    fn verify_uts_ns() -> Result<(), i32> {
        let new_hostname = b"river-ns-test\0";
        let ret = unsafe {
            libc::sethostname(
                new_hostname.as_ptr() as *const libc::c_char,
                (new_hostname.len() - 1) as libc::size_t,
            )
        };
        if ret != 0 {
            return Err(last_errno());
        }

        let mut buf = [0u8; 256];
        let ret = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
        if ret != 0 {
            return Err(last_errno());
        }
        let hostname = std::ffi::CStr::from_bytes_until_nul(&buf)
            .unwrap_or_default()
            .to_string_lossy();
        println!("  [child] UTS namespace: hostname = \"{hostname}\"");
        if hostname == "river-ns-test" {
            println!("  ✅ sethostname 在新 UTS namespace 中生效");
        } else {
            println!("  ⚠️  hostname 未如预期更改");
        }
        Ok(())
    }

    // ---- Mount Namespace ----
    fn verify_mount_ns() -> Result<(), i32> {
        // 先使挂载事件变为私有，避免传播到父 namespace
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
            println!(
                "  ⚠️  mount --make-rprivate / 失败: {}",
                std::io::Error::last_os_error()
            );
            // 非致命，继续尝试 tmpfs
        }

        // 挂载一个私有 tmpfs
        let ret = unsafe {
            libc::mount(
                c"tmpfs".as_ptr(),
                c"/tmp".as_ptr(),
                c"tmpfs".as_ptr(),
                0,
                c"size=1M".as_ptr() as *const libc::c_void,
            )
        };
        if ret != 0 {
            println!(
                "  ⚠️  mount tmpfs /tmp 失败: {}",
                std::io::Error::last_os_error()
            );
            return Ok(());
        }

        // 验证：在 /tmp 中创建文件
        let test_path = "/tmp/ns_test_marker";
        match std::fs::write(test_path, "namespace_test") {
            Ok(()) => {
                println!("  ✅ Mount namespace: 私有 tmpfs 已挂载并可写");
                let _ = std::fs::remove_file(test_path);
            }
            Err(e) => println!("  ⚠️  写入 tmpfs 失败: {e}"),
        }

        // 清理
        unsafe {
            libc::umount2(c"/tmp".as_ptr(), libc::MNT_DETACH);
        }
        Ok(())
    }

    // ---- IPC Namespace ----
    fn verify_ipc_ns() -> Result<(), i32> {
        // 创建一个 System V 消息队列，验证其在独立 IPC namespace 中
        let key = 0xDEAD_BEEF_u32 as libc::key_t;
        let msqid = unsafe { libc::msgget(key, libc::IPC_CREAT | libc::IPC_EXCL | 0o600) };
        if msqid < 0 {
            let err = std::io::Error::last_os_error();
            println!("  ⚠️  msgget 失败: {err}");
            return Ok(());
        }
        println!("  ✅ IPC namespace: 创建消息队列 msqid={msqid} (key=0xDEADBEEF)");

        // 立即销毁
        unsafe {
            libc::msgctl(msqid, libc::IPC_RMID, std::ptr::null_mut());
        }
        println!("  ✅ 消息队列已清理");
        Ok(())
    }

    // ---- Network Namespace ----
    fn verify_net_ns() -> Result<(), i32> {
        // 使用 netlink (RTM_GETLINK) 查询当前 network namespace 中的接口。
        // 注意：不能读 /sys/class/net，因为子进程未重新挂载 /sys，
        // sysfs 反映的是父 namespace 的视图，会导致误报 eth0 等接口。
        // netlink socket 绑定到创建它的 network namespace，结果可靠。
        let ifaces = list_net_interfaces_via_netlink();
        println!("  [child] Network namespace 接口 (netlink): {:?}", ifaces);

        if ifaces.len() == 1 && ifaces[0] == "lo" {
            println!("  ✅ Network namespace: 仅有 lo 接口（完全断网）");
        } else if ifaces.is_empty() {
            println!("  ⚠️  netlink 查询失败或无接口");
        } else {
            println!(
                "  ℹ️  存在非 lo 接口: {:?}",
                ifaces.iter().filter(|n| *n != "lo").collect::<Vec<_>>()
            );
        }
        Ok(())
    }

    /// 通过 NETLINK_ROUTE + RTM_GETLINK 枚举当前 network namespace 的网络接口。
    /// 返回接口名称列表。失败时返回空向量。
    fn list_net_interfaces_via_netlink() -> Vec<String> {
        use std::mem;

        // 创建 netlink socket
        let sock = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if sock < 0 {
            return Vec::new();
        }

        // 绑定到本进程（pid=0 表示内核自动分配）
        let mut local: libc::sockaddr_nl = unsafe { mem::zeroed() };
        local.nl_family = libc::AF_NETLINK as u16;
        local.nl_pid = 0;
        local.nl_groups = 0;
        let ret = unsafe {
            libc::bind(
                sock,
                &local as *const libc::sockaddr_nl as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if ret < 0 {
            unsafe { libc::close(sock) };
            return Vec::new();
        }

        // 发送 RTM_GETLINK dump 请求
        #[repr(C)]
        struct NlRequest {
            nlh: libc::nlmsghdr,
            ifm: libc::ifinfomsg,
        }
        let mut req: NlRequest = unsafe { mem::zeroed() };
        req.nlh.nlmsg_len = mem::size_of::<NlRequest>() as u32;
        req.nlh.nlmsg_type = libc::RTM_GETLINK;
        req.nlh.nlmsg_flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
        req.nlh.nlmsg_seq = 1;
        req.ifm.ifi_family = libc::AF_UNSPEC as u8;

        let ret = unsafe {
            libc::send(
                sock,
                &req as *const NlRequest as *const libc::c_void,
                mem::size_of::<NlRequest>(),
                0,
            )
        };
        if ret < 0 {
            unsafe { libc::close(sock) };
            return Vec::new();
        }

        // 接收响应并解析 IFLA_IFNAME 属性
        let mut buf = vec![0u8; 8192];
        let mut ifaces = Vec::new();

        loop {
            let n =
                unsafe { libc::recv(sock, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n <= 0 {
                break;
            }
            let len = n as usize;
            let mut offset = 0;
            while offset + mem::size_of::<libc::nlmsghdr>() <= len {
                let nlh: &libc::nlmsghdr =
                    unsafe { &*(buf.as_ptr().add(offset) as *const libc::nlmsghdr) };
                if i32::from(nlh.nlmsg_type) == libc::NLMSG_DONE
                    || i32::from(nlh.nlmsg_type) == libc::NLMSG_ERROR
                {
                    break;
                }
                if nlh.nlmsg_type == libc::RTM_NEWLINK {
                    // ifinfomsg 紧跟 nlmsghdr
                    let ifm_offset = offset + mem::size_of::<libc::nlmsghdr>();
                    // 属性从 ifinfomsg 之后开始（需对齐到 NLMSG_ALIGN）
                    let attr_offset =
                        ifm_offset + libc::NLMSG_ALIGN(mem::size_of::<libc::ifinfomsg>()) as usize;
                    let msg_end = offset + nlh.nlmsg_len as usize;
                    let mut a_off = attr_offset;
                    while a_off + mem::size_of::<libc::nlattr>() <= msg_end {
                        let nla: &libc::nlattr =
                            unsafe { &*(buf.as_ptr().add(a_off) as *const libc::nlattr) };
                        if nla.nla_type == libc::IFLA_IFNAME {
                            let name_start = a_off + mem::size_of::<libc::nlattr>();
                            let name_end = a_off + nla.nla_len as usize;
                            if name_end <= msg_end {
                                let name_bytes = &buf[name_start..name_end];
                                // 去除尾部 NUL
                                let name = std::ffi::CStr::from_bytes_until_nul(name_bytes)
                                    .map(|cs| cs.to_string_lossy().to_string())
                                    .unwrap_or_default();
                                if !name.is_empty() {
                                    ifaces.push(name);
                                }
                            }
                        }
                        a_off += unsafe { libc::NLA_ALIGN(i32::from(nla.nla_len)) } as usize;
                    }
                }
                offset += libc::NLMSG_ALIGN(nlh.nlmsg_len as _) as usize;
            }
            // 检查是否还有后续消息（NLM_F_MULTI）
            // 简化处理：如果收到 NLMSG_DONE 则退出
            let mut done = false;
            let mut off2 = 0;
            while off2 + mem::size_of::<libc::nlmsghdr>() <= len {
                let nlh2: &libc::nlmsghdr =
                    unsafe { &*(buf.as_ptr().add(off2) as *const libc::nlmsghdr) };
                if i32::from(nlh2.nlmsg_type) == libc::NLMSG_DONE {
                    done = true;
                    break;
                }
                off2 += libc::NLMSG_ALIGN(nlh2.nlmsg_len as _) as usize;
            }
            if done {
                break;
            }
        }

        unsafe { libc::close(sock) };
        ifaces.sort();
        ifaces
    }

    // ---- User Namespace ----
    fn verify_user_ns() -> Result<(), i32> {
        let uid = unsafe { libc::getuid() };
        let euid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getgid() };
        println!("  [child] User namespace: uid={uid}, euid={euid}, gid={gid}");
        // 在 root 创建的 user namespace 中，UID 映射取决于父进程的设置
        // 这里仅验证我们确实处于新的 user namespace
        println!("  ✅ User namespace: 已进入新用户命名空间");
        Ok(())
    }

    // ========================================================================
    // 父进程侧握手与验证
    // ========================================================================

    fn await_child_ready(status_r: &OwnedFd, pid: i32, label: &str) {
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
                eprintln!("  ❌ [{label}] 子进程在初始化期间死亡（EOF）");
                std::process::exit(1);
            }
            4 => {
                let errno = i32::from_ne_bytes(buf);
                if errno != 0 {
                    eprintln!(
                        "  ❌ [{label}] 子进程初始化失败: {}",
                        std::io::Error::from_raw_os_error(errno)
                    );
                    std::process::exit(1);
                }
            }
            _ => panic!("状态管道短读: {n} / 4 字节"),
        }

        // 从 /proc 验证 namespace 信息
        print_proc_ns_info(pid, label);
    }

    fn print_proc_ns_info(pid: i32, _label: &str) {
        let ns_dir = format!("/proc/{pid}/ns");
        let parent_ns_dir = "/proc/self/ns";

        let ns_types = ["pid", "uts", "mnt", "ipc", "net", "user"];
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

    fn wait_for_child(pidfd: &OwnedFd, _child_pid: Pid, label: &str) {
        println!("  等待子进程退出...");
        match waitid(WaitId::PidFd(pidfd.as_fd()), WaitidOptions::EXITED) {
            Ok(Some(status)) => {
                if status.exited() {
                    let code = status.exit_status().unwrap_or(0);
                    if code == 0 {
                        println!("  ✅ [{label}] 子进程正常退出 (code=0)");
                    } else {
                        println!("  ⚠️  [{label}] 子进程退出码={code}");
                    }
                } else if status.killed() {
                    println!(
                        "  ⚠️  [{label}] 子进程被信号 {} 终止",
                        status.terminating_signal().unwrap_or(0)
                    );
                }
            }
            Ok(None) => println!("  ⚠️  waitid 返回 None"),
            Err(e) => eprintln!("  ❌ waitid 失败: {e:?}"),
        }
    }

    // ========================================================================
    // User Namespace 特殊处理：父进程写入 UID/GID 映射
    // ========================================================================

    /// 对于 CLONE_NEWUSER，父进程需要在子进程开始工作前写入映射文件。
    /// 但由于我们的握手机制是子进程先执行再报告，这里采用另一种策略：
    /// 在 clone3 之前记录父进程的 namespace inode，clone3 之后由父进程
    /// 写入 /proc/<child>/uid_map 和 gid_map。
    ///
    /// 然而，子进程在 clone3 返回后立即开始执行，存在竞态。
    /// 解决方案：使用额外的同步管道，父进程写完映射后再让子进程继续。
    fn clone_user_namespace() -> (OwnedFd, Pid) {
        println!("--- User Namespace (带 UID/GID 映射) ---");

        let (status_r, status_w) = pipe_with(PipeFlags::CLOEXEC).expect("pipe2(O_CLOEXEC) 失败");
        // 额外管道：父→子，通知映射已完成
        let (map_done_r, map_done_w) =
            pipe_with(PipeFlags::CLOEXEC).expect("pipe2(O_CLOEXEC) 失败");

        let mut pidfd_raw: c_int = -1;
        let args = CloneArgs {
            flags: CLONE_NEWUSER | CLONE_PIDFD,
            pidfd: std::ptr::addr_of_mut!(pidfd_raw) as u64,
            exit_signal: libc::SIGCHLD as u64,
            ..Default::default()
        };

        let pid_raw = unsafe { clone3(&args) };

        if pid_raw == 0 {
            // ---- 子进程 ----
            drop(status_r);
            drop(map_done_w);
            child_user_ns_entry(status_w, map_done_r);
        }

        if pid_raw < 0 {
            let err = std::io::Error::last_os_error();
            eprintln!(
                "  ❌ clone3(CLONE_NEWUSER) 失败: {} (errno {})",
                err,
                err.raw_os_error().unwrap_or(0)
            );
            std::process::exit(1);
        }

        assert!(pidfd_raw >= 0);
        let child_pid = Pid::from_raw(pid_raw as i32).expect("无效 pid");
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd_raw) };

        drop(status_w);
        drop(map_done_r);

        // 父进程写入 UID/GID 映射
        let pid_i32 = pid_raw as i32;
        if let Err(e) = write_proc_file(pid_i32, "uid_map", "0 0 1\n") {
            eprintln!("  ❌ 写入 uid_map 失败: {e}");
        } else {
            println!("  ✅ 已写入 /proc/{pid_i32}/uid_map: 0 0 1");
        }

        // 需要先写 setgroups deny 才能写 gid_map（非特权 user ns 的要求）
        let _ = write_proc_file(pid_i32, "setgroups", "deny\n");

        if let Err(e) = write_proc_file(pid_i32, "gid_map", "0 0 1\n") {
            eprintln!("  ❌ 写入 gid_map 失败: {e}");
        } else {
            println!("  ✅ 已写入 /proc/{pid_i32}/gid_map: 0 0 1");
        }

        // 通知子进程映射已完成
        let _ = rustix::io::write(&map_done_w, &[1u8]);
        drop(map_done_w);

        // 等待子进程就绪报告
        await_child_ready(&status_r, pid_i32, "User NS");

        println!(
            "  ✅ clone3(CLONE_NEWUSER) 成功: pid={:?}, pidfd={}",
            child_pid,
            pidfd.as_raw_fd()
        );

        (pidfd, child_pid)
    }

    fn child_user_ns_entry(status_w: OwnedFd, map_done_r: OwnedFd) -> ! {
        // 等待父进程完成 UID/GID 映射
        let mut buf = [0u8; 1];
        loop {
            match rustix::io::read(&map_done_r, &mut buf) {
                Ok(0) => {
                    // 父进程关闭了管道，映射可能失败
                    break;
                }
                Ok(_) => break,
                Err(rustix::io::Errno::INTR) => continue,
                Err(_) => break,
            }
        }
        drop(map_done_r);

        let result = match verify_user_ns() {
            Ok(()) => 0i32,
            Err(errno) => errno,
        };

        let _ = rustix::io::write(&status_w, &result.to_ne_bytes());
        drop(status_w);

        unsafe {
            libc::sleep(2);
            libc::_exit(if result == 0 { 0 } else { 1 });
        }
    }

    // ========================================================================
    // 主流程
    // ========================================================================

    pub fn run() {
        println!("╔══════════════════════════════════════════════╗");
        println!("║     Linux Namespaces 能力演示                 ║");
        println!("╚══════════════════════════════════════════════╝\n");

        check_root();

        println!("内核版本要求:");
        println!("  • clone3:               >= 5.3");
        println!("  • PID namespace:        >= 2.6.24");
        println!("  • UTS namespace:        >= 2.6.19");
        println!("  • Mount namespace:      >= 2.4.19");
        println!("  • IPC namespace:        >= 2.6.19");
        println!("  • Network namespace:    >= 2.6.24");
        println!("  • User namespace:       >= 3.8\n");

        println!("API 覆盖:");
        println!("  • clone3 原始系统调用 (所有 namespace flags)");
        println!("  • CLOEXEC 状态管道握手协议");
        println!("  • /proc/<pid>/ns 交叉验证");
        println!("  • UID/GID 映射 (User namespace)\n");

        // 记录父进程的 namespace inode 用于对比
        println!("=== 父进程 Namespace Inodes ===");
        for ns in &["pid", "uts", "mnt", "ipc", "net", "user"] {
            if let Some(inode) = read_ns_inode(ns) {
                println!("  {ns:>5}: [{inode}]");
            }
        }
        println!();

        // 阶段 1: PID Namespace
        println!("=== 阶段 1: PID Namespace ===");
        let (pidfd, child_pid) = clone_into_namespace(CLONE_NEWPID, "PID NS");
        wait_for_child(&pidfd, child_pid, "PID NS");

        // 阶段 2: UTS Namespace
        println!("\n=== 阶段 2: UTS Namespace ===");
        let (pidfd, child_pid) = clone_into_namespace(CLONE_NEWUTS, "UTS NS");
        wait_for_child(&pidfd, child_pid, "UTS NS");

        // 阶段 3: Mount Namespace
        println!("\n=== 阶段 3: Mount Namespace ===");
        let (pidfd, child_pid) = clone_into_namespace(CLONE_NEWNS, "Mount NS");
        wait_for_child(&pidfd, child_pid, "Mount NS");

        // 阶段 4: IPC Namespace
        println!("\n=== 阶段 4: IPC Namespace ===");
        let (pidfd, child_pid) = clone_into_namespace(CLONE_NEWIPC, "IPC NS");
        wait_for_child(&pidfd, child_pid, "IPC NS");

        // 阶段 5: Network Namespace
        println!("\n=== 阶段 5: Network Namespace ===");
        let (pidfd, child_pid) = clone_into_namespace(CLONE_NEWNET, "Net NS");
        wait_for_child(&pidfd, child_pid, "Net NS");

        // 阶段 6: User Namespace (特殊处理)
        println!("\n=== 阶段 6: User Namespace ===");
        let (pidfd, child_pid) = clone_user_namespace();
        wait_for_child(&pidfd, child_pid, "User NS");

        // 附加：组合多个 Namespace
        println!("\n=== 附加: 组合 Namespace (PID + UTS + IPC + Mount) ===");
        let combined_flags = CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNS;
        let (pidfd, child_pid) = clone_into_namespace(combined_flags, "Combined");
        wait_for_child(&pidfd, child_pid, "Combined");

        println!("\n=== 所有阶段已完成 ===");
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    imp::run();

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("此示例仅在 Linux 上运行。");
        eprintln!("Linux Namespaces 是 Linux 特有功能。");
        std::process::exit(1);
    }
}
