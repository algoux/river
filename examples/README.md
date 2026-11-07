# Examples

本目录包含 `river` 项目的示例程序，演示如何在 Linux 和 Windows 平台上进行进程管理、输出捕获与安全沙箱。

## 示例列表

| 示例 | 平台 | 说明 |
|------|------|------|
| [`linux_capture.rs`](linux_capture.rs) | Linux | 使用 epoll + splice 零拷贝捕获子进程 stdout/stderr，支持大小限制与超限自动终止 |
| [`windows_capture.rs`](windows_capture.rs) | Windows | 使用匿名管道 + 专用读取线程捕获子进程输出，功能等同于 Linux 版本 |
| [`linux_pidfd.rs`](linux_pidfd.rs) | Linux | 演示 pidfd 系列能力：clone3(CLONE_PIDFD)、pidfd_send_signal、waitid(P_PIDFD)，以及基于 CLOEXEC 状态管道的沙箱握手协议 |
| [`linux_seccompiler.rs`](linux_seccompiler.rs) | Linux | 全面演示 seccompiler 库：allowlist/denylist 过滤器、参数匹配规则、多种 Action 类型、实时应用验证及错误处理 |
| [`linux_namespaces.rs`](linux_namespaces.rs) | Linux | 演示全部 6 种 Linux Namespaces（PID/UTS/Mount/IPC/Net/User），使用 clone3 + CLOEXEC 握手协议，需 root 权限 |

## 运行方式

```bash
# Linux 示例
cargo run --example linux_capture
cargo run --example linux_pidfd
cargo run --example linux_seccompiler
sudo cargo run --example linux_namespaces  # 需要 root

# Windows 示例
cargo run --example windows_capture
```

> **注意：** 每个示例都包含平台检查，在非目标平台上运行会提示并退出。

## 各示例详解

### linux_capture — 零拷贝输出捕获（Linux）

使用 `fork` + `execvp` 启动子进程，通过非阻塞管道和 `epoll` 事件循环实时将 stdout/stderr 数据以 `splice` 零拷贝方式写入文件。当任一输出流超过预设大小限制时，自动向子进程发送 `SIGKILL` 终止。

**关键技术点：**
- `pipe2(O_NONBLOCK | O_CLOEXEC)` 创建非阻塞管道
- `epoll` ET 模式驱动多路复用
- `splice(MOVE | MORE | NONBLOCK)` 实现内核态零拷贝传输
- 原子计数器追踪已写入字节数，超限时触发终止
- `clock_gettime(CLOCK_MONOTONIC)` 控制监控刷新频率

**可配置项（源码顶部常量）：**
- `EXECUTABLE` / `ARGS` — 要执行的命令
- `STDOUT_FILE` / `STDERR_FILE` — 输出文件路径
- `STDOUT_LIMIT` / `STDERR_LIMIT` — 输出大小上限

### windows_capture — 输出捕获（Windows）

[`linux_capture.rs`](linux_capture.rs) 的 Windows 对等实现。由于 Windows 匿名管道不支持 IOCP，改用专用读取线程替代 epoll；数据经用户空间缓冲区中转（无零拷贝）；使用 `TerminateProcess` 替代 `SIGKILL`。

**关键技术点：**
- `CreatePipe` 创建可继承匿名管道
- `CreateProcessW` + `STARTF_USESTDHANDLES` 重定向子进程标准流
- 独立 `reader_thread` 执行 ReadFile → WriteFile 循环
- `AtomicBool` kill flag 确保仅一个线程触发终止
- `WaitForSingleObject` 配合定时轮询实现实时监控

### linux_pidfd — pidfd 能力演示（Linux）

分阶段展示 Linux pidfd 机制，涵盖从创建到信号发送到回收的完整生命周期。

| 阶段 | 内容 |
|------|------|
| Stage 1 | `clone3(CLONE_PIDFD)` 原子获取 pidfd。子进程通过 CLOEXEC 状态管道完成沙箱就绪握手，父进程额外校验 `/proc/<pid>/status` 中的 Seccomp 字段 |
| Stage 2 | `pidfd_send_signal` 通过 pidfd 安全发送信号，避免 PID 复用风险 |
| Stage 3 | `waitid(WaitId::PidFd)` 通过 pidfd 回收子进程，先非阻塞轮询再阻塞等待 |

**内核版本要求：**
- `pidfd_send_signal`: ≥ 5.1
- `clone3 + CLONE_PIDFD`: ≥ 5.5
- `waitid(P_PIDFD)`: ≥ 5.4

### linux_seccompiler — seccomp-bpf 过滤器演示（Linux）

全面演示 [seccompiler](https://crates.io/crates/seccompiler) 库的各项能力：

| 阶段 | 内容 |
|------|------|
| Stage 1 | 基础 allowlist 过滤器构建与编译 |
| Stage 2 | denylist 过滤器：阻止 ptrace、reboot、kexec_load 等危险系统调用 |
| Stage 3 | 参数匹配规则：按 fd、flags、prot 等参数精细过滤 |
| Stage 4 | SeccompAction 变体：Allow、Errno、Trace、Log、Kill、KillProcess |
| Stage 5 | 在子进程中实际应用过滤器并验证被阻止的系统调用返回 EPERM |
| Stage 6 | `apply_filter`（单线程）与 `apply_filter_all_threads`（TSYNC）的区别 |
| Stage 7 | 错误处理与边界情况：空过滤器、无效架构、缺少 NO_NEW_PRIVS、多规则 OR 语义、MaskedEq 比较 |

### linux_namespaces — Linux Namespaces 能力演示（Linux）

使用 `clone3` 系统调用逐一创建全部 6 种 Linux Namespace，并通过 CLOEXEC 状态管道握手协议确保子进程初始化完成后再进行验证。

| 阶段 | Namespace | Flag | 验证方式 |
|------|-----------|------|----------|
| Stage 1 | PID | `CLONE_NEWPID` | 子进程 `getpid() == 1` |
| Stage 2 | UTS | `CLONE_NEWUTS` | `sethostname` + `gethostname` |
| Stage 3 | Mount | `CLONE_NEWNS` | `mount --make-rprivate` + 私有 tmpfs |
| Stage 4 | IPC | `CLONE_NEWIPC` | `msgget(IPC_CREAT\|IPC_EXCL)` 消息队列 |
| Stage 5 | Network | `CLONE_NEWNET` | `/sys/class/net` 仅含 lo |
| Stage 6 | User | `CLONE_NEWUSER` | 父进程写 uid_map/gid_map + 双管道同步 |
| 附加 | Combined | PID+UTS+IPC+Mount | 多 namespace 组合测试 |

**关键技术点：**
- `clone3` 原始系统调用封装（rustix 0.38 尚未支持）
- CLOEXEC 状态管道握手：子进程就绪后写入 4 字节 errno，EOF 表示初始化失败
- `/proc/<pid>/ns/*` inode 交叉验证：父进程对比自身与子进程的 namespace 标识
- User Namespace 双管道同步：解决父进程写映射文件与子进程执行的竞态
- 每个 namespace 独立 clone3，互不干扰

**运行要求：** 必须以 root 权限运行（`sudo cargo run --example linux_namespaces`）

## 依赖

- **Linux:** `rustix` (0.38)、`libc` (0.2)、`seccompiler` (0.5)
- **Windows:** `windows-sys` (0.60)

详见项目根目录 [`Cargo.toml`](../Cargo.toml)。
