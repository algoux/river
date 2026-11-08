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
| [`linux_pivot_root.rs`](linux_pivot_root.rs) | Linux | 演示 pivot_root 系统调用：完整容器化根文件系统切换流程，含 mount namespace + PID namespace 隔离验证，需 root 权限 |
| [`linux_cgroups_v2.rs`](linux_cgroups_v2.rs) | Linux | 全面演示 cgroups v2 能力：层级操作、进程迁移、CPU/Memory/PIDs/IO 控制器、clone3(CLONE_INTO_CGROUP)、cgroup.freeze、多进程并行 CPU 统计，需 root 权限 |
| [`windows_app_container.rs`](windows_app_container.rs) | Windows | 完整演示 AppContainer 沙箱能力：Profile 创建/删除、SID 获取、ACL 授权（读写/只读）、以 AppContainer 身份启动子进程、文件系统与环境变量隔离验证 |
| [`windows_app_container_runner.rs`](windows_app_container_runner.rs) | Windows | 在 AppContainer 沙箱中执行指定命令，通过 runtimes 参数授予目标目录只读执行权限，适用于运行脚本等场景 |

## 运行方式

```bash
# Linux 示例
cargo run --example linux_capture
cargo run --example linux_pidfd
cargo run --example linux_seccompiler
sudo cargo run --example linux_namespaces      # 需要 root
sudo cargo run --example linux_pivot_root      # 需要 root
sudo cargo run --example linux_cgroups_v2      # 需要 root

# Windows 示例
cargo run --example windows_capture
cargo run --example windows_app_container
cargo run --example windows_app_container_runner
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

### linux_pivot_root — pivot_root 根文件系统切换演示（Linux）

演示完整的容器化根文件系统切换流程，展示 `pivot_root` 系统调用的正确使用方式及隔离效果验证。

| 步骤 | 操作 | 说明 |
|------|------|------|
| 1 | mkdir + mount tmpfs | 在 `/mnt/pivot_newroot` 准备新根（必须在 make-rprivate 之前完成挂载） |
| 2 | mount --make-rprivate / | 防止挂载事件传播到父 namespace |
| 3 | mkdir /proc /dev /.oldroot | 在新根中创建必要子目录 |
| 4 | pivot_root(new_root, put_old) | 切换根文件系统，旧根被移动到 put_old |
| 5 | chdir("/") | 将工作目录切换到新根 |
| 6 | umount2(MNT_DETACH) | 延迟卸载旧根并删除挂载点 |
| 7 | 验证隔离性 | 检查根目录内容、PID、/proc、文件读写 |

**关键技术点：**
- `clone3(CLONE_NEWNS | CLONE_NEWPID | CLONE_PIDFD)` 同时创建 mount 和 PID namespace
- `pivot_root` 通过 `libc::syscall(SYS_pivot_root, ...)` 调用（rustix 未封装）
- WSL overlay 兼容性：tmpfs 挂载必须在 `mount --make-rprivate` 之前完成
- CLOEXEC 状态管道握手协议与 `linux_namespaces.rs` 一致
- 隔离验证：根目录仅含 dev/proc、PID=1、/proc 仅可见自身进程

**内核版本要求：**
- `pivot_root`: ≥ 2.3.41
- `clone3`: ≥ 5.3
- Mount namespace: ≥ 2.4.19
- PID namespace: ≥ 2.6.24

**运行要求：** 必须以 root 权限运行（`sudo cargo run --example linux_pivot_root`）

### linux_cgroups_v2 — cgroups v2 全面能力演示（Linux）

分 9 个阶段全面演示 Linux cgroups v2 (unified hierarchy) 的各项能力，覆盖所有主要控制器和核心机制。

| 阶段 | 内容 | 验证方式 |
|------|------|----------|
| Stage 1 | 基础层级操作 | 检测 cgroup v2 挂载、创建/删除子 cgroup、读写 controllers/subtree_control |
| Stage 2 | 进程迁移 | fork 子进程迁入测试 cgroup，验证 /proc/pid/cgroup 变化，父进程不受影响 |
| Stage 3 | CPU 控制器 | 设置 cpu.max/cpu.weight，fork CPU 密集子进程，读取 cpu.stat 验证节流 |
| Stage 4 | Memory 控制器 | 设置 memory.max/memory.high，子进程分配内存，读取 memory.events/memory.stat |
| Stage 5 | PIDs 控制器 | 设置 pids.max=5，管理器子进程 fork 孙进程触发超限拒绝 (EAGAIN)，读取 pids.events |
| Stage 6 | IO 控制器 | 检测块设备，设置 io.max 带宽限制，读取 io.stat/io.pressure |
| Stage 7 | clone3 + CLONE_INTO_CGROUP | 两层 cgroup + 管理器模式，clone3 原子将孙进程创建到目标 cgroup |
| Stage 8 | cgroup.freeze / events | 冻结/解冻 cgroup，验证 cgroup.events/memory.events/pids.events/cgroup.stat |
| Stage 9 | 多进程并行 CPU 统计 | N 个 worker 并行跑满所有 CPU 核心，验证 1 秒实际时间内 cgroup CPU 消耗 > 1 秒 |

**关键技术点：**
- cgroup v2 文件系统接口：所有操作通过 `/sys/fs/cgroup` 下的文件读写完成
- `clone3(CLONE_INTO_CGROUP | CLONE_PIDFD)` 原始系统调用：使用 `O_PATH` fd 指定目标 cgroup
- 两层 cgroup + 管理器子进程模式：解决 systemd delegation 边界下 `CLONE_INTO_CGROUP` 静默失败问题
- CLOEXEC 管道握手协议：与 `linux_pidfd.rs` / `linux_namespaces.rs` 一致的父子同步机制
- `clock_gettime(CLOCK_MONOTONIC)` 高精度计时：精确对比 wall clock 与 cgroup CPU 时间
- 自动清理：每个阶段独立创建/删除测试 cgroup，避免残留

**内核版本要求：**
- cgroups v2 (unified hierarchy): ≥ 4.5
- clone3 + CLONE_INTO_CGROUP: ≥ 5.7
- cgroup.freeze: ≥ 5.2
- memory.high: ≥ 5.8

**运行要求：** 必须以 root 权限运行（`sudo cargo run --example linux_cgroups_v2`）

### windows_app_container — AppContainer 沙箱能力演示（Windows）

完整演示 Windows AppContainer 沙箱机制的核心能力，涵盖从 Profile 管理到进程隔离验证的全流程。

| 阶段 | 内容 | 验证方式 |
|------|------|----------|
| Stage 1 | Profile 管理 | `CreateAppContainerProfile` 创建、`DeriveAppContainerSidFromAppContainerName` 派生 SID、`DeleteAppContainerProfile` 删除 |
| Stage 2 | ACL 授权 | `SetEntriesInAclW` + `SetNamedSecurityInfoW` 授予读写/只读权限，支持继承标志 |
| Stage 3 | 沙箱进程启动 | `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` + `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` 启动受限子进程 |
| Stage 4 | 文件系统隔离 | 授权目录写入成功、未授权路径 (C:\) 写入被拒绝、只读文件修改被拒绝 |
| Stage 5 | 环境变量隔离 | 白名单变量可见、宿主 PATH 等敏感变量未泄露 |

**关键技术点：**
- `userenv.dll` 三个未公开于 `windows-sys` 的 API 通过 `#[link] extern "system"` 手动声明
- `PROFILE_CREATE_LOCK` 序列化 Profile 创建：`CreateAppContainerProfile` 是写注册表的变更操作，并发调用会导致 `ERROR_KEY_DELETED` / `ERROR_INVALIDARG`
- `SECURITY_CAPABILITIES` 结构体通过 `UpdateProcThreadAttribute` 传递给 `CreateProcessW`，使子进程在创建时即成为 AppContainer
- 环境变量白名单：AppContainer 子进程需要最少 `SystemRoot` + `LOCALAPPDATA` 才能启动 `cmd.exe`
- ACL 合并语义：`SetEntriesInAclW` 按 trustee 合并 ACE，重复授权不会增加 DACL 条目数
- 句柄限制：仅 stdio 三个句柄通过 `HANDLE_LIST` 属性继承，防止句柄泄露

### windows_app_container_runner — AppContainer 命令执行器（Windows）

在 AppContainer 沙箱限制下执行用户指定的命令，并通过 `runtimes` 参数为目标进程授予特定目录的只读执行权限。适用于在隔离环境中运行脚本、测试程序等场景。

**配置方式（源码 `main` 函数）：**
```rust
// 要执行的命令
let command = "python";
let command_args = ["a.py"];

// Runtimes 目录列表 - 这些目录将被授予只读执行权限
let runtimes: Vec<std::path::PathBuf> = vec![
    // Python 安装目录（必须授权才能执行 python）
    std::path::PathBuf::from(r"C:\Users\MeiK\AppData\Local\Python\pythoncore-3.15-64"),
    // 工作目录
    std::path::PathBuf::from(r"E:\river"),
];
```

**关键技术点：**
- Profile 名称基于 PID 自动生成 (`river.runner.{pid}`)，避免冲突
- 仅授予 `FILE_GENERIC_READ | FILE_GENERIC_EXECUTE` 权限，禁止写入
- 程序结束时自动清理 AppContainer Profile
- 环境变量白名单隔离，防止宿主敏感变量泄露
- 捕获并输出子进程的 stdout/stderr，返回原始退出码

**常见错误处理：**
- `did not find executable at '...'`: 需要将可执行文件所在目录添加到 `runtimes`
- `Permission denied`: 检查脚本/依赖库所在目录是否已授权
- AppContainer 默认隔离几乎所有文件系统访问，所有需要的路径都必须显式授权

## 依赖

- **Linux:** `rustix` (0.38)、`libc` (0.2)、`seccompiler` (0.5)
- **Windows:** `windows-sys` (0.60)

详见项目根目录 [`Cargo.toml`](../Cargo.toml)。
