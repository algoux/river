# river 设计文档

> 状态：设计定稿，待实施。事实来源与内核版本门槛见附录 A/B。实施计划见 `docs/development-plan.md`。
> 本文是实现的唯一依据；实现过程中发现的问题回写到本文，而不是散落在代码注释里。

## 1. 目标与非目标

**目标**：一个 Python 库，把任意程序关进以某个目录为 rootfs 的 Linux 沙箱里执行，并给出判题级的资源计量与状态：

- **rootless**：不依赖 root、setuid helper、外部二进制（bwrap/nsjail/crun），只用当前用户 + 内核。
- **低开销**：一次 `exec` 的沙箱开销为个位数毫秒；没有常驻进程，没有轮询。
- **限制与计量**：CPU 时间 / 墙钟 / 内存 / 输出 / 进程数的限制与精确计量，`None` 表示不限制。
- **只支持最新内核**（≥ 6.8），不做任何兼容分支。

**非目标**：Windows/macOS 后端；旧内核；网络（沙箱内只有 `lo`）；容器镜像管理（rootfs 目录由调用方准备）；多租户隔离（调用方是可信的，沙箱内程序是不可信的）。

## 2. 术语

| 术语 | 含义 |
|---|---|
| 调用方 | 使用 river 的 Python 进程（可信） |
| 宿主 | 调用方所在的 Linux 系统 |
| rootfs | 调用方提供的一个目录，内容是一个完整的用户空间（如 `python:3.12-slim` 解压），文件属主必须是当前用户 |
| 沙箱 | 一次 `exec` 对应的子进程及其整棵进程树、命名空间、cgroup |
| `/work` | 沙箱内唯一可写的 bind 目录，对应宿主上一个临时目录 |
| 委托 cgroup | systemd 以 `Delegate=yes` 交给当前用户的 cgroup 子树 |

## 3. 架构

```
调用方 Python 线程 ──► River.exec()  [Rust, GIL 已释放]
   │
   ├─ 父进程（调用方进程）                     ├─ 子进程（clone3 一次创建全部 ns）
   │  1 校验参数、生成 id                       │  a PR_SET_PDEATHSIG
   │  2 创建 run cgroup，写限制                 │  b 写 setgroups/uid_map/gid_map
   │  3 创建 /work 宿主目录，写入 copy_in       │  c 等 "go"
   │  4 预序列化 ChildSpec（argv/envp/路径）    │  d mount 序列 → pivot_root
   │  5 clone3(NEWUSER|NEWPID|NEWNS|NEWNET|     │  e lo up、rlimits
   │            NEWIPC|NEWUTS|NEWCGROUP)        │  f 丢 caps、no_new_privs、Landlock、seccomp
   │  6 把子进程 pid 写入 cgroup.procs，发 "go" │  g chdir、stdio、execve
   │  7 epoll([pidfd, pipes, sync]) 直到退出    │     成功：sync fd 因 CLOEXEC 关闭 → 父看到 EOF
   │     墙钟到期 → cgroup.kill                 │     失败：写 {step, errno} 到 sync，_exit(42)
   │  8 waitid → 等 cgroup 清空 → 读计量        │
   │  9 判定 status、copy_out、清理             │
   └─ 返回 ExecResult
```

- **一次 `clone3` 创建全部命名空间**（user/pid/mount/net/ipc/uts/cgroup），子进程是新 pid ns 的 pid 1；它退出时内核杀光 ns 内其余进程，这是清场的基础。
- **父进程单线程 epoll**：pidfd、输出管道、stdin 写端、同步 socket 都在一个事件循环里；墙钟是 epoll 超时，没有后台线程，没有周期检查。
- **子进程在 `clone3` 之后只跑裸 syscall**（`rustix`/`libc`），不分配堆、不拿锁——调用方是多线程 Python 进程，clone 瞬间别的线程可能持有 malloc 锁。所有字符串在父进程预先转成 `CString`。
- **cgroup 必须存在**：即使调用方一个限制都不传，计量（`cpu.stat` / `memory.peak`）和墙钟 `cgroup.kill` 都依赖它。拿不到委托 → `CgroupNotDelegatedError`，不降级。

## 4. Python API

```python
import river
from river import River

river.doctor(raise_on_fail=True) -> DoctorReport

with River("/rootfs/python") as river:      # 没有任何配置参数；预检见 §8
    r = river.exec(
        executable,                       # str | os.PathLike；含 "/" 视为沙箱内路径，否则按 PATH 搜索（沙箱内）
        args=(),                          # Sequence[str]，argv = [executable, *args]
        *,
        cwd="/work",                      # 沙箱内绝对路径
        envs=None,                        # Mapping[str, str]；None → 读 <rootfs>/meta.json 的 envs；传入则完全替换
        cpu_time_limit_ms=None,
        wall_time_limit_ms=None,
        memory_limit_bytes=None,
        stdout_limit_bytes=None,
        stderr_limit_bytes=None,
        copy_in=None,                     # Mapping[沙箱内路径, bytes | str | os.PathLike]
        copy_out=None,                    # Mapping[沙箱内路径, None | str | os.PathLike]
        copy_out_limit_bytes=None,
        stdin_file=None,                  # 沙箱内路径（相对 cwd）
        stdin=None,                       # bytes；与 stdin_file 互斥
        stdout_file=None,                 # 沙箱内路径（相对 cwd）
        stderr_file=None,
        proc_limit=None,                  # pids.max + RLIMIT_NPROC
        open_file_limit=None,             # RLIMIT_NOFILE
        stack_limit_bytes=None,           # RLIMIT_STACK
        address_space_limit_bytes=None,   # RLIMIT_AS
    ) -> ExecResult
```

`ExecResult`（不可变，`dataclass` 风格）：

| 字段 | 类型 | 说明 |
|---|---|---|
| `status` | `str` | `AC` / `RE` / `TLE` / `MLE` / `OLE` |
| `exit_code` | `int \| None` | 正常退出时为退出码，被信号杀死时 `None` |
| `signal` | `int \| None` | 被信号杀死时的信号号（含我们 `cgroup.kill` 产生的 `9`），否则 `None` |
| `cpu_time_used_ms` | `int` | 来自 `cpu.stat usage_usec`，整棵树 |
| `wall_time_used_ms` | `int` | 从发出 "go" 到 `waitid` 返回 |
| `memory_used_bytes` | `int` | 来自 `memory.peak`（含 page cache） |
| `stdout` / `stderr` | `bytes \| None` | 管道收集；用了 `*_file` 时为 `None` |
| `files` | `dict[str, bytes]` | `copy_out` 中值为 `None` 的文件内容 |
| `error` | `str \| None` | 人类可读原因（`TLE` 时注明 cpu 或 wall，`RE` 时注明信号名等） |

状态语义：

| 码 | 含义 |
|---|---|
| `AC` | 退出码 0 |
| `RE` | 非 0 退出，或被信号杀死（`signal` 区分：`11` SIGSEGV、`31` SIGSYS = seccomp 拦截等） |
| `TLE` | 墙钟超时被我们杀；或 `SIGXCPU`；或结束后 `cpu_time_used_ms > cpu_time_limit_ms` |
| `MLE` | cgroup 发生 OOM kill；或结束后 `memory_used_bytes ≥ memory_limit_bytes` 且非正常退出 |
| `OLE` | 输出超过上限（我们杀） |

异常（只在宿主侧/建立阶段抛出；沙箱内的任何结局都走 `ExecResult`）：

```
river.RiverError(RuntimeError)
├─ KernelTooOldError           内核 < 6.8
├─ UserNamespaceDeniedError    max_user_namespaces=0 / AppArmor 限制 / 探测失败，附修复命令
├─ CgroupNotDelegatedError     附修复命令（systemd-run --user --scope -p Delegate=yes ... 或在已委托的 session/service 内运行）
├─ RootfsError                 rootfs 不存在、meta.json 缺失/非法、挂载点缺失、copy_in 路径不在 /work 下
├─ ExecSetupError              子进程 exec 之前失败：含 step 名（如 "child.mount.proc"）与 errno 文本
└─ CopyOutError                copy_out 目标缺失/超限/非普通文件；.result 挂着已得到的 ExecResult
```

其他约定：

- `River` 线程安全，多线程可并发 `exec`；每个 `exec` 独立 cgroup / mount ns / `/work`。
- `River.__init__` 做全部预检（§8），失败即抛；`__exit__` 只是释放引用，进程级资源（§7 的 `river/` cgroup）由 systemd 在进程退出时回收。
- `River` 没有配置参数：缺失的挂载点总是补建（§8），`/sys` 只读挂载（§5），`/tmp` 用内核默认 tmpfs，seccomp denylist 与 Landlock 总是开启（内核不支持 Landlock 时自动关闭并警告）。
- Ctrl-C：epoll 超时上限 100ms，每次醒来调用 `PyErr::check_signals`；收到中断 → `cgroup.kill` → 回收 → 抛 `KeyboardInterrupt`，不留孤儿沙箱。
- 环境变量：`RIVER_LOG=debug` 让父/子进程把每个 step 打到 stderr；`RIVER_HARDENING=off` 关闭 seccomp 与 Landlock（命名空间、只读 rootfs、丢 caps 不受影响），只用于定位"程序被加固层误伤"，不是配置项。
- 参数误用与缺失文件：`stdin` 与 `stdin_file` 同时给出 → `ValueError`；`stdin_file` 指向的文件不存在 → `ExecSetupError`（与 `cwd` 不存在一致，fail-fast，不静默回退空输入）；`executable` 不含 `/` 而 `envs` 缺 `PATH` → `ValueError`。

### 4.1 `meta.json`

位置：`<rootfs>/meta.json`（沙箱内以 `/meta.json` 可见，无害）。当前只定义一个键：

```json
{ "envs": { "PATH": "/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin", "HOME": "/work" } }
```

- `River.__init__` 时若文件存在则解析并校验：顶层必须是 JSON 对象，`envs` 键缺失视为空映射，存在则必须是 `str → str`；非法 → `RootfsError`。校验通过后 `exec(envs=None)` 使用它。
- `exec(envs=None)` 使用它；文件不存在且没有 `envs` → `RootfsError`。
- 其余键预留，未知键忽略。

## 5. 子进程序列（step 名即错误信息里的 step）

| step | 操作 | 说明 |
|---|---|---|
| `child.pdeathsig` | `prctl(PR_SET_PDEATHSIG, SIGKILL)`；父进程存活校验：`CLONE_NEWPID` 下 `getppid()` 恒为 0（父进程在 pid ns 之外），改为读 `/proc/self/status` 的 `PPid:` 行与期望的父 pid 比对，不符则直接退出 | 调用方线程意外死亡时整个沙箱随之消亡 |
| `child.idmap.*` | 写 `/proc/self/setgroups`=`deny`、`uid_map`=`0 <uid> 1`、`gid_map`=`0 <gid> 1` | 子进程是 userns 创建者，拥有 `CAP_SETUID/SETGID`，不需要父进程参与；此时看到的还是宿主 `/proc` |
| `child.wait_go` | 阻塞读 sync socket 1 字节 | 父进程此时把 pid 写进 `cgroup.procs`，保证 exec 前 limits 已生效 |
| `child.mount.private` | `mount("none", "/", NULL, MS_REC\|MS_PRIVATE)` | 阻止后续 umount/pivot 传播回宿主 |
| `child.mount.bind_root` | 按宿主**路径** `chdir` 进 rootfs（`CLONE_NEWNS` 之后预打开的 fd 仍指向父 ns 的 mount 对象，路径解析必须走本 ns）；`open_tree(OPEN_TREE_CLONE\|AT_RECURSIVE)` 克隆为**分离**挂载 → `mount_setattr(RDONLY\|NOSUID\|NODEV, RECURSIVE)` → `move_mount` 到原路径；再按宿主路径重新 `chdir`（从父目录**走进**该目录才会穿过新挂载点，`chdir(".")` 不会） | 让 new root 成为只读挂载点（`pivot_root` 的硬性要求）。实现注记：对**已挂接**的 bind 调 `mount_setattr` 恒 `EINVAL`（内核 `MNT_LOCK_*` 语义），旧式 bind+remount 在新内核上会静默忽略 flag，分离挂载是唯一可靠配方 |
| `child.mount.proc` | `mount("proc", "./proc", "proc", NOSUID\|NODEV\|NOEXEC)` | 新 pid ns 的 procfs；子进程是 pid 1 所以允许挂载 |
| `child.mount.devpts` | `devpts` `newinstance,ptmxmode=0666,mode=0620` 于 `./dev/pts`；再 bind **新实例自己的** `./dev/pts/ptmx` → `./dev/ptmx` | bind 宿主的 ptmx 会把 `/dev/ptmx` 链到宿主 devpts 实例，`openpty` 拿不到 slave；bind 新实例的节点才符合本 step 的目的 |
| `child.mount.shm` / `mqueue` / `tmp` | tmpfs（`mode=1777`）于 `./dev/shm`；`mqueue` 于 `./dev/mqueue`；tmpfs（`mode=1777`，内核默认大小）于 `./tmp` | |
| `child.mount.dev_*` | 宿主 `/dev/null` `/dev/zero` `/dev/full` `/dev/random` `/dev/urandom` 逐个 `open_tree(CLONE)` → `mount_setattr(NOSUID)` → `move_mount ./dev/*` | **不能加 `NODEV`**，否则设备不可用；userns 内自己 `mknod` 的节点不可用，所以必须 bind |
| `child.mount.work` | 宿主 work 目录 `open_tree(CLONE)` → `mount_setattr(NOSUID\|NODEV)` → `move_mount ./work` | 保留 exec（判题编译产物在 /work 运行） |
| `child.mount.sys` | `sysfs`（`nosuid\|nodev\|noexec\|ro`）于 `./sys`，再以 ro tmpfs 覆盖 `./sys/fs`；失败视为建立失败 | user namespace 拥有新 netns，所以允许挂载；挂载点由 §8 预检补建。6.6+ 内核在 userns 内挂 sysfs 时会**自动挂 cgroup2** 到 `/sys/fs/cgroup`，视图暴露调用方的 cgroup 子树，必须盖住 |
| `child.mount.pivot` | `pivot_root(".", ".")`；`chdir("/")`；`umount2(".", MNT_DETACH)` | 不需要 `.oldroot` 目录 |
| `child.net.lo` | `ioctl(SIOCSIFFLAGS)` 把 `lo` 置 `IFF_UP` | 在丢 caps 之前做 |
| `child.rlimit.*` | `setrlimit`，见 §6 | 只对传了参数的限制调用 |
| `child.caps.*` | `PR_CAPBSET_DROP` 全部 cap（userns 内允许）；`capset()` 清空 P/E/I | `PR_SET_SECUREBITS` 需要 **init user namespace** 的 CAP_SETPCAP，rootless 下 `EPERM`，不做；NOROOT 防的 uid-0-execve 重取权限路径由下一步 `no_new_privs` 关闭 |
| `child.nnp` | `PR_SET_NO_NEW_PRIVS` | seccomp / Landlock 的前提 |
| `child.landlock.*` | 见 §9 | 处理写类权限；读/执行不处理 |
| `child.seccomp` | `seccomp(SECCOMP_SET_MODE_FILTER)` | 见 §9 |
| `child.chdir` | `chdir(cwd)` | `ENOENT` → `ExecSetupError("cwd does not exist")` |
| `child.stdio` | stdin：`stdin_file` 打开（相对 cwd）/ 宿主管道 / `/dev/null`；stdout/stderr：`*_file` 以 `O_WRONLY\|O_CREAT\|O_TRUNC, 0644` 打开 / 管道写端；`dup2` | |
| `child.execve` | `execve`；无 `/` 时按 `envs["PATH"]`（沙箱内）逐段尝试 | 失败写 `{step, errno}` 到 sync，`_exit(42)` |

成功路径不写 sync socket；`execve` 时因 `CLOEXEC` 自动关闭，父进程读到 EOF 即"已 exec"。

信号注记：沙箱程序是新 pid ns 的 **pid 1**（`SIGNAL_UNKILLABLE`），内核只向 init 投递**带处理函数**的信号——用户态 `kill(getpid(), SIGSEGV)` 这类自杀式信号，以及内核 `send_sig`（非 priv）发的 `SIGXCPU`（RLIMIT_CPU soft 到期）与 `SIGXFSZ`（RLIMIT_FSIZE 超限）同样被直接丢弃（6.18 与 7.0 内核实测：CPU 死循环在 soft 秒后不死于 24，由 hard=soft+1 的 `SIGKILL` 在 +1s 兜底）。`RE`+`signal` 判定用真实硬件 fault 验证（如解引用空指针）；CPU 总量与文件输出上限因此依赖 hard 兜底 + 事后判定（§6）。父进程侧的 `cgroup.kill`/`SIGKILL` 投递不受影响。

## 6. 资源限制与计量

| 参数 | 建立（传了才做） | 计量（始终） | 判定 |
|---|---|---|---|
| `cpu_time_limit_ms` | `RLIMIT_CPU` soft=`ceil(ms/1000)`（到期 `SIGXCPU`，默认终止）、hard=soft+1（`SIGKILL`） | `cpu.stat usage_usec` | `WTERMSIG==SIGXCPU`，或结束后 `cpu_used > limit` → `TLE` |
| `wall_time_limit_ms` | epoll 超时 = deadline | `CLOCK_MONOTONIC`：发 "go" → `waitid` 返回 | 到期 → `cgroup.kill` → `TLE` |
| `memory_limit_bytes` | `memory.max`、`memory.swap.max=0`、`memory.oom.group=1` | `memory.peak`（等 `cgroup.events populated=0` 后读） | `memory.events` 的 `oom_kill` 或 `oom_group_kill` 计数 > 0，或结束后 `peak ≥ limit` 且非正常退出 → `MLE` |
| `stdout_limit_bytes` / `stderr_limit_bytes` | 管道：读到**超过**上限（恰等于不算）后置 `output_limit_hit` 并 `cgroup.kill`，继续读并丢弃；文件：`RLIMIT_FSIZE = max(两者)`（写入被钳在上限并返回 `EFBIG`；pid 1 丢弃内核发的 `SIGXFSZ`，见 §5 信号注记） | 实际收到的字节数 | `output_limit_hit`，或文件 **>** 各自上限，或文件恰好停在各自上限且运行非正常退出 → `OLE`。文件判定由宿主经 /work bind `stat`（`*_file` 解析后不在 /work 下且写入者是 fork 子进程的极端情况无法观测，判 `RE`） |
| `copy_out_limit_bytes` | 拷贝时截断检查 | — | 超过 → `CopyOutError` |
| `proc_limit` | `pids.max`、`RLIMIT_NPROC` | — | — |
| `open_file_limit` / `stack_limit_bytes` / `address_space_limit_bytes` | `RLIMIT_NOFILE` / `RLIMIT_STACK` / `RLIMIT_AS` | — | — |

关于 CPU 总量：cgroup v2 的 `cpu.max` 只限速率不限总量，没有"累计超 N 就杀"的 knob。本设计**不做任何周期检查**：单进程（含其全部线程）由 `RLIMIT_CPU` 内核级精确超时；fork 出的子进程各自计数，靶向由墙钟兜底，判定由结束后的 `cpu.stat` 给出。不做树级 `cpu.stat` 轮询。

判定优先级：`OLE` > `MLE` > `TLE` > `AC`/`RE`。

## 7. cgroup v2（rootless）

cgroup2 文件系统不能在 user namespace 内挂载，必须使用宿主上**被委托**的子树。

**进程级单例（`River` 首次构造时）**：

1. `/sys/fs/cgroup/cgroup.controllers` 存在，否则 `CgroupNotDelegatedError("cgroup v2 not mounted")`。
2. 从 `/proc/self/cgroup` 得到 `<base>`。
3. `<base>/cgroup.controllers` 必须含 `cpu`、`memory`、`pids`，否则未委托。
4. `mkdir <base>/river`，把自身 pid 写入 `<base>/river/cgroup.procs`（满足"启用 domain controller 的 cgroup 不能含进程"的约束）。
5. 向 `<base>/cgroup.subtree_control` 写 `+cpu +memory +pids`；`EACCES`/`EPERM` → 未委托；`EBUSY` → `<base>` 里还有别的进程（典型：外层 `uv run`/`make` 留下的父进程），报错里列出这些 pid。systemd 处理 `Delegate=yes` 时会把控制器启用到父级 slice 并一直保留，所以同一 slice 下之后新建的 scope 即使没写 `Delegate=yes` 也会通过 1–3 步，不能用"兄弟 scope"来模拟非委托环境。
6. 以上任一步失败 → `CgroupNotDelegatedError`，消息附修复命令：`systemd-run --user --scope -p Delegate=yes -- python app.py`（解释器必须是 scope 内唯一的进程，不要套 `uv run`），或把 river 放进 `Delegate=yes` 的 user service；普通 ssh 登录的 session scope 在 Ubuntu 24.04 上通常也是委托的。

**每次 exec**：`mkdir <base>/river-<pid>-<seq>`；按 §6 写 knob；clone 后把子进程 pid 写入 `cgroup.procs`；结束后 `rmdir`。清场一律 `cgroup.kill`（5.14+）。

## 8. 预检（`River.__init__` 与 `river.doctor()` 共用）

| 检查 | 失败 |
|---|---|
| 平台是 Linux | `RiverError` |
| `uname().release` ≥ 6.8 | `KernelTooOldError` |
| `/proc/sys/user/max_user_namespaces` > 0 | `UserNamespaceDeniedError` |
| `/proc/sys/kernel/apparmor_restrict_unprivileged_userns` 为 0 或不存在 | `UserNamespaceDeniedError`（附 `sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`） |
| fork 一个临时子进程做 `unshare(CLONE_NEWUSER)` 探测后退出 | `UserNamespaceDeniedError` |
| cgroup 委托（§7） | `CgroupNotDelegatedError` |
| rootfs 是目录；总是补建缺失的挂载点：目录 `proc`、`sys`、`dev/pts`、`dev/shm`、`dev/mqueue`、`tmp`、`work`，普通文件 `dev/null`、`dev/zero`、`dev/full`、`dev/random`、`dev/urandom`、`dev/ptmx`（已存在则跳过，只增不改，不碰其他任何文件）。补建失败（rootfs 只读等）且确实缺失 → `RootfsError`，消息指出缺的是哪个路径 | `RootfsError` |
| `meta.json` 可解析（存在时） | `RootfsError` |
| `/work` 宿主目录位置可用：`$XDG_RUNTIME_DIR/river` 否则 `/dev/shm/river-<uid>`（以 0700 创建，校验属主为当前用户） | `RiverError` |
| Landlock ABI 版本（信息项，`landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`） | 不失败，仅报告 |

`doctor()` 返回 `DoctorReport(checks=[Check(name, ok, detail, remediation)])`，`__str__` 打印表格；`raise_on_fail=True`（默认）时抛第一个失败的检查对应的异常，`remediation` 只在失败时有值。检查按固定顺序、固定名字排列（测试依赖这些名字）：`platform`、`kernel`、`userns.max`、`userns.apparmor`、`userns.probe`、`cgroup`、`workdir`、`landlock_abi`（信息项，永不失败）；rootfs 相关检查只在 `River.__init__` 做，不在报告里。`doctor()` 与 `River()` 共用同一份实现和同一个 cgroup 单例（§7），所以 `doctor()` 也会把调用进程停进 `<base>/river`——这正是 `River()` 会做的事，不是额外副作用。检查名到异常的映射只在实现里维护一处。

## 9. 沙箱内安全

**uid 映射**：单 uid；沙箱内 uid/gid 0 ↔ 宿主当前用户；`setgroups` 永久 deny。rootfs 必须由当前用户解压（否则文件显示为 `nobody`，640 文件/setuid 程序异常）。

**capabilities**：全部丢弃，`SECBIT_NOROOT|LOCKED`，所有挂载 `nosuid`。

**网络**：新 netns，只有 `lo`（up）。没有 veth、没有 DNS。

**Landlock**（总是开启）：处理的权限 = `WRITE_FILE`、`TRUNCATE`（ABI≥3）、`REMOVE_DIR`、`REMOVE_FILE`、`MAKE_CHAR`、`MAKE_DIR`、`MAKE_REG`、`MAKE_SOCK`、`MAKE_SYM`、`MAKE_FIFO`（ABI≥2）、`IOCTL_DEV`（ABI≥4），按内核 ABI 取交集；允许的位置：`/work`、`/tmp`、`/dev/shm` 全部处理权限，`/dev/pts` 与设备节点 `/dev/null`、`/dev/zero`、`/dev/full`、`/dev/random`、`/dev/urandom`、`/dev/ptmx` 授 `WRITE_FILE` + `IOCTL_DEV`（设备写入与设备 ioctl 都受 Landlock 管：不加 `WRITE_FILE` 连 `echo > /dev/null` 都失败，不加 `IOCTL_DEV` 则 `openpty` 的 `TIOCGPTN` 等设备 ioctl 被拒；PR 4 用 V9 验证）。读与执行不处理（rootfs 已只读）。在 `no_new_privs` 之后、`seccomp` 之前 `landlock_restrict_self`。内核不支持 Landlock（`landlock_create_ruleset` 返回 `ENOSYS`，ABI 0）时自动关闭并在 `RIVER_LOG=debug` 下警告，不算错误。

**seccomp**（denylist，总是开启；`RIVER_HARDENING=off` 时关闭）：

- `clone3` → 返回 `ENOSYS`（glibc 收到后回退到 `clone`）；`clone` 的 flags 参数 `SCMP_CMP_MASKED_EQ` 要求 namespace 相关位（`CLONE_NEWUSER|NEWNS|NEWPID|NEWNET|NEWIPC|NEWUTS|NEWCGROUP|NEWTIME|INTO_CGROUP`）为 0；`unshare`、`setns` → `EPERM`。沙箱内不能再创建任何 namespace。
- `socket` 只允许 `AF_UNSPEC/AF_UNIX/AF_INET/AF_INET6`；`AF_NETLINK`（nf_tables 攻击面）、`AF_PACKET`、`AF_ALG` 等 → `EPERM`。
- 挂载族：`mount umount2 pivot_root chroot fsopen fsconfig fsmount move_mount open_tree mount_setattr` → `EPERM`。
- 内核攻击面：`ptrace process_vm_readv process_vm_writev bpf perf_event_open keyctl add_key request_key userfaultfd io_uring_setup io_uring_enter io_uring_register kcmp pidfd_getfd name_to_handle_at open_by_handle_at memfd_secret` → `EPERM`。
- 系统级：`reboot kexec_load kexec_file_load init_module finit_module delete_module swapon swapoff settimeofday clock_settime clock_adjtime adjtimex adjtime sethostname setdomainname acct quotactl nfsservctl ioperm iopl syslog sysfs _sysctl uselib vhangup` → `EPERM`。`pidfd_open`、`pidfd_send_signal` 保留（沙箱内只能作用于自己 ns 里的进程）。
- fanotify 族（`fanotify_init fanotify_mark`）→ `EPERM`。
- 完整列表维护在 `src/sandbox/seccomp.rs` 的常量表里，以 syscall 名（`seccompiler` 按架构解析）而不是编号定义。

**不该暴露的东西**：宿主 `/sys/fs/cgroup`、`/proc/sys`（procfs 不加 `subset=pid`，兼容性优先）、宿主 `PATH`/`LD_*`（`envs` 从零构造）。

## 10. I/O

- **`/work` 宿主目录**：`$XDG_RUNTIME_DIR/river/<pid>/<id>`（tmpfs），否则 `/dev/shm/river-<uid>/<pid>/<id>`；exec 结束（无论成败）后删除。填满风险由 `memory.max`（tmpfs 页计入 memcg）+ `RLIMIT_FSIZE` + 结束即删兜底。
- **`copy_in`**：key 为沙箱内路径，相对路径相对 `cwd`，规范化后必须位于 `/work` 下，否则 `RootfsError`。值：`bytes`/`str`（UTF-8）= 内容；`os.PathLike` = 宿主文件（复制内容，不跟随到 `/work` 外）。`copy_in` 在 exec 之前写入宿主侧 `/work` 目录。
- **`copy_out`**：key 同上；value `None` → 内容进 `r.files[key]`；路径 → 覆盖写到宿主。读取用 `openat2(work_dir_fd, path, O_RDONLY|O_NOFOLLOW, RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)`，非普通文件 / 缺失 / 超过 `copy_out_limit_bytes` → `CopyOutError`（`.result` 已带）。
- **stdio**：见 §5 `child.stdio`；输出管道由父进程 epoll 循环收集进 `Vec<u8>`，上限后继续读并丢弃；进程退出后把管道剩余数据读完（计入上限判断）。

## 11. 工程结构

```
Cargo.toml                     # [lib] crate-type = ["cdylib", "rlib"]，pyo3 abi3-py312
pyproject.toml                 # maturin；[tool.maturin] module-name = "river._river", python-source = "python"
python/river/__init__.py       # from river._river import *；doctor() 的 Python 侧；类型
python/river/py.typed
src/lib.rs                     # #[pymodule] river._river
src/api.rs                     # River / ExecResult / 异常类
src/preflight.rs               # §8
src/cgroup.rs                  # §7
src/exec/mod.rs                # §3 父进程编排
src/exec/child.rs              # §5 子进程序列（无分配）
src/exec/mount.rs  caps.rs  seccomp.rs  landlock.rs  idmap.rs
src/exec/supervise.rs          # epoll 循环、信号检查、cgroup.kill
src/exec/io.rs                 # 管道、/work、copy_in/out（openat2）
tests/                         # pytest：functional / limits / attack / concurrency / doctor
docs/design.md  docs/example.py
```

依赖：`pyo3`、`libc`、`rustix`（mount/thread/process/fs/event/system/time）、`seccompiler`、`landlock`（crates.io 上的 crate 名；项目名 rust-landlock）、`caps`。不依赖 `zbus`、`cgroups-rs`、`tempfile`、`serde_json`（`meta.json` 经 Python 的 `json` 模块解析）。Python ≥ 3.12，`abi3-py312`。

测试环境：两套 Linux ≥ 6.8 环境——本地 WSL2（开发构建、快速 pytest）和一台远端 Linux（真实环境验证，内存较小）。rootless 路径必须用非特权账号验证；进程若不在委托 cgroup 里，用 `systemd-run --user --scope -p Delegate=yes ...` 启动。具体机器、账号、准备命令见 `docs/environment.local.md`（不入库）。

rootfs 制作（调用方文档同此）：

```sh
docker create --name py python:3.12-slim
docker export py | tar -xp --no-same-owner -C /path/rootfs/python   # 以运行 river 的用户执行
docker rm py
printf '{"envs":{"PATH":"/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin","HOME":"/work"}}' > /path/rootfs/python/meta.json
```

## 12. 实施顺序

| PR | 内容 | 验收 |
|---|---|---|
| 1 清场 + 骨架 ✅ 2026-11-24 | 删除旧实现全部代码与示例（Windows/macOS 后端、loopdev、examples、旧测试）；新 Cargo/pyproject/`python/river`；`river.doctor()` + 全部预检 | 两套环境上 `doctor()` 报告与本地环境记录一致（已达成） |
| 2 P0 沙箱 | clone3 → idmap → mount → pivot → caps → nnp → execve；父进程 epoll + 管道；计量；`AC/RE` | `python -c` 跑通；`docs/example.py` 全字段有值 |
| 3 P1 cgroup | §7 单例、run cgroup、限制 knob、`cgroup.kill`、`TLE/MLE/OLE` 判定 | 死循环 / 大内存 / 写爆 stdout / fork bomb 用例状态正确 |
| 4 P2 加固 | seccomp denylist、Landlock、`attack` 测试组 | 嵌套 userns、netlink、写 rootfs、symlink copy_out 全部被拒 |
| 5 P3 I/O | copy_in/out、`*_file`、`stdin`、meta.json、README | pytest 全绿，README 可照做 |
| 6 P4 发布 | manylinux wheel（docker 内构建）、版本号 | `pip install` 开箱即用 |

CI 不在本阶段范围内。

## 附录 A：内核特性门槛

| 特性 | 版本 | river 中的用途 | 无此特性时 |
|---|---|---|---|
| cgroup v2 统一层级 | 4.15+（发行版 2019+ 默认） | 全部资源限制 | 不支持 |
| `clone3()` / `open_tree` / `fsopen` / `fsmount` / `move_mount` | 5.2 | 新 mount API、带 ns flag 的 clone | 可用 `clone()` / `mount()` |
| procfs `subset=pid` | 5.8 | 隐藏 `/proc/sys` 等（默认不用） | — |
| unprivileged overlayfs（需 `userxattr`） | 5.11 | 不用（P3 可选项） | — |
| `mount_setattr`、idmapped mounts | 5.12 | 递归 rdonly/nosuid；idmapped 不用 | `mount(MS_REMOUNT)` 老坑 |
| Landlock | 5.13（ABI 逐版本增强，v6=6.12） | 文件系统写限制 | 自动关闭（实测：6.18 内核 ABI 7，7.0 内核 ABI 8，§9 列出的全部权限在两套环境都可用） |
| `cgroup.kill` | 5.14 | 原子清场 | kill pid 1 |
| `memory.peak` | 5.19 | 峰值内存 | `ru_maxrss` |
| `memory.oom.group` | 4.19 | OOM 整组杀 | — |
| `memory.peak` 写入重置 | ~6.11/6.12（未核实） | 不需要 | — |
| Ubuntu AppArmor userns 限制 | 23.10+/24.04 | 需 sysctl 放行 | — |

`MIN_KERNEL = 6.8`，启动时 `uname()` 检查并给出明确报错。

## 附录 B：参考资料

### 内核文档与补丁

- `user_namespaces(7)`：https://sources.debian.org/src/manpages/6.03-2/man7/user_namespaces.7/
- cgroup v2 文档：https://docs.kernel.org/admin-guide/cgroup-v2.html
- `cgroup.kill` 加入 5.14（Tejun Heo 的 pull request）：https://lkml.org/lkml/2021/7/1/573
- `memory.oom.group` 提交（2018-08，v4.19）：https://android.googlesource.com/kernel/common/+/3d8b38eb81cac81395f6a823f6bf401b327268e6
- `memory.peak` 写入重置补丁（2024-07）：https://marc.info/?l=linux-mm&m=172230707908018&q=mbox
- `FS_USERNS_MOUNT` 只给 cgroup v1 的 patch（2015）：https://lkml.org/lkml/2015/12/7/1098
- procfs `subset=pid` since 5.8：http://yhbt.net/lore/linux-man/CAFnufp1U8Tp2hpgAPi-aEhXdVVoUqeZdqbHd1RbYiu_OqQRLEA@mail.gmail.com/#R
- idmapped mounts / `mount_setattr`（Linux 5.12）：https://kernelnewbies.org/Linux_5.12
- 非特权 overlayfs（5.11）：https://github.com/xanmod/linux/commit/7fa2e79a6bb924fa4b2de5766dab31f0f47b5ab6
- `userxattr` 的必要性（moby overlayutils）：https://pkg.go.dev/github.com/moby/moby/v2/daemon/graphdriver/overlayutils
- Landlock 内核文档：https://docs.kernel.org/userspace-api/landlock.html ；2026-10 现状报告：https://landlock.io/talks/2026-10-08_landlock-lss.pdf

### rootless cgroup 委托

- BenchExec 论文《cgroups v2 Support for BenchExec》（委托、`systemd-run -p Delegate=yes`、dbus-user-session 依赖）：https://www.sosy-lab.org/research/bsc/2022.Gloster.Cgroups_v2_Support_for_BenchExec.pdf
- systemd resource-control（`Delegate=`）：https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html
- Podman troubleshooting §2.6（rootless 资源限制权限错误）：https://github.com/containers/podman/blob/main/troubleshooting.md
- Ubuntu cgroup v2 委托与 `+` ACL 说明（2026 文章，二手来源）：https://computingforgeeks.com/ubuntu-2604-cgroup-v2-migration/

### 参考实现

- go-judge 设计文档（状态枚举、cgroup 行为、`memory.peak` / maxrss 回退）：https://docs.goj.ac/cn/design
- go-judge 挂载点与 tmpfs 参数：https://docs.goj.ac/mount
- go-judge 配置项（`-no-fallback`、`-time-limit-checker-interval`、`-copy-out-limit`）：https://docs.goj.ac/cn/configuration
- nsjail `mount.c`（`MS_REC|MS_PRIVATE`、`pivot_root`）：https://android.googlesource.com/platform/external/nsjail/+/be25a24b5b04f3fa5852c262739b22c4368a0465%5E%21/mount.c
- `pivot_root(".", ".")` 与 `MS_SLAVE|MS_REC` 讨论：https://lists.linuxfoundation.org/pipermail/containers/2019-October/040665.html
- systemd `namespace.c`（procfs hidepid/subset 的实际用法）：https://github.com/systemd/systemd/blob/d69ee5acdccec762b6b58b5b79902be14bb54a98/src/core/namespace.c
- youki 开发文档（Rust 容器运行时，clone → init 流程）：https://youki-dev.github.io/youki/developer/youki.html
- Docker 默认 seccomp profile（`clone3` ENOSYS、`clone`/`unshare` 的 masked 过滤）：https://docs.docker.com/engine/security/seccomp/

### 安全

- Ubuntu AppArmor userns 限制说明：https://discourse.ubuntu.com/t/understanding-apparmor-user-namespace-restriction/58007
- CVE-2024-1086（nf_tables）：https://ubuntu.com/security/CVE-2024-1086
- CVE-2023-0386（overlayfs）：https://ubuntu.com/security/CVE-2023-0386

### Rust 生态

- `rustix::mount` 模块（mount / pivot_root / fsopen / open_tree / move_mount）：https://docs.rs/rustix/0.38.31/rustix/mount/
- `seccompiler`：https://docs.rs/seccompiler
- PyO3：https://pyo3.rs/ ；maturin：https://www.maturin.rs/
- `nix::sched::clone` 与 `CLONE_NEWUSER` 的 uid 映射问题：https://stackoverflow.com/feeds/question/79090668
