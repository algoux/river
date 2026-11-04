# Linux 后端技术文档

支撑环境：Linux 5.9+（`close_range`）、cgroups v2（含 `memory.peak` /
`memory.swap.max`）、seccomp-bpf、systemd 宿主的 root judger。除
`seccompiler`（纯 Rust 的 BPF 编译库）外零外部依赖：不引 nix、不 shell out、
系统调用直发。

## 1. 三层防御

### 身份与文件系统：namespace + pivot_root

单次 run 的挂载布局（supervisor A 在 unshare 后构建）：

```
<workdir>/root                 tmpfs（mode 755，nosuid,nodev，MS_PRIVATE）
├── cwd/                       bind mount ← 宿主 per-run workdir（rw）
│   ├── tmp/                   TMPDIR（在同一个 bind 内）
│   └── .river/<name>          宿主可执行文件注入点（ro bind，按需）
├── proc/                      B 在自己的 pid ns 内挂载的新 procfs
├── dev/                       tmpfs + null/zero/random/urandom/tty（0666）
├── runtimes/<n>/              调用方 runtimes，bind + remount ro,nosuid,nodev
└── usr lib lib64 bin sbin etc 系统目录，bind + ro,nosuid,nodev（见下）
```

**rootfs 模式**（`Sandbox(rootfs=...)`）：调用方提供的根树 **整体替换** 上表
中的"系统目录"层——不再并入任何宿主系统目录，rootfs 必须自包含（动态链接
器、libc、shell 都在里面）。实现是 **overlayfs**：

```
mount -t overlay -o lowerdir=<rootfs>,upperdir=<workdir>/upper,workdir=<workdir>/ovl-work <root>
# 在 merged 视图里 mkdir /cwd /proc /dev /.oldroot 与各 runtime bind 目标
# （落在 per-run 的 upper tmpfs 层，宿主 rootfs 树零写入）
mount -o remount,ro,nosuid,nodev <root>     # 冻结 rootfs 视图
# 之后的 cwd bind（rw）、/dev tmpfs、runtimes ro bind、pivot_root 与默认模式相同
```

- 宿主 rootfs 是 **只读 lower 层**，永远不会被写入——包括不需要在调用方树里
  预建 `/cwd`、`/proc` 等挂载点（纯 ro bind 做不到这一点：挂载点必须先存在）。
- remount ro 后 rootfs 视图冻结；唯一可写处仍是 `/cwd`（bind 在 ro overlay
  之上）。upper 层随 workdir 每次 run 销毁。
- `executable` 坐标系变为 **rootfs 内路径**（如 `/usr/bin/python3`），不做宿主
  注入；rootfs 里不存在即 exec 失败（`SE`）。
- 构造期校验：绝对路径、存在、非 `/`；路径含 `,` 或 `:` 会被拒绝（它们是
  overlay options 的分隔符）。

`pivot_root(root, root/.oldroot)` 后 `umount2("/.oldroot", MNT_DETACH)`，
宿主文件系统完全不可见。

**系统目录为什么总是只读并入**：动态链接器、libc、shell 是任何二进制启动的
前提。这是 Windows 后端"System32 永远可读"规则的 Linux 对应物（DESIGN §4）。

**copy_in 只读**：文件 root 属主 + mode 0444；程序以 nobody(65534) 运行。
目录（cwd 树）递归 chown 给 nobody，否则程序连文件都建不了。

### 权限围栏（setuid 面归零）

降权之后、exec 之前按顺序执行：

1. `PR_SET_DUMPABLE=0`（`setuid` 会重置它，必须在其后设置）；
2. `PR_SET_NO_NEW_PRIVS=1` —— **必需**：否则 `/usr` 里任何 setuid/capability
   二进制都会让程序拿到初始 user namespace 的真实 uid 0；
3. `capset` 清零 permitted/effective/inheritable；
4. rlimits：`CORE=0`、`NOFILE=1024`、`FSIZE=64MB`、
   `CPU=ceil(time_limit)+1s`（主动轮询的兜底）；
5. seccomp allowlist（默认 `EPERM`）。

所有只读 bind 都带 `nosuid,nodev`（`/dev` 的 tmpfs 只加 `nosuid`，否则设备
节点不可用）。`/etc`、`/usr` 仍整目录只读并入——`/etc` 的信息暴露面属于已知
取舍（含 `passwd`/`hosts`/`machine-id`；`shadow` 因 nobody 不可读）。

### 系统调用：seccomp allowlist

`seccompiler` 在 **judger 进程内编译一次**，BPF 程序跨 fork 传给 B 再
`apply`（子进程不做任何分配）。默认动作 `EPERM`（不是 `KILL`：正常运行时
只应看到普通 errno）。

关闭的对象（命名空间无法隔离的集合）：

- `keyctl`/`add_key`/`request_key`（按 uid 共享的 keyring）
- 任何 `socket()`（`socketpair` 保留给本地 IPC）；`AF_VSOCK`
- `io_uring_*`、`flock`、`ptrace`、`process_vm_*`、`pidfd_*`、`kcmp`
- `mount*`/`pivot_root`/`chroot`/`unshare`/`setns`/`open_tree`/`fsmount`/
  `mount_setattr`（**含 user namespace 创建**）
- `bpf`/`perf_event_open`/`userfaultfd`/`mknod*`/模块加载/`reboot`/`kexec*`/
  `swapon*`/`clock_settime`/`sethostname`

其余（CPython、动态链接器、shell、普通编译产物所需）无条件放行；新增语言
运行时前先跑一遍 AC 回归，缺 syscall 的表现是 `SIGSYS`（exit 159）。

### 可执行文件注入

默认模式（无 rootfs）：`executable` 是宿主路径（契约）。若该路径不在任何已
bind 的目录（系统目录或 `runtimes`）之下，setup 时把它 **只读 bind 到
`/cwd/.river/<name>`** 并从那里 exec（`argv[0]` 同步改为沙箱内路径）。无需
复制、无需调用方把宿主任意目录塞进 `runtimes`。若可执行文件本身已在 bind
覆盖范围内（如 venv 的 python），则原路径直接执行。

rootfs 模式：`executable` 是 **rootfs 内路径**，直接 exec、不做宿主注入
（见 §1 rootfs 模式）。

### 网络拒绝（无条件）：network namespace

空 netns 没有任何 up 的接口（**连 lo 都不启用**）：connect/EAGAIN、DNS 均
失败，比防火墙规则更彻底。网络拒绝是无条件保证——不是能力开关，任何平台、
任何配置下都不允许目标应用连接网络；seccomp 允许列表同时不包含 `socket`
等网络系统调用（纵深防御）。

### 资源与进程树：cgroups v2

```
/sys/fs/cgroup/river/cgroup.subtree_control  "+memory +pids"
/sys/fs/cgroup/river/run-<judger-pid>-<n>/
    memory.max       调用方限额，或物理内存（"不设限"仍受机制约束）
    memory.swap.max  0（必须：否则 swap 让慢速分配器停在 cap 之下）
    pids.max         存活进程上限 + 1（supervisor 占 1，程序额度不变）
    cpu.stat         usage_usec（整棵树 CPU，证据 + 主动限额来源）
    memory.peak      整棵树峰值 RSS+page cache（内存证据）
    memory.events    oom_kill（MLE 的直接证据 → Status.oom_killed）
    cgroup.procs     成员枚举：残余子孙检测
    cgroup.kill      "1" = 原子杀整棵子树（内核 5.14+，有回退）
```

cgroup 根可用环境变量 `RIVER_CGROUP_ROOT` 指向被委托的层级（默认
`/sys/fs/cgroup`）。

**supervisor 自己写 `cgroup.procs`**（setsid 之后、fork 程序之前）：成员身份
必须早于程序的第一次分配，而从 judger 侧写入会与 supervisor 的 fork 竞态。

### 进程树策略：pid namespace + watchdog

- 程序 B 是 pid ns 内 PID 1：主进程退出 → 内核杀死 ns 内所有子孙（防甩锅
  的机制面）。
- 残余检测仍由 `cgroup.procs` 完成：收尸后 100ms 宽限期内非空 → 残余计数
  → 契约层判 `SE`（与 Windows §5.4 的异步竞态处理同构）。
- 超时/输出超限/CPU 超限的杀路径：`kill(-pgid, SIGKILL)`（supervisor
  setsid 后 pgid = supervisor pid，整棵树继承）+ `cgroup.kill` 兜底。

## 2. 执行管线（单次 run）

```
validate(spec)
  ① workdir：创建 per-run 目录 + copy_in 落盘(0444) + 目录 chown nobody
  ② stdio：3 组管道（stdin/stdout/stderr），CLOEXEC
  ③ cgroup：创建 run 目录，写 memory.max / memory.swap.max=0 / pids.max
  ④ fork A（supervisor）：
       setsid → 写 cgroup.procs → PDEATHSIG → unshare(6 个 ns)
       → sethostname("river") → mount(/ MS_PRIVATE)
       → tmpfs 根 + binds(ro,nosuid,nodev) + 可执行文件注入 → pivot_root
       → 写 "ok\n" 到 ready 管道 → fork B → close(3) → wait4(B) → _exit(code)
     fork W（watchdog）：轮询 getppid()，judger 死亡即 kill(-A)
  ⑤ B：PDEATHSIG → mount /proc → setgroups/setgid/setuid(nobody)
        → dumpable=0 → no_new_privs=1 → capset 清零 → rlimits → seccomp
        → chdir(/cwd[/rel]) → execvpe
  ⑥ monitor：wait4(A)（rusage 聚合 A+B）+ 2ms 轮询墙钟/OLE 事件
             + 10ms 轮询 cpu.stat（超限即杀，KillOrigin::CpuLimit）
  ⑦ 证据：cgroup cpu.stat / memory.peak / memory.events / 残余计数
          → classify → Status（含 oom_killed）
  ⑧ 清理：cgroup.kill → wait_until_empty → rmdir → workdir Drop → watchdog 收尸
```

## 3. 判定与测量

| 证据 | 来源 | 语义 |
|---|---|---|
| CPU 时间 | `cpu.stat usage_usec` | 整棵树，含已退出的子进程；10ms 轮询主动限额 |
| 墙钟 | `Instant` | 看门狗（2ms 轮询） |
| 峰值内存 | `memory.peak` | **RSS + page cache**，不是 Windows 的 commit |
| OOM | `memory.events` `oom_kill` | 直接证据 → `Status.oom_killed`，优先于 peak 推断 |
| 残余子孙 | `cgroup.procs` | 收尸后 100ms 宽限期，排除已死主进程的异步残留 |
| 退出码 | `wait4` | 正常 `WEXITSTATUS`；信号终止 `128+WTERMSIG`（OOM → 137） |

内存语义差异（写进 DESIGN §5）：page cache 计入 `memory.peak`，读大文件会
抬高峰值；`malloc` 不写不占 RSS。`mle_peak_slack_bytes` 的 slack 参数在
Linux 样本上回归通过（1/8 限额 + 1MB 下限），OOM 事件命中时不受该 slack 约束。

## 4. 与 Windows 后端的语义差异

| 方面 | Windows | Linux |
|---|---|---|
| 内存限额语义 | commit | RSS + page cache（`memory.swap.max=0`） |
| OOM 证据 | 无（分配失败） | `memory.events` → `Status.oom_killed` |
| CPU 限额执行 | Job CPU 限额 + 墙钟；判定按实测 CPU | 10ms `cpu.stat` 轮询主动杀 + `RLIMIT_CPU` |
| 系统调用过滤 | win32k/mitigation policy | seccomp allowlist（默认 EPERM） |
| 异常终止 exit_code | NTSTATUS (如 0xC0000005) | `128+sig`（如 139/137） |
| 残余子孙判定 | Job 进程列表 | `cgroup.procs` + 100ms 宽限 |
| 主进程死后子孙 | Job 强杀 + SE | pid ns init 退出即内核杀光（AC 也可） |
| rootfs | 不支持 | 只读 overlayfs 替换沙箱根；executable 为 rootfs 内路径 |
| 计时抖动 | 较大（5-10% 放宽） | 较小；CPU 超调 ≤10ms |
| 部署检查 | — | `river.doctor()` + 构造期 fail-closed |

## 5. 测试

```shell
sudo -E uv run pytest        # 打印各判定与证据（root 必需）
```

测试必须以 root 运行（unshare/挂载/cgroup 写入需要 `CAP_SYS_ADMIN`）。
套件分布：`test_functional.py` / `test_conformance.py` 平台无关；
`test_attack.py` 仅 Windows；`test_attack_linux.py` / `test_cleanup_linux.py`
仅 Linux；`test_rootfs_linux.py` 仅 Linux（rootfs 模式）。断言纪律同 Windows
（去掉机制必须失败）。
