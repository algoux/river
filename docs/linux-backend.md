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
- 构造期校验：绝对路径、存在（目录或 squashfs 镜像文件）、非 `/`；目录形式
  的路径含 `,` 或 `:` 会被拒绝（它们是 overlay options 的分隔符）。
- **squashfs 镜像**：`rootfs` 指向常规文件时校验 magic（`hsqs`），经
  `/dev/loop-control` 选空闲 loop 设备 → `LOOP_SET_FD` 绑定镜像 → 以
  `MS_RDONLY|MS_NOSUID|MS_NODEV` 挂载 squashfs 到 `<workdir>/sqfs`（宿主
  namespace，fork 时被 supervisor 的私有 ns 继承），该挂载点即 overlay
  lowerdir。镜像路径可以含逗号/冒号（lowerdir 用的是挂载点）。loop 绑定与
  挂载由父进程 `LoopGuard` RAII 释放（`umount2(MNT_DETACH)` +
  `LOOP_CLR_FD`），时序上晚于 copy_out 回收。无 `/dev/loop-control`（常见
  于容器宿主）或 squashfs 模块不可加载 → 明确报错，不静默降级。

`pivot_root(root, root/.oldroot)` 后 `umount2("/.oldroot", MNT_DETACH)`，
宿主文件系统完全不可见。

**系统目录为什么总是只读并入**：动态链接器、libc、shell 是任何二进制启动的
前提。这是 Windows 后端"System32 永远可读"规则的 Linux 对应物（DESIGN §4）。

**copy_in 只读（内容不可改）**：文件 root 属主 + mode 0444，程序以 per-run
leased uid 运行（见下）。只有 **workdir 根与 `tmp/`** chown 给该 uid（否则程序
连文件都建不了）；`copy_in` 目录保持 root 属主 0755——可读、可进入、不可写。
属主才能 `chmod`，因此程序既不能改写输入也不能清掉写保护（旧实现把整棵树
chown 给 nobody，属主 chmod 后即可改写，已修）。程序仍拥有 cwd 根，所以可以
删除/重命名自己 cwd 里的条目：内容不变、无外泄，语义上接受。`copy_in` 值为
宿主机目录时递归投放（常规文件与子目录；符号链接跳过）。

**per-run uid 租约**：每个 run 从固定高位 uid 区间独占租一个 uid/gid
（`RIVER_UID_BASE`/`RIVER_UID_COUNT`，默认 `[100000, 100064)`）。租约是
`<tmp>/river-uidpool/<uid>` 上的 `flock`：judger 被硬杀时内核自动释放，无需
清扫。旧实现固定降权到 `nobody(65534)`，任何同 uid 的宿主机进程都能读写活跃
run 的 workdir（实测 `setpriv --reuid=65534 cat <workdir>/secret.txt` 成功），
并发 run 之间同样无隔离；租约 uid 关闭了这条横向通道。池耗尽时阻塞（20ms
轮询），与 Windows slot 池语义一致。`doctor()`/首次租约会检查区间与
`/etc/passwd` 冲突——冲突是构造期错误（fail closed）。

**copy_out 回收**：运行结束（monitor 返回后、workdir Drop 前）由 root
judger 把产物拷回宿主路径。**永不跟随符号链接**：程序可以植入指向宿主任意
路径的链接，跟随即任意文件外泄——链接条目跳过，文件打开带 `O_NOFOLLOW`
（防 TOCTOU）。源缺失跳过（可选产物）；`copy_out_limit_kb` 是回收总字节
配额：超限的文件不收（无半截文件）、停止回收并上报 `KillOrigin::CopyOutQuota`
→ 契约层判 `OLE`。

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
取舍（含 `passwd`/`hosts`/`machine-id`；`shadow` 因非 root 不可读）。

### 系统调用：seccomp allowlist

`seccompiler` 在 **judger 进程内编译一次**，BPF 程序跨 fork 传给 B 再
`apply`（子进程不做任何分配）。默认动作 `EPERM`（不是 `KILL`：正常运行时
只应看到普通 errno）。

关闭的对象（命名空间无法隔离的集合）：

- `keyctl`/`add_key`/`request_key`（按 uid 共享的 keyring）
- 任何 `socket()`（`socketpair` 保留给本地 IPC）；`AF_VSOCK`
- `io_uring_*`、`flock`、`ptrace`、`process_vm_*`、`pidfd_*`、`kcmp`
- `mount*`/`pivot_root`/`chroot`/`unshare`/`setns`/`open_tree`/`fsmount`/
  `mount_setattr`
- **`clone` 的参数掩码**：仅当 flags（x86_64 arg0）不含任何
  `CLONE_NEWNS/NEWUSER/NEWPID/NEWNET/NEWIPC/NEWUTS/NEWCGROUP` 时放行；否则
  `clone(CLONE_NEWUSER)` 会拿到新 userns 里的 `CAP_SYS_ADMIN`，重新打开
  allowlist 刻意关闭的内核面（旧实现无条件放行，实测能进真实的新 userns）。
- **`clone3` 强制 `ENOSYS`（叠加预过滤器）**：seccomp 无法解引用
  `clone3` 的 `struct clone_args` 指针，参数掩码不可用；而 glibc ≥2.34 的
  `pthread_create` 遇到 `EPERM` 不回落（只有 `ENOSYS` 回落到 `clone`）。解法
  是在 allowlist 之上再叠一个小过滤器，把 `clone3` 无条件判 `ENOSYS`——线程
  创建照常（glibc 回落），`clone3(CLONE_NEWUSER)` 通道关闭。实测：修复前沙箱
  内 `clone3(CLONE_NEWUSER)` 成功、子进程在新 userns 内 `CapEff` 全 1（宿主
  的 AppArmor userns 限制也拦不住）；修复后返回 `ENOSYS(38)`。直接调用
  `clone3` 且不回退的程序（罕见，如容器运行时）会得到 `ENOSYS`——已知代
  价。`doctor()` 仍报告 `userns_allowed`/`apparmor_userns_restrict` 供部署
  诊断（针对宿主上其他进程的 userns 创建，不是沙箱内的）。
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
  ① workdir：租 per-run uid + 创建目录 + copy_in 落盘(0444) + 目录 chown 该 uid
  ② stdio：3 组管道（stdin/stdout/stderr），CLOEXEC
  ③ cgroup：创建 run 目录，写 memory.max / memory.swap.max=0 / pids.max
  ④ fork A（supervisor）：
       setsid → 写 cgroup.procs → PDEATHSIG → unshare(6 个 ns)
       → sethostname("river") → mount(/ MS_PRIVATE)
       → tmpfs 根 + binds(ro,nosuid,nodev) + 可执行文件注入 → pivot_root
       → 写 "ok\n" 到 ready 管道 → fork B → close(3) → wait4(B) → _exit(code)
     fork W（watchdog）：轮询 getppid()，judger 死亡即 kill(-A)
  ⑤ B：PDEATHSIG → mount /proc → setgroups/setgid/setuid(leased uid)
        → dumpable=0 → no_new_privs=1 → capset 清零 → rlimits → seccomp
        → chdir(/cwd[/rel]) → execvpe
  ⑥ monitor：poll(pidfd(A), OLE eventfd) 事件驱动等待（墙钟为 poll 超时；
             无 pidfd 的内核回退 2ms 轮询）；CPU 限额时 poll 超时取 10ms，
             每拍读 cpu.stat，超限即杀（KillOrigin::CpuLimit）
  ⑦ 证据：cgroup cpu.stat / memory.peak / memory.events / 残余计数
          → classify → Status（含 oom_killed）
  ⑧ 清理：cgroup.kill → wait_until_empty → rmdir → workdir Drop → watchdog 收尸
```

## 3. 判定与测量

| 证据 | 来源 | 语义 |
|---|---|---|
| CPU 时间 | `cpu.stat usage_usec` | 整棵树，含已退出的子进程；10ms 轮询主动限额 |
| 墙钟 | `Instant` + `poll` 超时 | 事件驱动（无唤醒开销；旧内核回退 2ms 轮询） |
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
| CPU 限额执行 | 10ms Job accounting 轮询主动杀（整树 user+kernel） | 10ms `cpu.stat` 轮询主动杀 + `RLIMIT_CPU` |
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
