# river 设计文档

river 是一个沙箱库（Python 扩展，Rust 实现），用于在受限环境中运行不受信任的
可执行文件并采集资源用量与结果。对标 go-judge 的 `exec` 语义，但不做判题比对——
比对/checker 永远是调用方（OJ 判题层）的职责。

## 1. 沙箱模型

所有平台共享同一个心智模型，差异只在实现机制：

```
私有可写 cwd     每次 run 新建的临时工作目录，块退出即销毁
+ runtimes       宿主机目录以只读(+执行)方式并入沙箱（运行时环境）
+ copy_in        每 run 投放的私有文件（程序对它们默认只读）
+ env            增量合并进白名单基底
```

被测程序能看到的文件系统面只有这三块，其余宿主目录不可见。

| 能力 | Linux | macOS | Windows |
|---|---|---|---|
| 状态 | ✅ 已实现（L5，rootfs 待 L6） | 待更新 | ✅ 已实现 |
| `rootfs` | 阶段 L6（现在传入即 `ValueError`） | sandbox-exec profile | ❌ 传入即 `ValueError` |
| `runtimes` 实现 | 只读 bind mount（+ 系统目录只读） | 只读 profile 扩展 | AppContainer + 只读 ACL |
| 网络隔离 | namespace（空 netns） | profile | AppContainer 无 capability 即断网 |
| 资源限制 | cgroup v2（memory/pids） | — | Job Object |

Windows 不支持 `rootfs`：Windows 进程永远从真实 `System32` 加载系统 DLL，
"另一份操作系统"的语义不成立（除非容器/虚拟化，明确排除）。运行时环境
（Python、JDK 等）通过 `runtimes` 授权直读 + `env` 注入 PATH 组合出来。

Linux 的对应取舍：动态链接器/libc/shell 是任何程序启动的前提，因此
`/usr /lib /lib64 /bin /sbin /etc` 始终以只读方式并入沙箱——这是
"System32 永远可读"规则的 Linux 对应物；`runtimes` 在此基础上提供运行时
目录。技术细节与踩坑记录见 [docs/linux-backend.md](docs/linux-backend.md)。

## 2. API 契约

完整签名见 `river.pyi`，用法见 `examples/example.py`。

### 2.0 能力内省

```python
river.capabilities()
# {'platform': 'windows', 'rootfs': False, 'network_isolation': True,
#  'concurrent_runs': True, 'default_max_processes': 64,
#  'internal_wall_limit_secs': 86400}
```

调用方（OJ 调度层）据此程序化适配平台差异，无需 try/except 探测。

### 2.1 Sandbox 构造

```python
river.Sandbox(rootfs=None, runtimes=None, max_wall_secs=None, max_processes=None)
```

- `rootfs` —— Windows 传入抛 `ValueError`
- `runtimes` —— 只读运行时目录
- `max_wall_secs` / `max_processes` —— 收紧（不可禁用）内部安全上限；
  默认 24h 墙钟 / 64 存活进程。"不设限"只是调用方语义，机制永远存在。

### 2.2 run() 参数

| 参数 | 坐标系 | 默认值语义 |
|---|---|---|
| `executable` | 宿主机路径 | 必填 |
| `args` | — | `[]` |
| `cwd` | **沙箱内相对路径** | 沙箱根（私有 cwd） |
| `env` | — | 仅白名单基底 |
| `time_limit_ms` | — | `None` = 不限制 |
| `wall_time_limit_ms` | — | `None` = 不限制；仅设 `time_limit_ms` 时默认 `2×time_limit_ms + 1000` |
| `memory_limit_kb` | — | `None` = 不限制 |
| `stdin` / `stdin_file` | — | 互斥（同给抛 `ValueError`）；`stdin_file` 零拷贝优先 |
| `copy_in` | 键为沙箱相对路径 | 程序对文件默认**只读** |
| `stdout_limit_kb` / `stderr_limit_kb` | — | 击杀阈值：超过即杀并判 OLE |
| `stdout_file` / `stderr_file` | 宿主机路径 | 完整输出留档（截至被杀为止）；与 `r.stdout`（截断 bytes）并存 |

**限制语义与机制的区分**：`None` 表示*调用方不设限*，但后端始终存在内部安全
上限（wall clock ≤ 24h、内存 ≤ 物理内存）——"无限"不能意味着防护机制不存在。

参数校验：`stdin` 与 `stdin_file` 互斥；`copy_in` 键必须是沙箱内相对路径
（拒绝绝对路径、盘符、`..` 逃逸）；`copy_in` 值必须是 bytes 或宿主机路径。
校验失败抛 Python 异常，不走 `SE`。

### 2.3 Status 字段

| 字段 | 说明 |
|---|---|
| `time_used_ms` / `wall_time_used_ms` | CPU 时间 / 墙钟时间（ms）；TLE 判定取两者超限的并集 |
| `memory_used_kb` | 峰值内存（KB） |
| `status` | `AC` / `TLE` / `MLE` / `OLE` / `RE` / `SE` |
| `signal` | **合成值**：正常 0，沙箱强杀为 9（模仿 Linux 惯例便于移植） |
| `exit_code` | 原始退出码；异常终止时为 NTSTATUS 值 |
| `oom_killed` | 是否被内核 OOM killer 收割（Linux：`memory.events` `oom_kill>0`；Windows 恒为 false） |
| `stdout` / `stderr` | 截断后的输出 |
| `stdout_truncated` / `stderr_truncated` | 各通道独立的截断标志 |

判定含义：`AC` 正常退出；`TLE` CPU/墙钟超限；`MLE` 内存超限；`OLE` 输出超限；
`RE` 非零退出/异常终止；`SE` 沙箱自身错误或检测到残余子孙。

### 2.4 `with` 块退出协议

`__exit__` 保证：无残留被测进程、临时工作目录已删除、令牌/句柄已释放。

## 3. 关键设计决策

1. **stdin 优先 Path，bytes 作便捷项**：大测试点文件走 `stdin_file` 零拷贝；
   bytes 起喂线程。
2. **输出三机制分离**：`*_limit` 是击杀阈值、`*_file` 是完整留档、`r.stdout`
   是截断采样。
3. **copy_in 一律只读**：硬链接优化只有在拒绝写 ACE 下才安全，否则被测进程
   可篡改宿主源文件。不做"可写白名单"。
4. **copy_in 不走 MoveFile**：移动保留源 ACL，拷贝继承目标目录 ACL；落盘后
   显式重置 ACL。
5. **不做交互题**：实时双向管道不塞进 run 参数。
6. **进程策略（分层）**：主进程是唯一的被评测对象；允许普通包装器
   （`cmd /c`、解释器辅助进程）派生，存活总数有上限，fork 炸弹有界。
   **主进程退出即终止全部残余子孙**——程序不得把工作甩给子进程在主进程死后
   继续产出；检测到残余子孙时判 `SE` 而非误导性的 `AC`。
7. **`SE` 的语义范围**：沙箱自身错误（spawn 失败、清理失败）或主进程死后仍有
   存活子孙。参数校验失败仍抛 Python 异常。
8. **判定以证据优先**：沙箱强杀与限额证据的优先级高于进程的原始退出码
   （被强杀的进程退出码往往无意义）。

### 3.1 分层架构（contract / backend）

- `contract` —— 平台无关的冻结契约：`RunSpec` 校验、`RunEvidence → Verdict`
  判定（纯函数 `classify`，唯一权威实现）、`Status` pyclass。平台后端只
  上报观测证据（`RunEvidence`：kill 来源、退出码、残余进程数、CPU/内存
  实测与有效限额），判定永远在契约层完成——"证据优先于退出码"只写一次、
  测一次，Linux 落地时不会被平台机制带偏。
- `backend` —— 平台机制（进程隔离、资源限制、stdio）。Windows 的
  AppContainer / Job Object / Mitigation Policy 是这些机制的实现，不是
  判定逻辑的一部分。`river.capabilities()` 由后端提供能力矩阵。

## 4. Windows 实现要点

三层防御，缺一层即有对应攻击面：

- **身份与文件系统**：AppContainer。子进程在创建时携带 AppContainer SID，
  令牌无 capability 即默认断网；文件系统可见面由 ACL 显式授权。
- **资源与进程**：Job Object。内存上限（commit 语义）、CPU 时间上限、存活
  进程总数上限、`KILL_ON_JOB_CLOSE` 兜底。墙钟由看门狗保证。
- **内核攻击面**：创建时 Mitigation Policy，禁用 win32k 系统调用与 DLL 注入式
  hook 扩展点。

技术细节与实测数据见 [docs/windows-backend.md](docs/windows-backend.md)。

## 5. 平台行为特性

调用方按这些特性使用 API：

- **内存语义**：Windows 的内存限制约束 commit 而非 RSS；惰性提交意味着
  `malloc` 大块不写入不触发 MLE。Linux 约束 cgroup 的 RSS + page cache：
  读大文件会抬高 `memory_used_kb`，而 `malloc` 不写不计入。
- **计时抖动**：Windows 计时受调度/Defender/缺页影响大于 Linux，建议调用方
  放宽 5-10% 或取两次较优。实测稳定态抖动远低于该窗口，但宿主机偶发卡顿会
  抬高单次样本——取两次较优更稳妥。Linux 抖动较小，但仍建议留 5% 余量。
- **并发**：`Sandbox` 可被多个 Python 线程并发 `run()`（两个平台都成立）。
- **signal**：始终为合成值。`exit_code` 的平台差异：Windows 异常终止透传
  NTSTATUS（如 `0xC0000005`）；Linux 信号终止为 `128 + signo`（OOM 杀为
  137，段错误为 139）。`oom_killed` 是 Linux 专属的直接证据（Windows 恒为
  false，其内存限额让分配失败而非触发 OOM killer）。
- **linux 资源执行**：CPU 限额每 10ms 轮询 `cpu.stat` 并主动杀（超调上界
  约 10ms，另有 `RLIMIT_CPU` 兜底）；内存限额同时写 `memory.swap.max=0`，
  否则 swap 会让慢速分配器一直停在 cap 之下逃过 OOM（实测：有 swap 时在
  64MB 限额下存活满 20s 墙钟，`swap.max=0` 后 1.6s 被 OOM 杀）；单文件写入
  受 `RLIMIT_FSIZE`（64MB）约束。Linux 以 seccomp allowlist 默认拒绝
  （`EPERM`）非白名单系统调用。
- **linux root 权限**：Linux 后端需要以 root 运行（namespace/挂载/cgroup
  写入均需要 `CAP_SYS_ADMIN`），这是评测部署的既定形态。
- **linux 残余子孙**：主进程（pid ns 内 PID 1）退出时内核会杀死全部子孙，
  因此"甩锅给子进程"在机制上不成立；残余检测仍保留（cgroup.procs 非空 →
  `SE`）以覆盖内核与观测之间的竞态窗口。

## 6. 参考实现

- DMOJ/wbox：Windows 沙箱评测的历史方案（临时低权用户 + 防火墙 + Job +
  DLL 注入），river 的 AppContainer 方案是其现代化替代
- criyle/go-judge：Linux 参照系；其 REST 请求/响应字段与本 API 大体同构，
  river 的 Linux 后端同样采用 namespace + pivot_root + cgroup
- Linux 后端机制与踩坑记录：[docs/linux-backend.md](docs/linux-backend.md)
