# Windows 后端技术设计

支撑最低版本：Windows 10 21H2+ / Windows 11。零外部依赖：无 WSL、无虚拟化、
无驱动、无管理员权限、仅新增 `windows-sys` crate（按 feature 裁剪）。

> **状态（2026-11）**：Windows 后端首版**已完成并收官**。实施计划（S1–S13）
> 全部落地并提交；本文档现在是**技术设计文档**：§1–§8 是架构与判定语义
> （长期参考），§9 是决策记录、踩坑记录与实施历史。
>
> **范围**：Windows 是唯一目标平台。§9.4 列出的方向（Linux/macOS 后端、
> 网络放行、copy_in 可写、私有桌面 GUI 等）**已确认明确不做**——本仓库
> 当前形态即最终形态，后续只有修 bug 与维护文档。

## 1. 安全架构：三层防御

对不可信代码的约束 = 三层原生机制叠加，缺一层即有对应攻击面：

### 第一层：AppContainer（身份与文件系统）

Chromium/Edge 沙箱同款机制。**实现要点**：不需要创建降权令牌——子进程在
spawn 时通过 `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` 属性（携带
AppContainer SID）直接成为 AppContainer，普通令牌即可。

- 每次评测使用固定的 profile（复用，避免反复创建/删除），令牌不含任何
  capability → **默认断网**（无 `internetClient` 即无网络能力，零防火墙配置）
- 文件系统天然收窄：AppContainer 令牌默认几乎不可见任何目录，可见面 =
  显式授权的部分（见 §2）
- 无需管理员权限、无 profile 目录、毫秒级创建

对比历史方案：DMOJ/wbox 用"临时低权用户 + CreateProcessWithLogonW"，慢且有
SLS Job 链问题；AppContainer 是其 2026 年的正确替代。

### 第二层：Job Object（资源与进程）

```
JOB_OBJECT_LIMIT_PROCESS_MEMORY   内存上限（commit 语义，恒生效：用户限额或物理内存兜底）
JOB_OBJECT_LIMIT_PROCESS_TIME     CPU 时间上限（粒度粗，作快速路径）
JOB_OBJECT_LIMIT_ACTIVE_PROCESS   存活进程总数上限（默认 64，含主进程）
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE 兜底：judger 崩溃→句柄关闭→全家终止
```

**进程策略（已与设计者确认）**：主进程是唯一的被评测对象；允许普通包装器
（`cmd /c`、解释器辅助进程）派生，存活总数 ≤ 64，fork 炸弹有界。
**防甩锅**：主进程退出后，用 Job 的 process-id list 检测残余子孙——存在即
立即终止，verdict 判 `SE`（而非误导性的 AC）。原 `max_processes=1` 会让
`cmd /c findstr` 这类壳+子结构直接失败（实测 stderr "Not enough quota"），
故放弃。

wall clock 由看门狗线程保证（Job 的 CPU 限制测不出 `Sleep` 型挂机）。

### 第三层：创建时 Mitigation Policy（内核攻击面）

通过 `UpdateProcThreadAttribute` 在 spawn 时传入（无需 wbox 时代的 DLL 注入）：

```
WIN32K_SYS_DISABLE       禁全部 GDI/USER 系统调用（win32k 是最大内核漏洞面；
                         也消灭弹窗/改鼠标/关机对话框类恶作剧）
EXTENSION_POINT_DISABLE  禁 DLL 注入式 hook
```

注意：~~CHILD_PROCESS_DISABLED~~ **不再使用**——与已确认的进程策略冲突
（普通包装器需要派生子孙）；"主进程唯一"由 monitor 的残余检测 +
强制终止保证（见 §1 第二层）。

另有 `SetErrorMode(SEM_NOGPFAULTERRORBOX)`（父进程设置，子进程继承，静默崩溃
弹窗——不走 `CreateProcessWithLogonW` 就没有继承链被打断的问题）。
错误模式是**进程全局**的，所以 spawn.rs 的 `with_silent_crash_dialog` 在
spawn 前后保存/恢复旧值，不影响 judger 自身行为。

### 明确不做（均已确认，不再排期）

- `BLOCK_NON_MICROSOFT_DLLS` 签名策略：**不开**。静态编译的评测目标可用，
  但会误伤动态链接的运行时
- 网络放行（`allow_network` 参数）：**不做**。一律断网是既定安全策略
- SLC/临时用户方案：**不采用**（慢、要管理员、Job 链坑）
- 私有桌面隔离 GUI：**不做**（见踩坑 18，已知并接受）

完整清单见 §9.4。

## 2. 文件系统模型

被测进程的可见面（其余全部不可见）：

| 对象 | 授权 | 机制 |
|---|---|---|
| per-run 私有 cwd | 读/写/执行 | 临时目录 + ACE 授予 AppContainer SID |
| `runtimes` 各目录 | 读/执行 | 宿主目录 ACL 加只读 ACE（零拷贝，Defender 只扫一次） |
| `copy_in` 文件 | 只读 | 落盘到 cwd 后显式重置 ACL（不走 MoveFile；同卷硬链接优化仅在拒绝写 ACE 下安全，首版直接拷贝） |
| System32 及系统 DLL | 读/执行（系统默认） | AppContainer 天然可读，这是有意为之——程序需要加载系统 DLL |

环境变量：基底 = `SystemRoot` + `TEMP`/`TMP`（指向私有 cwd 下的 tmp 子目录），
`env` 参数增量覆盖。缺 `SystemRoot` 会导致 socket/临时目录等 API 大面积故障。

## 3. 执行管线（单次 run）

```
validate(spec)                          已完成
  ① workdir：创建 per-run 临时目录，copy_in 落盘（bytes 直写/宿主拷贝 + ACL 重置）
  ② token：AppContainer 令牌；acl：cwd 可写 / runtimes 只读 grant
  ③ spawn：STARTUPINFOEX —— std 句柄 + JOB_LIST + MITIGATION_POLICY 属性
           + SEM_NOGPFAULTERRORBOX（子进程继承）+ CREATE_SUSPENDED → ResumeThread
  ④ monitor：主线程 WaitForMultipleObjects({进程, 输出超限事件}, wall 预算，GIL 已释放)
           + 2×管道读线程（计数/截断/落盘 *_file/超限 SetEvent）
  ⑤ 收尾：GetExitCodeProcess / Job accounting(CPU) / Job PeakProcessMemoryUsed
           → verdict 映射（NTSTATUS 表）→ Status
  ⑥ 清理：TerminateJobObject(若存活) → 句柄关闭(KILL_ON_JOB_CLOSE 兜底)
           → reparse-point 安全删除临时目录
```

## 4. 判定与测量

- **双计时**：CPU = **Job accounting**（`JOBOBJECT_BASIC_ACCOUNTING_INFORMATION`，
  统计整棵进程树），wall = Rust `Instant`（Windows 上底层即 QPC）；
  TLE = 看门狗 wall 超限 ∪ 实测 CPU 超限（`Sleep` 挂机靠前者抓）
  —— 注意 Windows 8+ 上 `GetProcessTimes` 读**别的进程**恒为 0，
  必须用 Job accounting（见 §9.2.10）
- **内存**：`JobObjectExtendedLimitInformation.PeakProcessMemoryUsed`（commit 语义，
  与 Linux RSS 的差异已在 DESIGN.md §4 承诺）
- **MLE 判定优先于 RE**：强杀后以"Job 内存超限证据"归类，而非看 exit code
- **强杀路径**：TLE/MLE/OLE 三者统一 `TerminateJobObject` → signal 合成 9
- **NTSTATUS 映射**（verdict.rs 维护完整表）：`0xC0000005` 访问违例、
  `0xC00000FD` 栈溢出、`0xC0000409` 快速失败 → RE；正常路径退出码原样透传

## 5. 模块拆分

```
src/platform/windows/
├── mod.rs        模块组装（~10 行）
├── sandbox.rs    pyclass 胶水：构造/上下文管理/run() 编排；唯一的 Python 边界
├── token.rs      AppContainer profile/SID/令牌
├── acl.rs        授权原语：目录/文件 grant、只读/读写（无完整性标签）
├── job.rs        Job Object 创建、四类限制、峰值内存与 CPU 统计查询
├── spawn.rs      STARTUPINFOEX 属性组装、CreateProcess、挂起启动
├── stdio.rs      三通道：stdin 供给、stdout/stderr 读线程（限额/截断/落盘）
├── workdir.rs    临时目录生命周期、copy_in 落盘、reparse 安全删除
├── monitor.rs    等待/看门狗/双计时/收尸
└── verdict.rs    exit code/NTSTATUS → status+signal 映射表
```

原则：pyo3 边界最小化（仅 sandbox.rs 触碰 Python 对象）；一文件一关注点；
verdict.rs 的映射表独立成文件便于逐条 review。

并发：`run()` 可并发调用，per-run 状态全在局部；阻塞段用 `py.detach`
释放 GIL（pyo3 0.30 已将 `allow_threads` 更名为 `detach`）；Sandbox 无共享
可变状态。

内部安全上限（None=无限的机制层兜底）：wall ≤ 24h、内存 ≤ 物理内存；
首版为常量，后续按需升级为构造参数。

## 6. 实施历史（13 步，每步 ≤250 行、独立提交、独立验证）

> 计划**已全部完成**（S1–S13）。下表保留作为**实施历史与验收依据**，
> 各步的 commit hash 见 §9.1，代码见 `src/platform/windows/`。
> 新增功能请直接开新步，格式沿用下表。

| 阶段 | 步 | 内容 | 验收 | 产出 |
|---|---|---|---|---|
| **P1 测量核心**<br>（无安全，验证测量正确性） | S1 ✅ | `stdio.rs` 管道层 | echo 捕获、截断标志 | 单测：读线程终止条件，防死锁 |
| | S2 ✅ | `job.rs` + 裸 spawn | Job 强杀 ping；进程数=1 生效 | 单测：句柄 RAII、KILL_ON_JOB_CLOSE 时序 |
| | S3 ✅ | `monitor.rs` + verdict(AC/RE) | sleep 程序 CPU/wall 差异；非零退出判 RE | 单测：GIL 释放边界 |
| | S4 ✅ | `sandbox.rs` 接线 | 冒烟：run() 返回真实 Status | 单测：字段语义对照冻结 API |
| **P2 沙箱化** | S5 ✅ | `workdir.rs` 临时目录+copy_in | copy_in 落 cwd；块退出目录消失；junction 删净 | 单测：删除不跟随 reparse；异常不泄漏目录 |
| | S6 ✅ | `token.rs` AppContainer profile/SID | 令牌起进程身份正确 | 单测：profile 复用策略 |
| | S7 ✅ | `acl.rs` + 接入 spawn | **安全里程碑**：写 C:\ 失败、写 cwd 成功、读 runtimes 成功（写 runtimes 拒绝） | 单测：ACE 权限位精确；TEMP 指向 cwd |
| **P3 攻击面加固** | S8 ✅ | mitigation policies + 禁网 | 攻击清单 1–7（`examples/s8_smoke.py`，行为级探针 + 子进程内核状态自查询） | 单测：WIN32K=0x1<<28、EXTENSION_POINT=0x1<<32（官方 shift） |
| **P4 判定完备** | S9 ✅ | 看门狗 + TLE/MLE | `while(1)`/`sleep(inf)`/malloc 炸弹 → TLE/TLE/MLE | 单测：证据优先于 exit code（见 §9.2.5） |
| | S10 ✅ | 完整 NTSTATUS 表 + OLE | 段错误/栈溢出分类；输出喷泉 mid-run 击杀判 OLE+truncated | 单测：`*_limit` 是击杀阈值；NTSTATUS 表逐条对照 |
| **P5 生命周期** | S11 ✅ | 异常路径 + `__exit__` 强化 | judger 被杀后无孤儿进程/无残留目录 | 单测：守卫类型(Drop)而非手动清理 |
| | S12 ✅ | 并发与压力 | 8 路并发 ×50 次稳定（400 次全 AC、无残留目录、抖动 2-4%） | 单测：零共享状态审查（可变全局仅 5 处） |
| **P6 测试套件** | S13 ✅ | pytest 三件套 + README 能力矩阵 | 59 pytest 全绿（functional 21 / attack 23 / limits 15） | 单测：顺带修掉 CPU 时间测量 bug（见 §9.2.10）与残余子孙竞态（见 §9.2.11） |

**节奏约定（沿用）**：每步一个 commit（`feat(win32): S<n> ...`）；单步预计超
250 行时先停下协商拆分，不硬写。

### 6.1 测试套件（S13）

```
tests/
├── conftest.py          fixtures：被测解释器、runtimes、sandbox、宿主秘密文件
├── test_functional.py   21 例：API 契约的正常路径（copy_in/env/stdin/stdout_file/校验异常）
├── test_attack.py       23 例：§7 攻击清单的 pytest 化（每个都断言"被拒绝"的行为级证据）
└── test_limits.py       15 例：CPU/墙钟/内存/输出四类限额与判定
```

每个测试都**在沙箱内跑真实程序**（被测解释器 = `sys.executable`），
因此每次约 100ms。攻击探针用**纯 Python**（不用 ctypes）——win32k 锁定下
`ctypes` 连加载都失败（踩坑 15），所以"ctypes 加载失败"本身就是
win32k 策略生效的直接证据。

> **测试有效性纪律**：断言必须"非平凡"——例如"judger 被中断后无孤儿进程"
> 那条用例，把 `KILL_ON_JOB_CLOSE` 去掉后**必须失败**才算有效断言；
> 清理动作（taskkill）只能放在断言**之后**，否则断言会被清理动作本身
> 满足而变成同义反复。


## 7. 攻击样本回归清单（pytest 化，S13 收口）

| # | 攻击面 | 期望 | 覆盖位置 |
|---|---|---|---|
| 1 | 写 `C:\Windows\Temp` / 桌面 | 拒绝（AppContainer + ACL） | `test_attack.py::test_write_to_system_temp_is_denied` / `..._to_desktop_...` |
| 2 | 读写 cwd 外文件、遍历 `C:\` | 拒绝 | `..._host_file_outside_cwd_is_invisible` / `..._walking_the_host_drive_...` |
| 3 | `RegSetValue` HKCU/HKLM | 拒绝 | `..._registry_write_is_denied` / `..._registry_read_outside_the_profile_...` |
| 4 | socket 连外网 / DNS | 拒绝（无 capability） | `..._outbound_network_is_denied` / `..._dns_resolution_is_denied` |
| 5 | `CreateProcess` 自复制 | **允许但有界**（设计决策 §9.2.2） | `..._child_processes_are_allowed_but_bounded` / `..._fork_bomb_is_bounded` |
| 6 | `while(1)` / `Sleep(∞)` / malloc 炸弹 / stdout 喷泉 | TLE/TLE/MLE/OLE | `test_limits.py` 四例 + `test_attack.py::..._resource_exhaustion_...` |
| 7 | `ExitWindowsEx`/`BlockInput`/`MessageBox` | 失败/无效果（win32k 禁用） | `test_attack.py::test_gui_and_shutdown_apis_are_unreachable`（+ Rust 侧 `LoadLibraryA` 原生探针） |
| 8 | `OpenProcess(WRITE)` 他人进程 / 发窗口消息 | 拒绝 | `test_attack.py::test_opening_another_process_for_write_is_denied` / `..._window_messages_...` |
| 9 | judger 被中断（Ctrl+C / 崩溃） | 被测进程随 KILL_ON_JOB_CLOSE 死亡，无残留 `river-*` 目录 | `test_attack.py::test_an_interrupted_judger_leaves_no_orphan_process`（**已验证：去掉 KILL_ON_JOB_CLOSE 该用例必失败**） || 10 | cwd 留 junction 指向系统目录 | 清理不跟随 | `test_attack.py::..._junction_left_in_cwd_is_not_followed_...` + workdir.rs 单测 |

> **注（攻击面 7/8 的探针限制）**：win32k 锁定下 `import ctypes` 整体失败
> （`_ctypes.pyd` 静态依赖 user32），所以 Python 层的攻击探针**无法**直接
> 调用 Win32 GUI API。能观察到的证据是"ctypes 加载失败"本身——它证明所有
> user32 后端 API（ExitWindowsEx/BlockInput/MessageBox/PostMessage）都
> 不可达。底层证据（`LoadLibraryA("user32.dll")` 在不静态导入 user32 的
> 原生探针里失败）在 Rust 单测 `spawn.rs` 里。

## 8. 已知限制（最终形态，非暂定）

以下是**最终形态**的限制，不是待办项——对应方向已确认明确不做（§9.4）：

- 不支持放行网络（一律禁网）
- copy_in 文件对程序一律只读
- 内存为 commit 语义（与 Linux RSS 差异见 DESIGN.md）
- Defender 实时扫描对首次冷启动有影响（建议对临时目录根加排除，文档说明，
  不自动改系统配置）
- 允许派生子进程（普通包装器需要）；约束是 64 存活上限 + 残余检测（SE）
- 普通 Win32 GUI 程序的窗口会暴露到用户桌面（不做私有桌面隔离，见踩坑 18）
- 沙箱内 `ctypes` 整体不可用（win32k 锁定的副作用）——被测程序若依赖
  ctypes/PowerShell/CLR 会在加载阶段失败（0xC0000142）
- 内部安全上限是常量：wall ≤ 24h、内存 ≤ 物理内存（不提供构造参数）

## 9. 决策记录与实施历史（2026-11）

### 9.1 提交清单（全部有提交 + 单测 + 冒烟验证）

| 提交 | 内容 |
|---|---|
| `fd68539` | 冻结 Sandbox/Status 接口（参数集、坐标系、None=无限语义、copy_in） |
| `3541b58` | river.pyi 类型 stub（maturi 自动打包 __init__.pyi + py.typed）+ Status 字段带单位 |
| `c6ee2f1` | 本文档 + DESIGN.md |
| `074c88e` | S1 stdio.rs：管道三通道、读线程（计数/截断/抽干/落盘）、stdin 两种喂法 |
| `0397910` | S2 job.rs（限制 + 峰值内存查询）+ spawn.rs（挂起启动→挂 Job→resume） |
| `4e7687b` | S3 monitor.rs（双计时 + wall 看门狗）+ verdict.rs（AC/RE/TLE 雏形） |
| `ad20ee3` | S4 run() 接线（真实 Status；GIL 用 py.detach；SE 契约）+ 分层进程策略 |
| `f6892b0` | S5 workdir.rs（per-run 目录、copy_in 落盘、reparse 安全清理）+ example.py 可运行 |
| `667aeda` | S6 token.rs（AppContainer profile/SID，userenv extern 手写声明） |
| `a759830` | S7 acl.rs（grant/grant_rw/grant_ro，幂等去重）+ spawn.rs 接入 AppContainer（SECURITY_CAPABILITIES + HANDLE_LIST + 白名单环境块）+ sandbox.rs 全链路接线 |
| `3d929c7` | S8 spawn.rs 加 `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY`（WIN32K_SYSTEM_CALL_DISABLE + EXTENSION_POINT_DISABLE，均为 ALWAYS_ON）+ examples/s8_smoke.py（攻击清单 1–7 探针） |
| `cb6f7f6` | S8 修整：移除探针中的 GUI 触发路径（打包版 notepad stub 句柄杀不掉真窗口，泄漏桌面窗口）；EXTENSION_POINT 验证定版为子进程内核状态自查询 |
| `8a28e2e` | S9 verdict.rs 证据优先判定（SE>OLE>MLE>TLE>exit code）+ monitor CPU/MLE 行为级单测 + examples/s9_smoke.py |
| `40aad23` | S10 OLE 击杀阈值（stdio 超限事件 + monitor 双路等待 + `KillReason::OutputLimit`）+ NTSTATUS 全表（ntstatus_name）+ examples/s10_smoke.py |
| `948ba7a` | S11 `SuspendedGuard`（assign 失败杀挂起子进程）+ `sweep_stale_workdirs`（死主目录清扫，接入 `Sandbox::new`/`__exit__`）+ examples/s11_smoke.py |
| `96bf8d4` | S12 并发修复：AppContainer profile 创建加锁 + 每进程只创建一次（token.rs）、DACL 授权串行化（acl.rs）、过期目录清扫串行化（workdir.rs）、`Sandbox` 改 `frozen`（可多线程并发 run）+ examples/s12_stress.py / s12_probe.py |
| `722e31e` | S13 pytest 三件套（tests/：functional 21 / attack 23 / limits 15）+ README 能力矩阵 + **CPU 时间测量修复**（改用 Job accounting，见 §9.2.10） |

当前状态：Windows 后端首版完成。`run()` 端到端可用；Rust 单测 53/53 绿，
pytest 59 例全绿（functional / attack / limits 三件套）。**进程跑在
AppContainer 身份下 + 内核攻击面收窄**：win32k 系统调用与全局钩子/AppInit/
Winsock LSP/legacy IME 注入被禁，无 capability 即禁网；文件系统可见面 =
cwd 可写 + runtimes 只读；判定完备（AC/TLE/MLE/OLE/RE/SE）；生命周期由
RAII 守卫保证（杀 judger 无孤儿进程、无残留目录）；并发安全（8 路 ×50 次
压力全绿）。

### 9.2 关键实现决策（已定，勿翻案）

1. **沙箱机制**：AppContainer，spawn 时经 `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`
   携带 SID（Chromium 方式），不用降权令牌。profile `river.sandbox` 复用。
2. **进程策略**：总数 ≤ 64（`DEFAULT_MAX_PROCESSES`）；主进程退出即杀残余子孙，
   残余 > 0 → verdict **SE**（防甩锅）。`CHILD_PROCESS_DISABLED` 弃用。
3. **网络**：一律禁网（AppContainer 无 capability 即默认断网），无放行参数。
4. **进程列表查询**：`JobObjectBasicProcessIdList`（可变长缓冲，234 时翻倍重试）。
5. **verdict 证据优先级（S9/S10 定版）**：SE（残余子孙）> OLE（`OutputLimit`
   击杀，直接观测）> MLE（异常终结 + 峰值 commit 内存钉在限额，slack =
   max(1MiB, limit/8)）> TLE（看门狗 wall 击杀 ∪ 实测 CPU 超限）> exit code
   （0=AC 否则 RE，NTSTATUS 表逐条命名见 `verdict.rs ntstatus_name`）。
   MLE 排在 TLE 之前，因为 malloc 炸弹通常由 wall 看门狗收割——内存证据才
   指明真正死因。OLE 是读线程的直接观测，排在推断类证据之前。干净退出
   （exit 0）即使峰值贴近限额也保持 AC。Job 的 commit 限额让超额分配**失败**
   而非成功，故峰值天然停在限额之下一个分配粒度内，slack 必须覆盖这个间隙。
6. **OLE 击杀阈值语义（S10）**：`stdout_limit_kb`/`stderr_limit_kb` 是
   **击杀阈值**（严格超出才杀；恰好等于限额仍 AC，`truncated` 亦不置位）。
   stdio.rs 建一个 manual-reset 事件，读线程发现 `total > limit` 即
   SetEvent；monitor 用 `WaitForMultipleObjects({process, event}, wall)`
   双路等待，命中事件 → TerminateJobObject → `KillReason::OutputLimit`。
   `stdout_file` 是截至被杀为止的全量留档（被杀时程序尚在写的块不计）。
7. **并发下的 AppContainer profile（S12 重大发现）**：
   `CreateAppContainerProfile` 是**写系统状态**的 API（写 AppContainer
   映射注册表键 + profile 目录），并发调用会互相破坏——8 路并发实测报
   `ERROR_KEY_DELETED` / `ERROR_INVALIDARG` / `ERROR_FILE_NOT_FOUND` /
   `RPC_E_SERVERCALL_RETRYLATER`，全部判成 SE。修法与 Chromium sandbox
   库一致：**创建操作加锁串行化**（token.rs `PROFILE_CREATE_LOCK`），
   且每个进程只创建一次（`created_profiles` 缓存），之后只用纯读的
   `DeriveAppContainerSidFromAppContainerName`。
   **注意**：不能把"derive 成功"当作"profile 已存在"——derive 出来的
   SID 若从未真正创建过，子进程采用该 SID 启动时会以
   `ERROR_FILE_NOT_FOUND` 失败（映射键与 profile 目录不存在）。必须真的
   `CreateAppContainerProfile` 过一次（缓存标记的就是这件事）。
8. **DACL 授权是 read-modify-write（S12）**：`GetNamedSecurityInfo` →
   `SetEntriesInAclW` → `SetNamedSecurityInfo` 不是原子操作，并发授权
   同一目录会丢 ACE。acl.rs 用进程级 `GRANT_LOCK` 串行化整个
   check-then-modify 循环（操作只需几微秒，正确性优先）。
9. **过期目录清扫要加锁（S12）**：两个线程同时清扫会互相删除/遍历同一
   目录 → `ERROR_SHARING_VIOLATION`。workdir.rs 用 `SWEEP_LOCK` 串行化。
10. **CPU 时间必须读 Job 的 accounting，不是 `GetProcessTimes`（S13 重大
    发现）**：Windows 8+ 起，**别的进程**的 CPU 时间用 `GetProcessTimes`
    一律读回 0——即使拿 `PROCESS_ALL_ACCESS` 打开、即使目标已经退出（只剩
    一点点 kernel 时间）；只有进程读**自己**的时间是对的。river 一直
    因此把 `time_used_ms` 报成 ~0，CPU 限额的 TLE 证据链整个失效
    （`while True` 撞 CPU 限额会判 RE 而不是 TLE）。
    正确来源是 Job 的 `JOBOBJECT_BASIC_ACCOUNTING_INFORMATION`
    （`TotalUserTime`/`TotalKernelTime`）——它统计**整棵树**（主进程 +
    所有子孙），这正是评测需要的语义。改动见 `Job::cpu_time_ms`。
11. **残余子孙判定必须排除主进程自己的 pid（S13 竞态）**：内核是
    **异步**更新 Job 的进程列表的——主进程被 signal 之后的一小段时间内，
    它仍可能出现在列表里。把主进程算作"残余子孙"会让正常程序偶发被判
    `SE`（实测 400 次并发里偶发 1 次）。修法：`Job::alive_process_ids()`
    返回 pid 列表，monitor 用主进程 pid 过滤掉它
    （见 `monitor.rs` 的 `main_pid` 过滤）。

### 9.3 踩坑记录（写后续代码前必读）

1. **存活的 std Command 持有原始 stdio 句柄**，会卡死读线程（等不到 EOF）。
   S1 有回归测试；生产路径在 spawn 返回后立即关闭 judger 侧句柄副本。
2. **`RemoveDirectoryW` 对 junction 拒绝访问**。删 reparse point 的正规路径：
   `CreateFileW(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)` +
   `SetFileInformationByHandle(FileDispositionInfo)`（workdir.rs 已实现）。
3. **只读属性挡住 DeleteFileW**：删除前先清 `FILE_ATTRIBUTE_READONLY`。
4. **findstr 保留输入行尾**（LF 进 LF 出）；Windows 子进程 stdout 管道是文本
   模式，`\n` 会被子进程自己写成 `\r\n`——断言时用 `rstrip()`。
5. **windows-sys 0.60 不含 userenv profile API**（CreateAppContainerProfile 等）
   和 ConvertSidToStringSidW → token.rs 手写 extern（userenv/advapi32）。
6. **HRESULT 形式的 ERROR_ALREADY_EXISTS 是 0x800700B7**，不是裸 183。
7. pyo3 0.30：`Python::allow_threads` 已改名 **`py.detach`**。
8. cargo 拉新依赖需要代理（HTTPS_PROXY=http://127.0.0.1:7890）；杀掉 cargo
   进程后可能残留 target/debug/.cargo-lock，需手动删除。
9. **Windows 子进程 stdout 是文本模式**——需要在 python.exe 侧注意；
   river 的管道本身是二进制透传。
10. **AppContainer spawn 的环境块必须包含 LOCALAPPDATA**：白名单基底只有
    SystemRoot 时 `CreateProcessW` 返回 `ERROR_ENVVAR_NOT_FOUND`（203）。
    此外内核会用 AppContainer profile 的路径**覆盖**子进程的
    LOCALAPPDATA/TEMP/TMP 等（即使块里显式给了别的值）——profile 的 Temp
    目录是沙箱私有的，反而是好事；cwd 的 `tmp/` 仍会创建并作为白名单值。
11. **SetEntriesInAclW 对同一 trustee 的多个 grant 是合并掩码**（rw ∪ ro），
    不是并列 ACE——acl.rs 用"完全相同的 SID+mask 则跳过"实现幂等，重复
    grant runtimes 目录不会让 DACL 无限增长。
12. **EXTENDED_STARTUPINFO_PRESENT 时 `STARTUPINFOW.cb` 必须是
    `sizeof(STARTUPINFOEXW)`**，传 `sizeof(STARTUPINFOW)` 会报 87。
13. **venv 的 python.exe 需要读 venv 根目录**（`pyvenv.cfg`）与 base 解释器
    目录——S7 起 runtimes 必须包含 `dirname(sys.executable)`、`sys.prefix`、
    `sys.base_prefix`，否则被测 Python 在沙箱内起不来（RE）。
14. **MITIGATION_POLICY 的 shift 值以官方 UpdateProcThreadAttribute 文档为
    准**：WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON = 0x1<<28、
    EXTENSION_POINT_DISABLE_ALWAYS_ON = 0x1<<32（同一 u64），别凭记忆写
    24/41；两个 policy 合用一个 u64，多出的 u64 会让内核拒绝整个属性。
15. **win32k 锁定下 user32 完全无法初始化**：任何静态导入 user32 的进程
    （含 PowerShell/CLR/_ctypes.pyd）直接 0xC0000142 或 LoadLibrary 失败。
    行为探针宿主必须用"纯 kernel32 + LoadLibrary 动态解析"的原生 exe
    （测试里用 rustc 现编，见 spawn.rs `mitigation_policies_are_enforced_...`）。
16. **EXTENSION_POINT_DISABLE 不在 SetWindowsHookExW API 层失败**，而是在
    钩子 DLL 注入其他进程时静默不生效；其行为级注入验证在 Win11 上不可
    靠（无策略也不注入），故测试用子进程自查询 GetProcessMitigationPolicy
    （policy index 6）验证内核已应用状态。
17. **测试永不启动 GUI / 打包应用**：Win11 的 notepad.exe 是 Store 执行别名
    stub——`TerminateProcess(句柄)`/Job Object 都杀不掉它激活出来的真窗口
    进程（真进程由 DCOMLaunch 创建，激活链断裂，不在父子谱系内）。S8 迭代
    中曾因此向用户桌面泄漏两个 notepad 窗口（已清理，触发路径已删除）。
    测试只产生管道 IO 的控制台子进程。
18. **孙进程 GUI 暴露属已知且接受的设计现状**（与所有者确认，2026-11）：
    被测进程允许派生子进程（§9.2.2），子孙继承 AC 令牌（文件/网络限制
    对它们仍有效），且实测打包版 notepad 在 AC 内无法真正启动；普通 Win32
    GUI 程序的窗口暴露到用户桌面不作隔离（不引入 CreateDesktopW 独立
    桌面方案）。attack list 第 7 项的"弹窗骚扰"仅对被测进程本体成立。
19. **`-O` 会把无副作用无限递归优化成不增长栈的死循环**（LLVM UB 规则，
    S10 实测挂死一次测试二进制）：栈溢出探针必须用大帧（64KiB 数组）+
    `read_volatile` + `std::hint::black_box` + 非尾调用位置，否则测试要等
    24h 安全上限。
20. **裸 HANDLE 不是 Send**：跨线程传递事件/句柄裸值时在 ReaderSpec 里存
    `usize` 再转回，否则 `thread::spawn` 编译失败。
21. **EOF 后读线程可能多收到块**：OLE 击杀是竞速语义——程序在被杀前写出
    的块全部进 `stdout_file` 留档，断言只应要求"≥1 块且 > 截断样本"。
22. **venv 的 python.exe 是启动器（S11 冒烟定位）**：`subprocess.Popen`
    拿到的 pid 是启动器的，真正跑解释器（和 river 扩展、per-run 目录
    命名）的是它的子进程——凡按 pid 关联目录/进程的测试，要用目录名反查
    或差异 glob，不能信 Popen 的 pid；杀 judger 要 `taskkill /T /F` 杀
    整棵树，只杀启动器会留下真解释器。
23. **CreateProcessW 成功后的失败路径必须杀挂起子进程**：句柄关闭不杀
    进程，未入 Job 的挂起子进程会成为永久孤儿——spawn.rs 用
    `SuspendedGuard`（Drop 即 TerminateProcess，成功路径 disarm）兜住
    `AssignProcessToJobObject` 失败。
24. **并发下最先炸的是 AppContainer profile（S12）**：见 §9.2.7——写系统的
    `CreateAppContainerProfile` 必须加锁；且"derive 得到 SID"≠"profile 已
    存在"。这条坑在串行测试里完全看不见（单线程永远正常），只有真正并发
    才暴露——所以 S12 这类压力测试不是走过场。
25. **pyo3 0.30 的 `#[pyclass]` 默认 `!Sync`**：需要多线程并发调用同一个
    实例的方法时应声明 `frozen`（Sandbox 无可变状态，声明后语义才明确）。
    另注意 `py.detach` 期间 GIL 已释放，Rust 侧的锁（如 profile 创建锁）
    是唯一的互斥保证。
26. **写 pytest 攻击用例时不要用 ctypes（S13）**：win32k 锁定下
    `import ctypes` 直接失败（见踩坑 15），`ctypes.WinDLL('kernel32')`
    也起不来（"DLL 初始化例程失败"）。攻击探针要用纯 Python
    （`os`/`open`/`winreg`/`socket`/`subprocess`/`os.kill`），
    "ctypes 加载失败"本身就是 win32k 策略生效的证据。
27. **Job 的 `PROCESS_TIME` 限额粒度很粗**：Windows 按 ~10ms 粒度检查，
    实测 500ms 的 CPU 限额在 ~1200ms 才触发（且含进程启动开销）。判定
    不能依赖"恰好在限额处被杀"，必须用**实测 CPU 时间与限额比较**
    （这正是 S9 引入的证据逻辑）。
28. **抖动基线要用 MAD，不能用极差（S13）**：宿主机偶发卡顿（Defender
    扫描、调度、其他进程）会让单次样本翻倍（实测 326ms → 637ms）。
    用极差（max-min）判定基线会被宿主机噪声打穿；改用**中位数绝对偏差**
    （MAD）后，真实抖动是 **0–0.5%**，宿主机噪声单独作为 outliers 报告。
    另：第一次样本是冷启动（新建 .pyd 的首次扫描），基线要丢掉它。

### 9.4 明确不做的方向（已与所有者确认，不再排期）

Windows 后端**就此收官**：S1–S13 全部提交，53 Rust 单测 + 59 pytest 全绿，
README 能力矩阵齐备。以下方向**均已确认明确不做**，不要实现、不要"顺手
加一个"、不要列为待办：

| 方向 | 结论与理由 |
|---|---|
| Linux / macOS 后端 | **不做**。Windows 是唯一目标平台；§1 的跨平台模型只是设计时的统一心智模型，不承诺实现 |
| `allow_network` 能力 | **不做**。一律断网是既定安全策略（评测程序不需要外网），不做参数化放行 |
| copy_in 可写白名单 | **不做**。copy_in 一律只读是简单且安全的语义；没有"某些文件可写"的需求 |
| 私有桌面隔离 GUI | **不做**。见踩坑 18（孙进程 GUI 暴露是已知并接受的设计现状），不引入 `CreateDesktopW` 方案 |
| 压力基线常态化（CI 化） | **不做**。压力脚本 `examples/s12_stress.py` 手动跑即可，不接 CI |
| 限额可配置化 | **不做**。内部安全上限（wall ≤ 24h、内存 ≤ 物理内存）保持常量 |
| 完整 NTSTATUS 表的进一步细分 | **不做**。现有 `ntstatus_name` 表覆盖判题需要的异常终止；再细分不改变判定结果 |

**范围声明**：本仓库当前形态即最终形态。后续工作只有两类——**修 bug**
（含本文档 §9.3 踩坑记录里那类 Windows 行为陷阱）和**维护文档**。
新增功能需求不在计划内。

**节奏约定（沿用）**：每步一个 commit（`feat(win32): S<n> ...`）；单步预计超
250 行时先停下协商拆分，不硬写。

### 9.5 工作环境备忘

- 构建/测试：`cargo test --lib -- --test-threads=1`（53 个单测）；pytest：
  `uv sync --extra test && uv run maturin develop && uv run pytest`（59 例）；
  Python 冒烟：`uv run python -c ...`（用 `sys.executable` 作为被测程序）
- example.py：`uv run python examples/example.py`（三个场景可运行，已跑在
  AppContainer 下）；`examples/s7_smoke.py`：S7 安全里程碑四项验证；
  `examples/s8_smoke.py`：攻击清单 1–7（win32k/hook/禁网/文件/注册表/TLE）；
  `examples/s9_smoke.py`：S9 判定完备（while(1)/sleep/malloc 炸弹 → TLE/TLE/MLE
  + 限额内 AC 回归）；`examples/s10_smoke.py`：S10 OLE（喷泉 mid-run 击杀、
  `stdout_file` 留档 vs 截断样本、恰好等于限额仍 AC）；
  `examples/s11_smoke.py`：S11 生命周期（杀 judger 树 → 无孤儿进程、残留
  目录被下次构造清扫、foreign 目录不误删）；
  `examples/s12_stress.py`：S12 压力（8 路 ×50 次 = 400 次全 AC、无残留目录、
  计时抖动基线 2-4%）；`examples/s12_probe.py`：每线程各自构造 Sandbox 的
  并发 sweep 场景
- 行尾：Windows 下子进程输出带 `\r\n`，测试断言统一用 `rstrip()` 或精确字节
