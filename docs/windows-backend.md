# Windows 后端技术方案与实施计划

支撑最低版本：Windows 10 21H2+ / Windows 11。零外部依赖：无 WSL、无虚拟化、
无驱动、无需管理员权限、仅新增 `windows-sys` crate（按 feature 裁剪）。

## 1. 安全架构：三层防御

对不可信代码的约束 = 三层原生机制叠加，缺一层即有对应攻击面：

### 第一层：AppContainer（身份与文件系统）

Chromium/Edge 沙箱同款机制（`CreateAppContainerProfile` + 令牌创建）。

- 每次评测使用固定的 profile（复用，避免反复创建/删除），令牌不含任何
  capability → **默认断网**（无 `internetClient` 即无网络能力，零防火墙配置）
- 文件系统天然收窄：AppContainer 令牌默认几乎不可见任何目录，可见面 =
  显式授权的部分（见 §2）
- 无需管理员权限、无 profile 目录、毫秒级创建

对比历史方案：DMOJ/wbox 用"临时低权用户 + CreateProcessWithLogonW"，慢且有
SLS Job 链问题；AppContainer 是其 2026 年的正确替代。

### 第二层：Job Object（资源与进程）

```
JOB_OBJECT_LIMIT_PROCESS_MEMORY   内存上限（commit 语义）
JOB_OBJECT_LIMIT_PROCESS_TIME     CPU 时间上限（粒度粗，作快速路径）
JOB_OBJECT_LIMIT_ACTIVE_PROCESS=1 禁止 fork 炸弹
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE 兜底：judger 崩溃→句柄关闭→全家终止
JOB_OBJECT_UILIMIT_*              禁剪贴板/读他人窗口/改全局参数
```

wall clock 由看门狗线程保证（Job 的 CPU 限制测不出 `Sleep` 型挂机）。

### 第三层：创建时 Mitigation Policy（内核攻击面）

通过 `UpdateProcThreadAttribute` 在 spawn 时传入（无需 wbox 时代的 DLL 注入）：

```
WIN32K_SYS_DISABLE       禁全部 GDI/USER 系统调用（win32k 是最大内核漏洞面；
                         也消灭弹窗/改鼠标/关机对话框类恶作剧）
CHILD_PROCESS_DISABLED   禁止再派生子进程（与 Job 进程数限制双保险）
EXTENSION_POINT_DISABLE  禁 DLL 注入式 hook
```

另有 `SetErrorMode(SEM_NOGPFAULTERRORBOX)`（父进程设置，子进程继承，静默崩溃
弹窗——不走 `CreateProcessWithLogonW` 就没有继承链被打断的问题）。

### 明确不做 / 留待升级

- `BLOCK_NON_MICROSOFT_DLLS` 签名策略：静态编译的评测目标可用，但会误伤
  动态链接的运行时，默认不开
- 网络放行（`allow_network` 参数）：AppContainer 加 capability 即可，将来按需
- SLC/临时用户方案：不采用（慢、要管理员、Job 链坑）

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
           + SEM_NOGPFAULTERRORBOX + CREATE_SUSPENDED → ResumeThread
  ④ monitor：主线程 WaitForSingleObject(wall 预算，GIL 已释放)
           + 2×管道读线程（计数/截断/落盘 *_file）
  ⑤ 收尾：GetExitCodeProcess / GetProcessTimes / Job PeakProcessMemoryUsed
           → verdict 映射（NTSTATUS 表）→ Status
  ⑥ 清理：TerminateJobObject(若存活) → 句柄关闭(KILL_ON_JOB_CLOSE 兜底)
           → reparse-point 安全删除临时目录
```

## 4. 判定与测量

- **双计时**：CPU = `GetProcessTimes`，wall = `QueryPerformanceCounter`；
  TLE = 看门狗 wall 超限 ∪ Job CPU 超限（`Sleep` 挂机靠前者抓）
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
├── acl.rs        授权原语：目录/文件 grant、只读/读写、完整性标签
├── job.rs        Job Object 创建、四类限制、峰值内存查询
├── spawn.rs      STARTUPINFOEX 属性组装、CreateProcess、挂起启动
├── stdio.rs      三通道：stdin 供给、stdout/stderr 读线程（限额/截断/落盘）
├── workdir.rs    临时目录生命周期、copy_in 落盘、reparse 安全删除
├── monitor.rs    等待/看门狗/双计时/收尸
└── verdict.rs    exit code/NTSTATUS → status+signal 映射表
```

原则：pyo3 边界最小化（仅 sandbox.rs 触碰 Python 对象）；一文件一关注点；
verdict.rs 的映射表独立成文件便于逐条 review。

并发：`run()` 可并发调用，per-run 状态全在局部；等待段 `py.allow_threads`
释放 GIL；Sandbox 无共享可变状态。

内部安全上限（None=无限的机制层兜底）：wall ≤ 24h、内存 ≤ 物理内存；
首版为常量，后续按需升级为构造参数。

## 6. 实施计划（13 步，每步 ≤250 行、独立提交、独立验证）

### P1 测量核心（无安全，验证测量正确性）

| 步 | 内容 | 行数 | 验证 | review 重点 |
|---|---|---|---|---|
| S1 | `stdio.rs` 管道层 | ~200 | 单测：echo 捕获、截断标志 | 读线程终止条件，防死锁 |
| S2 | `job.rs` + 裸 spawn | ~250 | Job 强杀 ping；进程数=1 生效 | 句柄 RAII、KILL_ON_JOB_CLOSE 时序 |
| S3 | `monitor.rs` + verdict(AC/RE) | ~200 | sleep 程序 CPU/wall 差异；非零退出判 RE | GIL 释放边界 |
| S4 | `sandbox.rs` 接线 | ~150 | 冒烟：run() 返回真实 Status | 字段语义对照冻结 API |

### P2 沙箱化

| 步 | 内容 | 行数 | 验证 | review 重点 |
|---|---|---|---|---|
| S5 | `workdir.rs` 临时目录+copy_in | ~200 | copy_in 落 cwd；块退出目录消失；junction 删净 | 删除不跟随 reparse；异常不泄漏目录 |
| S6 | `token.rs` AppContainer 令牌 | ~150 | 令牌起进程身份正确 | profile 复用策略 |
| S7 | `acl.rs` + 接入 spawn | ~250 | **安全里程碑**：写 C:\ 失败、写 cwd 成功、读 runtimes 成功；python via runtimes 跑通 | ACE 权限位精确（READ\|EXECUTE 无 WRITE/DELETE）；TEMP 指向 cwd |

### P3 攻击面加固

| 步 | 内容 | 行数 | 验证 |
|---|---|---|---|
| S8 | mitigation policies + 禁网 | ~150 | 攻击清单前 7 项全灭（每个 policy 验证实际生效，非仅 API 返回值） |

### P4 判定完备

| 步 | 内容 | 行数 | 验证 | review 重点 |
|---|---|---|---|---|
| S9 | 看门狗 + TLE/MLE | ~200 | `while(1)`/`sleep(inf)`/malloc 炸弹 → TLE/TLE/MLE | 强杀后 GetProcessTimes 可读；证据优先于 exit code |
| S10 | 完整 NTSTATUS 表 + OLE | ~120 | 段错误/栈溢出分类；输出喷泉判 OLE+truncated | 映射表逐条对照文档 |

### P5 生命周期

| 步 | 内容 | 行数 | 验证 | review 重点 |
|---|---|---|---|---|
| S11 | 异常路径 + `__exit__` 强化 | ~200 | judger 被杀后无孤儿进程/无残留目录 | 守卫类型(Drop)而非手动清理 |
| S12 | 并发与压力 | ~100+测试 | 8 路并发 ×50 次稳定；计时抖动基线 | 零共享状态审查 |

### P6 测试套件

| 步 | 内容 | 验证 |
|---|---|---|
| S13 | pytest 三件套：`test_functional/test_attack/test_limits`（攻击样本 ctypes 编写）+ README 能力矩阵 | 全绿 |

**节奏约定**：每步一个 commit（`feat(win32): S<n> ...`）；单步预计超 250 行时
先停下协商拆分，不硬写。

## 7. 攻击样本回归清单（S8 起逐步变绿，S13 全量 pytest 化）

1. 写 `C:\Windows\Temp` / 桌面 → 拒绝（AppContainer + ACL）
2. 读写 cwd 外文件、遍历 `C:\` → 拒绝
3. `RegSetValue` HKCU/HKLM → 拒绝
4. socket 连外网 → 拒绝（无 capability）
5. `CreateProcess` 自复制 → 失败（双保险）
6. `while(1)` / `Sleep(∞)` / malloc 炸弹 / stdout 喷泉 → TLE/TLE/MLE/OLE
7. `ExitWindowsEx`/`BlockInput`/`MessageBox` → 失败/无效果（win32k 禁用 + UI 限制）
8. `OpenProcess(WRITE)` 他人进程 / 发窗口消息 → 拒绝
9. judger 被 Ctrl+C → 被测进程随 KILL_ON_JOB_CLOSE 死亡，无残留 `river-*` 目录
10. cwd 留 junction 指向系统目录 → 清理不跟随

## 8. 已知限制（首版）

- 不支持放行网络（一律禁网）
- copy_in 文件对程序一律只读（可写白名单参数将来加）
- 内存为 commit 语义（与 Linux RSS 差异见 DESIGN.md）
- Defender 实时扫描对首次冷启动有影响（建议对临时目录根加排除，文档说明，
  不自动改系统配置）
