# Windows 后端技术文档

支撑最低版本：Windows 10 21H2+ / Windows 11。零外部依赖：无 WSL、无虚拟化、
无驱动、无需管理员权限。

Windows 沙箱由三层原生机制叠加而成，缺一层即有对应攻击面。

## 1. 三层防御

### 身份与文件系统：AppContainer

Chromium/Edge 同款机制。子进程在创建时携带 AppContainer SID 直接成为
AppContainer——不需要创建降权令牌，普通令牌即可。

- 使用固定 profile（复用，避免反复创建/删除），令牌不含任何 capability
  → **默认断网**，零防火墙配置
- 文件系统天然收窄：AppContainer 令牌默认几乎不可见任何目录，可见面 =
  显式授权的部分
- 无需管理员权限，毫秒级创建

对比 DMOJ/wbox 的"临时低权用户 + CreateProcessWithLogonW"：慢，且有 SLS
Job 链问题。

### 资源与进程：Job Object

```
JOB_OBJECT_LIMIT_PROCESS_MEMORY   内存上限（commit 语义，恒生效：用户限额或物理内存兜底）
JOB_OBJECT_LIMIT_PROCESS_TIME     CPU 时间上限（粒度粗，作快速路径）
JOB_OBJECT_LIMIT_ACTIVE_PROCESS   存活进程总数上限（默认 64，含主进程）
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE 兜底：judger 崩溃→句柄关闭→全家终止
```

**进程策略**：主进程是唯一的被评测对象；允许普通包装器（`cmd /c`、解释器
辅助进程）派生，存活总数 ≤ 64，fork 炸弹有界。**防甩锅**：主进程退出后用
Job 的 process-id list 检测残余子孙，存在即立即终止并判 `SE`（而非误导性的
AC）。

> 限制存活进程数为 1 会让 `cmd /c findstr` 这类壳+子结构直接失败（实测
> stderr "Not enough quota"），故放弃。

墙钟由看门狗保证——Job 的 CPU 限制测不出 `Sleep` 型挂机。

### 内核攻击面：创建时 Mitigation Policy

通过 `UpdateProcThreadAttribute` 在创建时传入（无需 wbox 时代的 DLL 注入）：

```
WIN32K_SYSTEM_CALL_DISABLE   禁全部 GDI/USER 系统调用（win32k 是最大内核漏洞面）
EXTENSION_POINT_DISABLE      禁 DLL 注入式 hook 扩展点
```

`CHILD_PROCESS_DISABLED` 明确**不使用**——与允许包装器派生的进程策略冲突。

另设 `SetErrorMode(SEM_NOGPFAULTERRORBOX)` 静默崩溃弹窗（错误模式是进程
全局的，spawn 前后保存/恢复，不影响 judger 自身行为）。

## 2. 文件系统模型

被测进程的可见面，其余全部不可见：

| 对象 | 授权 | 机制 |
|---|---|---|
| per-run 私有 cwd | 读/写/执行 | 临时目录 + ACE 授予 AppContainer SID |
| `runtimes` 各目录 | 读/执行 | 宿主目录 ACL 加只读 ACE（零拷贝，Defender 只扫一次） |
| `copy_in` 文件 | 只读 | 落盘到 cwd 后显式重置 ACL（不走 MoveFile：移动保留源 ACL，拷贝继承目标目录 ACL） |
| System32 及系统 DLL | 读/执行（系统默认） | AppContainer 天然可读——程序需要加载系统 DLL |

环境变量基底 = `SystemRoot` + `TEMP`/`TMP`（指向私有 cwd 下的 tmp 子目录），
`env` 参数增量覆盖。缺 `SystemRoot` 会导致 socket/临时目录等 API 大面积故障。

## 3. 执行管线（单次 run）

```
validate(spec)
  ① workdir：创建 per-run 临时目录，copy_in 落盘 + ACL 重置
  ② token：AppContainer 身份；acl：cwd 可写 / runtimes 只读 grant
  ③ spawn：STARTUPINFOEX（std 句柄 + HANDLE_LIST + MITIGATION_POLICY）
           + CREATE_SUSPENDED → 入 Job → ResumeThread
  ④ monitor：WaitForMultipleObjects({进程, 输出超限事件}, wall 预算)
           + 2×管道读线程（计数/截断/落盘 *_file/超限置事件）
  ⑤ 收尾：退出码 + Job accounting(CPU) + Job 峰值内存 → verdict 映射 → Status
  ⑥ 清理：TerminateJobObject(若存活) → 句柄关闭 → reparse 安全删除临时目录
```

## 4. 判定与测量

- **双计时**：CPU 来自 **Job accounting**（统计整棵进程树），墙钟来自
  `Instant`。TLE = 看门狗墙钟超限 ∪ 实测 CPU 超限（`Sleep` 挂机靠前者抓）。
  ⚠️ Windows 8+ 上 `GetProcessTimes` 读**别的进程**恒为 0，必须用 Job
  accounting（见 §5.1）。
- **内存**：Job 的 `PeakProcessMemoryUsed`（commit 语义）。
- **MLE 优先于 RE**：强杀后以"内存超限证据"归类，而非看退出码。
- **强杀路径**：TLE/MLE/OLE 统一 `TerminateJobObject` → signal 合成 9。
- **NTSTATUS 映射**：访问违例、栈溢出、快速失败等异常终止归 `RE`，退出码
  原样透传（调用方可据此细分）。

判定以**证据优先**，优先级从高到低：

```
SE   残余子孙（防甩锅）
OLE  输出击杀（读线程的直接观测）
MLE  异常终结 + 峰值内存钉在 commit 限额
TLE  看门狗击杀 ∪ 实测 CPU 超限
     退出码映射（0 = AC，否则 RE）
```

两条容易踩的排序细节：

- **MLE 排在 TLE 之前**：malloc 炸弹通常是被墙钟看门狗收割的，内存证据才
  指明真正的死因。
- **OLE 排在推断类证据之前**：输出超限是直接观测，不是推断。

commit 限额让超额分配**失败**而非成功，因此峰值天然停在限额之下一个分配
粒度内——判定"是否触顶"必须留出这个间隙（否则正常程序会被误判 MLE）。
同理，干净退出（exit 0）即使峰值贴近限额也保持 `AC`：程序在限额内完成了。

## 5. 踩坑记录

> 以下都是"看起来正常、实际会静默出错"的 Windows 行为，改动本后端前必读。

### 5.1 CPU 时间：必须读 Job 的 accounting

Windows 8+ 起，**别的进程**的 CPU 时间用 `GetProcessTimes` 一律读回 0——
即使拿 `PROCESS_ALL_ACCESS` 打开、即使目标已经退出（只剩一点点 kernel
时间）；只有进程读**自己**的时间是对的。

这个坑很隐蔽：测量代码"看起来"完全正常，但 `time_used_ms` 恒为 ~0，CPU
限额的 TLE 证据链整个失效（撞 CPU 限额会判 `RE` 而不是 `TLE`）。正确来源
是 Job 的 `JOBOBJECT_BASIC_ACCOUNTING_INFORMATION`——它统计整棵树（主进程
+ 全部子孙），这正是评测需要的语义。

### 5.2 AppContainer profile 的创建竞态

`CreateAppContainerProfile` 是**写系统状态**的 API（写 AppContainer 映射
注册表键 + profile 目录），并发调用会互相破坏——8 路并发实测报
`ERROR_KEY_DELETED` / `ERROR_INVALIDARG` / `ERROR_FILE_NOT_FOUND` /
`RPC_E_SERVERCALL_RETRYLATER`，全部判成 SE。Chromium sandbox 库踩过同样的
坑并用锁串行化。

修法：创建操作加锁串行化，且每进程只创建一次，之后只用纯读的
`DeriveAppContainerSidFromAppContainerName`。

⚠️ **不能把"derive 成功"当作"profile 已存在"**——derive 出来的 SID 若从未
真正创建过，子进程采用该 SID 启动时会以 `ERROR_FILE_NOT_FOUND` 失败
（映射键与 profile 目录不存在）。

### 5.3 DACL 授权是 read-modify-write

`GetNamedSecurityInfo` → `SetEntriesInAclW` → `SetNamedSecurityInfo` 不是
原子操作，并发授权同一目录会丢 ACE。需要串行化整个 check-then-modify 循环。

`SetEntriesInAclW` 对同一 trustee 的多个 grant 是**合并掩码**（rw ∪ ro），
不是并列 ACE——幂等实现要按"SID + 完整掩码相同才跳过"来做。

### 5.4 Job 的进程列表是异步更新的

内核在主进程被 signal 后的一小段时间内，仍可能把它列在 Job 的进程列表里。
把它算作"残余子孙"会让正常程序偶发被判 `SE`（实测 400 次并发里偶发 1
次）。判定残余子孙时必须**排除主进程自己的 pid**。

### 5.5 Job 的 PROCESS_TIME 限额粒度很粗

Windows 按 ~10ms 粒度检查，实测 500ms 的 CPU 限额在 ~1200ms 才触发（且含
进程启动开销）。判定不能依赖"恰好在限额处被杀"，必须用**实测 CPU 时间与
限额比较**。

### 5.6 win32k 锁定会让 user32 完全无法初始化

任何静态导入 user32 的进程（含 PowerShell/CLR/`_ctypes.pyd`）直接
`0xC0000142` 或 LoadLibrary 失败。行为探针宿主必须用"纯 kernel32 +
LoadLibrary 动态解析"的原生 exe。

连带影响：**沙箱内 `ctypes` 整体不可用**——被测程序若依赖
ctypes/PowerShell/CLR 会在加载阶段失败。这是既定取舍（换来最大的内核漏洞
面被关闭）。

### 5.7 EXTENSION_POINT_DISABLE 的验证方式

它不在 `SetWindowsHookExW` API 层失败，而是在钩子 DLL 注入其他进程时静默
不生效；其行为级注入验证在 Win11 上不可靠（无策略也不注入），故用子进程
自查询 `GetProcessMitigationPolicy`（policy index 6）验证内核已应用状态。

### 5.8 MITIGATION_POLICY 的 shift 值

以官方 `UpdateProcThreadAttribute` 文档为准：
`WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON = 0x1<<28`、
`EXTENSION_POINT_DISABLE_ALWAYS_ON = 0x1<<32`（同一 u64），别凭记忆写
24/41；两个 policy 合用一个 u64，多出的 u64 会让内核拒绝整个属性。

### 5.9 挂起进程不能只靠关闭句柄清理

`CreateProcessW` 成功但后续步骤失败时（如入 Job 失败），关闭句柄**不杀**
进程——挂起的子进程会永久泄漏且不在任何 Job 里。必须用守卫类型（Drop 即
`TerminateProcess`）兜住这段窗口。

### 5.10 其它 Windows 细节

- `RemoveDirectoryW` 对 junction 拒绝访问。删 reparse point 的正规路径：
  以 `FILE_FLAG_OPEN_REPARSE_POINT` 打开 + `SetFileInformationByHandle`。
- 只读属性挡住 `DeleteFileW`：删除前先清 `FILE_ATTRIBUTE_READONLY`。
- `EXTENDED_STARTUPINFO_PRESENT` 时 `STARTUPINFOW.cb` 必须是
  `sizeof(STARTUPINFOEXW)`，传 `sizeof(STARTUPINFOW)` 会报 87。
- HRESULT 形式的 `ERROR_ALREADY_EXISTS` 是 `0x800700B7`，不是裸 183。
- AppContainer spawn 的环境块必须含 `LOCALAPPDATA`：只有 `SystemRoot` 时
  `CreateProcessW` 返回 `ERROR_ENVVAR_NOT_FOUND`（203）。内核还会用 profile
  的路径**覆盖**子进程的 LOCALAPPDATA/TEMP/TMP。
- venv 的 `python.exe` 需要读 venv 根目录（`pyvenv.cfg`）与 base 解释器
  目录——`runtimes` 必须包含它们，否则被测 Python 起不来。
- `findstr` 保留输入行尾；Windows 子进程 stdout 是文本模式，`\n` 会写成
  `\r\n`——断言时用 `rstrip()`。
- **venv 的 `python.exe` 是启动器**：`subprocess.Popen` 拿到的 pid 不是解释器
  的 pid。按 pid 关联目录/进程的测试要用目录名反查或差异 glob；杀进程树要
  `taskkill /T /F`。
- **裸 HANDLE 不是 `Send`**：跨线程传递句柄时在结构体里存 `usize` 再转回。
- `-O` 会把无副作用的无限递归优化成不增长栈的死循环（LLVM UB 规则）——
  栈溢出探针必须用大帧 + `read_volatile` + `black_box` + 非尾调用。
- `win32k` 锁定下 user32 无法初始化，见 §5.6。

## 6. 并发与生命周期

- **并发安全**：`run()` 可并发调用，per-run 状态全在局部；`Sandbox` 无共享
  可变状态（声明为 `frozen`）。所有写系统状态的操作（profile 创建、DACL
  授权、过期目录清扫）按进程串行化——全仓可变全局仅 5 处。
- **生命周期靠守卫**：`KILL_ON_JOB_CLOSE` 保证 judger 崩溃时全家终止；临时
  目录由 `Drop` 删除；judger 被硬杀时残留的目录由下次构造时的清扫回收
  （只清属主进程已死的目录）。

## 7. 攻击面回归清单

| # | 攻击面 | 期望 |
|---|---|---|
| 1 | 写系统临时目录 / 桌面 | 拒绝 |
| 2 | 读写 cwd 外文件、遍历宿主盘 | 拒绝 |
| 3 | 注册表读写 | 拒绝 |
| 4 | 外网连接 / DNS | 拒绝 |
| 5 | 派生子进程 | **允许但有界**（≤64 存活 + 残余检测判 `SE`） |
| 6 | 死循环 / 挂机 / malloc 炸弹 / 输出喷泉 | TLE / TLE / MLE / OLE |
| 7 | 关机 / 锁输入 / 弹窗类 UI 调用 | 失败或无效果 |
| 8 | 打开他人进程 / 发窗口消息 | 拒绝 |
| 9 | judger 被中断 | 被测进程随之死亡，无残留目录 |
| 10 | cwd 留 junction 指向系统目录 | 清理不跟随 |

第 7/8 项的探针限制见 §5.6。

## 8. 测试

```shell
uv sync --extra test && uv run maturin develop
uv run pytest                          # functional / attack / limits 三件套
cargo test --lib -- --test-threads=1   # rust 单测
```

Python 套件在沙箱内跑真实程序（被测解释器 = `sys.executable`），每次约
100ms。攻击探针用纯 Python——win32k 锁定下 ctypes 不可用（§5.6）。

**测试有效性纪律**：断言必须"非平凡"。例如"judger 被中断后无孤儿进程"
那条用例，去掉 `KILL_ON_JOB_CLOSE` 后必须失败才算有效断言；清理动作只能
放在断言**之后**，否则断言会被清理动作本身满足而变成同义反复。

## 9. 工作环境备忘

- 计时抖动基线：固定 300ms 忙循环的墙钟测量，中位数绝对偏差 **0–0.5%**
  （远低于建议的 5-10% 放宽窗口）。但**宿主机偶发卡顿**（Defender 扫描、
  调度）会让单次样本明显偏高——基线要用 MAD 而非极差判定，噪声单独记为
  outliers；第一次样本是冷启动，要丢掉。
- 行尾：Windows 下子进程输出带 `\r\n`，测试断言统一用 `rstrip()` 或精确字节。
- `examples/` 下有各阶段的冒烟脚本（`s7_smoke.py` … `s12_stress.py`）。
