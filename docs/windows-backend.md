# Windows 后端技术文档

支撑最低版本：Windows 10 21H2+ / Windows 11。零外部依赖：无 WSL、无虚拟化、
无驱动、无需管理员权限。

Windows 沙箱由三层原生机制叠加而成，缺一层即有对应攻击面。

## 1. 三层防御

### 身份与文件系统：AppContainer

Chromium/Edge 同款机制。子进程在创建时携带 AppContainer SID 直接成为
AppContainer——不需要创建降权令牌，普通令牌即可。

- 使用**槽位 profile 池**（`river.sandbox.<session>.<slot>`，每会话最多 16 个）：
  每个 run 独占一个槽，取用时擦除其 `%LOCALAPPDATA%\Packages\<profile>\AC`
  目录、结束释放时再擦一次——固定 profile 曾让 run 之间通过该目录持久通信
  （实测 run1 写的文件 run2 可读、宿主永久可见）。不逐 run 建/删 profile：
  实测 create+delete ≈ 6.6ms/run 且被全局锁串行化，槽位复用的 per-run 成本
  ≈ 0.5ms。令牌不含任何 capability → **默认断网**，零防火墙配置
- 文件系统天然收窄：AppContainer 令牌默认几乎不可见任何目录，可见面 =
  显式授权的部分
- 无需管理员权限，毫秒级创建

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

通过 `UpdateProcThreadAttribute` 在创建时传入：

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
| `copy_in` 文件 | 内容只读 | 落盘后设置保护性只读 DACL（用户 SID 与包 SID 仅 RX；目录用可继承 ACE）。**不能**只靠 `FILE_ATTRIBUTE_READONLY`：继承的 cwd ACE 含 `FILE_WRITE_ATTRIBUTES`，程序 `chmod` 后可改写（实测）。保护性 DACL 同时关闭继承，删除/改名所需的 DELETE 位也不再授予。
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
  Windows 8+ 上 `GetProcessTimes` 读**别的进程**恒为 0，CPU 时间必须以 Job
  accounting 为来源。
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

## 5. 并发与生命周期

- **并发安全**：`run()` 可并发调用，per-run 状态全在局部；`Sandbox` 无共享
  可变状态（声明为 `frozen`）。所有写系统状态的操作（profile 创建、DACL
  授权、过期目录清扫）都串行化：进程内用锁，槽位租约用**会话级命名互斥体**
  （`Local\river.sandbox.profile.<session>.<slot>`），所以同一会话里的多个
  judger 进程也不会同时擦除同一个 profile。
- **profile 生命周期**：槽位 profile 首次使用时创建、之后一直复用（每会话
  ≤16 个）；进程崩溃时内核自动释放命名互斥体（下一次租约看到
  `WAIT_ABANDONED`，照常接管并擦除包目录）。旧版本遗留的固定
  `river.sandbox` profile 不再使用，可手工删除。
- **生命周期靠守卫**：`KILL_ON_JOB_CLOSE` 保证 judger 崩溃时全家终止；临时
  目录由 `Drop` 删除；judger 被硬杀时残留的目录由下次构造时的清扫回收
  （只清属主进程已死的目录）。

## 6. 攻击面回归清单

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

第 7/8 项：win32k 锁定下任何静态导入 user32 的进程（含
PowerShell/CLR/`_ctypes.pyd`）在加载阶段即失败，探针只能用纯 Python 或
纯 kernel32 的原生程序。

## 7. 测试

```shell
uv sync --extra test && uv run maturin develop
uv run pytest                          # functional / attack / limits 三件套
cargo test --lib -- --test-threads=1   # rust 单测
```

Python 套件在沙箱内跑真实程序（被测解释器 = `sys.executable`）。攻击探针
用纯 Python——win32k 锁定下 ctypes 不可用。Windows 子进程输出带 `\r\n`，
测试断言统一用 `rstrip()` 或精确字节。

**测试有效性纪律**：断言必须"非平凡"。例如"judger 被中断后无孤儿进程"
那条用例，去掉 `KILL_ON_JOB_CLOSE` 后必须失败才算有效断言；清理动作只能
放在断言**之后**，否则断言会被清理动作本身满足而变成同义反复。
