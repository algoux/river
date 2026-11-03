# river 设计文档

river 是一个跨平台沙箱库（Python 扩展，Rust 实现），用于在受限环境中运行不受信任的
可执行文件并采集资源用量与结果。对标 go-judge 的 `exec` 语义，但不做判题比对——
比对/checker 永远是调用方（OJ 判题层）的职责。

## 1. 统一的三平台心智模型

所有平台共享同一个模型，平台差异只体现在实现机制上：

```
私有可写 cwd     每次 run 新建的临时工作目录，块退出即销毁
+ runtimes       宿主机目录以只读(+执行)方式并入沙箱（运行时环境）
+ copy_in        每 run 投放的私有文件（程序对它们默认只读）
+ env            增量合并进白名单基底（SystemRoot/TEMP/TMP 恒存在）
```

| 能力 | Linux | macOS | Windows |
|---|---|---|---|
| `rootfs` | ✅ chroot / pivot_root | ✅ sandbox-exec profile | ❌ 传入即 `ValueError` |
| `runtimes` 实现 | 只读 bind mount | 只读 profile 扩展 | AppContainer + 只读 ACL |
| 网络隔离 | namespace | profile | AppContainer 无 capability 即断网 |
| 资源限制 | cgroup | ... | Job Object |

Windows 不支持 `rootfs` 的原因：Windows 进程永远从真实 `System32` 加载系统 DLL，
"另一份操作系统"的语义不成立（除非容器/虚拟化，明确排除）。运行时环境（Python、
JDK 等）通过 `runtimes` 授权直读 + `env` 注入 PATH 组合出来。

## 2. 冻结的 API 契约

（完整签名见 `river.pyi`；用法示例见 `examples/example.py`）

### 2.1 Sandbox 构造

```python
river.Sandbox(rootfs=None, runtimes=None)
```

- `rootfs: str | os.PathLike | None` —— 仅 Linux/macOS；Windows 传入抛 `ValueError`
- `runtimes: Sequence[str | os.PathLike] | None` —— 只读运行时目录

### 2.2 run() 参数

| 参数 | 类型 | 坐标系 | 默认值语义 |
|---|---|---|---|
| `executable` | 路径 | 宿主机路径 | 必填 |
| `args` | `Sequence[str]` | — | `[]` |
| `cwd` | `str \| None` | **沙箱内相对路径** | 沙箱根（私有 cwd） |
| `env` | `Mapping[str, str] \| None` | — | 仅白名单基底 |
| `time_limit_ms` | `int \| None` | — | `None` = 不限制 |
| `wall_time_limit_ms` | `int \| None` | — | `None` = 不限制；仅设 `time_limit_ms` 时默认 `2×time_limit_ms + 1000` |
| `memory_limit_kb` | `int \| None` | — | `None` = 不限制 |
| `stdin` / `stdin_file` | `bytes` / 宿主机路径 | — | 互斥（同给抛 `ValueError`）；`stdin_file` 零拷贝优先 |
| `copy_in` | `Mapping[沙箱相对路径, bytes \| 宿主机路径]` | 键为沙箱相对路径 | 程序对文件默认**只读** |
| `stdout_limit_kb` / `stderr_limit_kb` | `int \| None` | — | 击杀阈值：超过即杀并判 OLE |
| `stdout_file` / `stderr_file` | 宿主机路径 | — | 完整输出留档（截至被杀为止）；与 `r.stdout`（截断 bytes）并存 |

**限制语义与机制的区分**：`None` 表示*调用方不设限*（语义），但后端始终存在内部
安全上限（机制）：wall clock ≤ 24h、内存 ≤ 物理内存。"无限" 不能意味着防护机制
不存在——无内存限制的 malloc 炸弹会拖垮宿主。

**校验规则**（跨平台，已实现于 `src/platform/mod.rs`）：
- `stdin` 与 `stdin_file` 互斥
- `copy_in` 键必须是沙箱内相对路径（拒绝绝对路径、盘符、`..` 逃逸）
- `copy_in` 值必须是 bytes 或宿主机路径

### 2.3 Status 字段

| 字段 | 类型 | 说明 |
|---|---|---|
| `time_used_ms` / `wall_time_used_ms` | `int` | CPU 时间 / 墙钟时间（ms）；TLE 判定取两者超限的并集 |
| `memory_used_kb` | `int` | 峰值内存（KB）。Windows 上为 commit 语义（见已知差异 §4） |
| `status` | `Literal["AC","TLE","MLE","OLE","RE","SE"]` | 判定 |
| `signal` | `int` | **合成值**：正常 0；沙箱强杀（TLE/MLE/OLE）为 9。Windows 无信号，此字段模仿 Linux 惯例便于调用方移植 |
| `exit_code` | `int` | 原始退出码；异常终止时为 NTSTATUS 值（如 `0xC0000005` 访问违例） |
| `stdout` / `stderr` | `bytes` | 截断后的输出 |
| `stdout_truncated` / `stderr_truncated` | `bool` | 各通道独立的截断标志 |

判定枚举含义：`AC` 正常退出（0）；`TLE` CPU/墙钟超限；`MLE` 内存超限；
`OLE` 输出超限；`RE` 非零退出/异常终止；`SE` 沙箱自身错误（spawn 失败等）。

### 2.4 `with` 块退出协议

`__exit__` 保证：无残留被测进程、临时工作目录已删除、令牌/句柄已释放。

## 3. 设计决策记录

1. **stdin 优先 Path，bytes 作便捷项**：大测试点文件走 `stdin_file` 零拷贝
   （句柄直传，被测进程无按路径重开的权限）；bytes 起喂线程。
2. **输出三机制分离**：`*_limit` 是击杀阈值（恒生效）、`*_file` 是完整留档
   （judger 从管道读全量落盘）、`r.stdout` 是截断采样。
3. **copy_in 默认只读**：同卷硬链接优化只有在拒绝写 ACE 下才安全（否则被测
   进程可篡改宿主源文件）；需要程序可写的文件走真拷贝（将来加白名单参数）。
4. **copy_in 不走 MoveFile**：移动保留源 ACL，拷贝继承目标目录 ACL；落盘后
   显式重置 ACL。
5. **不做交互题**：实时双向管道（interactor）是独立模式，将来单列，不塞进 run 参数。
6. **进程策略（分层）**：主进程是唯一的被评测对象；允许普通包装器
   （`cmd /c`、解释器辅助进程）派生，Job 内存活总数有上限（当前默认 64），
   fork 炸弹有界。**主进程退出即终止全部残余子孙**——程序不得把工作甩给
   子进程在主进程死后继续产出；检测到残余子孙时 verdict 为 `SE`（沙箱异常），
   而非误导性的 `AC`。
7. **`SE` 的语义范围**：判定为 `status="SE"` 的情况包括 (a) 沙箱自身错误
   （spawn 失败、清理失败），(b) 主进程死后仍有存活子孙（防甩锅）。
   参数校验失败仍抛 Python 异常，不走 `SE`。

## 4. 已知平台差异（文档化承诺）

- **内存语义**：Windows 的 Job 内存限制约束 commit 而非 RSS；惰性提交意味着
  `malloc` 大块不写入不触发 MLE（与 Linux overcommit 行为相近）。
- **计时抖动**：Windows 计时受调度/Defender/缺页影响大于 Linux，建议调用方
  放宽 5-10% 或取两次较优。实测基线（2026-11，Win11，8 路并发压力下）：
  固定 300ms 忙循环的墙钟测量中位数 323ms，10 次采样极差 2-4%，低于建议的
  5-10% 放宽窗口；单次冷启动（Defender 首次扫描）可能出现更大抖动。
- **并发**：`Sandbox` 可被多个 Python 线程并发 `run()`（内部无共享可变状态，
  已按进程串行化的系统级操作见 docs/windows-backend.md §9.2.7–§9.2.9）。
- **signal**：始终为合成值（见 §2.3）。

## 5. 参考实现

- DMOJ/wbox：Windows 沙箱评测的历史方案（临时低权用户 + 防火墙 + Job +
  DLL 注入），river 的 AppContainer 方案是其现代化替代
- criyle/go-judge：Linux 参照系；其 REST 请求/响应字段与本 API 大体同构
