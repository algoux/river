# river 开发计划

> 本文是实现阶段的入口文档：读完本文，再读 `docs/design.md`（设计定稿，实现的唯一依据，附录含参考资料）和 `docs/example.py`（API 目标），就可以开始干活。
> 测试机器、账号、路径、准备命令等本地信息只写在 `docs/environment.local.md`（已 gitignore，只在本机）。

## 0. 协作规则

- 用中文交流；技术名词、代码、命令、报错原文保持英文。先结论后细节。
- 改动前说清楚范围（动哪些文件、改成什么样）。破坏性操作（删除、覆盖、批量重写）先列清单再动手。
- **每次 `git push` 之前都要确认**；其他不可逆/对外可见的操作同样先确认。
- **服务器地址、账号、绝对路径等本地信息只写 `*.local.md`**，不进任何会提交的文件。
- 不擅自扩大改动范围；发现顺带的问题可以指出，但别顺手改。
- 报错照实贴原文和退出码，判断不了就说判断不了。
- 交付时用 `文件路径:行号` 指出改动位置。
- CI 不在当前阶段范围内。除非要求，不做冒烟测试。
- 设计已经定稿（`docs/design.md`），实现中遇到设计没覆盖的情况：小的自行决定并回写到 design.md；涉及语义/接口的先问。

## 1. 仓库现状（2026-11-24，PR 2 之后）

| 项 | 现状 |
|---|---|
| 分支 / 远端 | `master` @ `4d98ce6`（旧实现，未动）；`dev` @ `fe92fca`（PR 2），`origin = git@github.com:algoux/river.git` |
| 工作分支 | 所有开发在 `dev`；其他开发机从 GitHub 拉 `dev`（同步方式见 `docs/environment.local.md`） |
| 已跟踪 | `Cargo.toml`、`Cargo.lock`、`pyproject.toml`、`uv.lock`、`README.md`、`LICENSE`、`.gitignore`、`python/river/`、`src/{lib,api,preflight,cgroup}.rs`、`src/exec/{mod,child,mount,caps,idmap,landlock,seccomp,supervise,io}.rs`、`tests/test_doctor.py`、`tests/test_functional.py`、`tests/conftest.py`、`docs/`（`design.md`、本计划、`example.py`） |
| 不提交 | `docs/environment.local.md`（`*.local.md`）、`.venv/`、`target/`、`python/river/_river.abi3.so`（`maturin develop` 的 editable 产物，`*.so` 已忽略）、`.dsh/`、`.mypy_cache/`、`.ruff_cache/` |
| 依赖 | `pyo3 0.30`（`abi3-py312`）、`libc`、`rustix 0.38`、`seccompiler 0.5`、`landlock 0.4`（crates.io 上的 crate 名；项目名叫 rust-landlock）、`caps 0.5`；Python ≥ 3.12，pytest ≥ 8 |

## 2. 开发工作流（通用）

- Windows 侧只做编辑、`git commit`、`git push`（推送前确认）和 ssh；不在 Windows 上构建。
- Linux 侧（WSL 或远端）构建与测试。构建产物放在 Linux 原生文件系统，不要放在 Windows 盘的挂载点上。
- 通用命令（在仓库根目录，以将要运行 river 的普通用户执行）：
  ```sh
  uv sync --extra test && uv run maturin develop
  systemd-run --user --scope -p Delegate=yes --setenv=RIVER_TEST_ROOTFS=<rootfs 路径> -- .venv/bin/python -m pytest -x
  ```
- `systemd-run` 里面必须是解释器本身（`.venv/bin/python`），不要套 `uv run`/`make`：它们会留一个父进程在 scope 里，river 无法在那里启用控制器（`EBUSY`）。`uv sync`/`uv run maturin develop` 放在 `systemd-run` 外面即可。
- rootless 路径必须用**非特权账号**验证；用 root 测试会绕过 unprivileged userns，不能作为依据。
- rootfs 用 `docker create python:3.12-slim` → `docker export` → 以运行 river 的用户 `tar -xp --no-same-owner` 解压，再写 `meta.json`（命令见 `docs/environment.local.md`，README 在 PR 5 写通用版本）。
- 提交信息沿用仓库风格：`feat(linux): ...`、`docs: ...`、`test: ...`。

## 3. 明确不做的事

以下都讨论过并决定不做，实现时不要加回来：

- 树级 `cpu.stat` 轮询（CPU 总量靶向 = `RLIMIT_CPU` + 墙钟 + 事后判定）；不再使用 `cpu.max`。
- D-Bus / `zbus` 自动申请 cgroup scope；拿不到委托就报错。
- overlay CoW rootfs、subuid/`newuidmap`、idmapped mount、squashfs/loopdev。
- CI / GitHub Actions（P4 再说）。
- Windows / macOS 后端。
- 沙箱内网络（只有 `lo`）。
- 旧内核兼容、任何形式的 fallback 路径。

## 4. PR 计划

每个 PR 独立可验证，做完再开下一个。验证命令在 WSL 和远端两套环境各跑一遍（至少功能组）。

### PR 1 清场 + 骨架 + `river.doctor()` ✅ 已完成（2026-11-24，`dev` @ `a302ebb`）

目标：删掉旧实现，建立新骨架，`doctor()` 能给出与 `docs/environment.local.md` 一致的环境报告。

删除（已确认，执行时仍先列清单）：`src/`、`examples/`、`tests/`、`river.pyi`、`Cargo.lock`、`uv.lock`、`.github/`。

新建 / 重写：

| 文件 | 内容 |
|---|---|
| `Cargo.toml` | `[package] name="river"`，edition 2024，`[lib] crate-type=["cdylib","rlib"]`；依赖 `pyo3`（`abi3-py312` + `extension-module` feature 交给 maturin）、`libc`、`rustix`（features：`mount thread process fs event system time`）、`seccompiler`、`landlock`（crate 名；项目名 rust-landlock）、`caps`；只支持 Linux，不需要 `cfg(target_os)` 分支 |
| `pyproject.toml` | maturin backend；`requires-python >= 3.12`；`[tool.maturin] module-name = "river._river", python-source = "python", features = ["pyo3/extension-module"]`；`[project.optional-dependencies] test = ["pytest>=8"]`；`[tool.pytest.ini_options] testpaths=["tests"]`、markers：`functional limits attack concurrency doctor`；`[tool.uv] package = false` |
| `python/river/__init__.py` | `from river._river import River, ExecResult, RiverError, KernelTooOldError, ...`；`doctor()` 的 Python 侧（调用 `_river.run_doctor_checks(raise_on_fail)`，组装 `DoctorReport`）；`__all__` |
| `python/river/_river.pyi`、`py.typed` | 原生模块的类型存根 |
| `src/lib.rs` | `#[pymodule] mod _river`（声明式 `#[pymodule_export]`）：导出异常类、`River`、`ExecResult`、`run_doctor_checks()` |
| `src/api.rs` | `River` / `ExecResult` 的 PyO3 类骨架：`River.__init__` 调 `preflight::check_all()` + rootfs 检查；`exec()` 暂抛 `NotImplementedError`；异常类层级用 `create_exception!`（design.md §4） |
| `src/preflight.rs` | design.md §8 全部检查，按序为 `platform kernel userns.max userns.apparmor userns.probe cgroup workdir landlock_abi`，返回 `Vec<(name, ok, detail, remediation)>`；**检查名 → 异常的映射只在这里**，`run_doctor_checks(raise_on_fail)` 同时服务 `doctor()` 和 `River()`；内核版本解析用 `uname()`；AppArmor knob 不存在视为通过；userns 探测 = `fork` 一个子进程 `unshare(CLONE_NEWUSER)` 后 `_exit(0/errno)`；Landlock ABI 作为信息项（裸 syscall，libc 没有 `LANDLOCK_CREATE_RULESET_VERSION`）；rootfs 挂载点补建与 `meta.json` 校验也在这里 |
| `src/cgroup.rs` | design.md §7 第 1–5 步 + 进程级单例 `OnceLock`；`doctor()` 与 `River()` 共用这个单例——只读 `cgroup.controllers` 检测不出未委托（WSL 的 `/non-systemd` 也显示有控制器），必须真的走到第 5 步；`EBUSY` 时列出 `<base>` 内残留进程；run cgroup 的创建留到 PR 3 |
| `tests/test_doctor.py` | 委托 / 非委托两组用 `skipif` 互斥：委托环境下 `doctor()` 全绿、`raise_on_fail=False` 结构正确、单例已建立；非委托环境下 `raise_on_fail=True` 抛 `CgroupNotDelegatedError` 且含修复命令。另有一个**确定性**负向用例：子进程把自己挪进 `river/` 下一个无控制器的子 cgroup 再跑 `doctor()`（"兄弟 scope"在当前 systemd 上不可靠，见 design.md §7）。`River()` 的挂载点补建 / `meta.json` 用 `tmp_path`，真实 rootfs 用例靠 `RIVER_TEST_ROOTFS` |
| `README.md` | 重写：一句话定位、状态（开发中）、指向 `docs/design.md` 与本计划、通用开发命令（§2）。不写任何机器信息 |
| `.gitignore` | 追加 `.mypy_cache/`、`.ruff_cache/`、`*.so`（`*.local.md` 已加） |

验证：

```sh
uv run maturin develop && systemd-run --user --scope -p Delegate=yes -- .venv/bin/python -c "import river; print(river.doctor())"
systemd-run --user --scope -p Delegate=yes -- .venv/bin/python -m pytest -m doctor
```

完成标准：两套环境（远端用非特权账号）上 `doctor()` 报告与 `docs/environment.local.md` 的环境表一致；在非委托环境下 `doctor(raise_on_fail=True)` 抛 `CgroupNotDelegatedError` 且消息含修复命令；`git status` 干净且没有 `*.local.md` 被跟踪；`dev` 分支已推送（推送前确认）。

**结果：全部满足。** WSL：委托 12 过 3 跳，非委托 6 过 9 跳；远端 tester：委托 13 过 2 跳（带真实 rootfs），非委托 6 过 9 跳；两套 `doctor()` 各项与环境表一致，Landlock ABI 见 §5 V6。执行中修正了计划的两个假设：启动命令里不能套 `uv run`（§2），crate 名是 `landlock`。

### PR 2 P0 沙箱 ✅ 已完成（2026-11-24，`dev` @ `fe92fca`）

目标：`docs/example.py` 原样跑通，`AC`/`RE` 正确，计量有值。

范围：`src/exec/{mod,child,mount,caps,idmap,landlock,seccomp,supervise,io}.rs`（design.md §3、§5、§9、§10 的全部内容，cgroup 相关调用先留空位）。PyO3 侧：`River.exec()` 完整签名、`ExecResult`、`ExecSetupError`（含 step + errno）。

实现要点：

- 子进程代码路径（`child.rs`）只能用 `rustix`/`libc` 裸 syscall，不分配、不加锁；`ChildSpec` 在父进程预序列化（`CString` 数组、`O_PATH` fd）。
- `clone3`：优先 `libc::clone3`（libc ≥ 0.2.15x 有 `clone_args`），否则 `nix::sched::clone`；flags 见 design.md §3；`CLONE_PIDFD` 拿 pidfd。
- `mount_setattr`：rustix 0.38 若未暴露，直接 `libc::syscall(SYS_mount_setattr, ...)`。
- Landlock：按 ABI 版本取交集；内核不支持（`ENOSYS`）时跳过并在 `RIVER_LOG=debug` 下打印警告（WSL 内核可能没有 Landlock）。
- `PR_SET_PDEATHSIG` + `getppid()` 校验放在子进程第一步。
- 父进程：单线程 epoll（`rustix::event::epoll`）覆盖 pidfd / stdout / stderr / stdin 写端 / sync socket；超时 = `min(墙钟 deadline, 100ms)`；空醒时 `Python::with_gil(PyErr::check_signals)`。
- 计量：`cpu.stat usage_usec`、`memory.peak`（PR 3 才有 run cgroup，PR 2 先从 `River` 的 `river/` cgroup 读，值不准没关系，接口到位）。

测试（`tests/test_functional.py`，marker `functional`）：hello world；stdout/stderr 捕获；非 0 退出 → `RE` + `exit_code`；`kill -SEGV $$` → `RE` + `signal=11`；`cwd`；`envs` 来自 meta.json 与显式覆盖；`stdin` bytes；`/sys` 已挂载且 `/dev/null` 可写（V9）；`executable` 不存在 → `ExecSetupError`；`cwd` 不存在 → `ExecSetupError`；8 线程并发 exec。

完成标准：以上测试两套环境全绿；`RIVER_TEST_ROOTFS` 指向 docker 导出的 `python:3.12-slim`。

**结果：全部满足。** WSL（委托 scope）与远端 tester 各 32 过 2 跳（跳过的是非委托环境用例；functional 组 20/20）。`docs/example.py` 的调用形态由 `test_example_py_call_shape` 逐参数复刻验证（其 `stdin_file="input.txt"` 原先与 `copy_in={}` 自相矛盾，已按拍板结论改为 `copy_in={"input.txt": "1 2 3\n"}`；`stdin_file` 不存在 → `ExecSetupError`）。执行中修正了设计的多处内核级假设并已回写 design.md §4/§5/§9：pdeathsig 校验改读 `/proc/self/status` 的 PPid（NEWPID 下 getppid 恒为 0）；rootfs 进入与 ro-bind 改用 open_tree 分离挂载配方（对已挂 bind 的 mount_setattr 恒 EINVAL，旧式 bind+remount 被忽略）；ptmx bind 新实例的 `./dev/pts/ptmx`；`PR_SET_SECUREBITS` rootless 不可达（删）；Landlock 设备授权补 `IOCTL_DEV`（openpty）；≥6.6 内核 sysfs 自动挂 cgroup2，用 ro tmpfs 盖 `./sys/fs`；pid-1 丢弃无 handler 的自杀信号（`RE`+signal 用真实 fault 验证）。V4/V5 不成立、V7/V8/V9 通过（§5）。远端 `systemd-run` 需显式 `--setenv=HOME`（pytest 9 探测 `$HOME/pytest.toml`，scope 继承的 HOME 不可靠；记录在 environment.local.md）。

### PR 3 P1 cgroup

目标：所有限制参数生效，`TLE`/`MLE`/`OLE` 判定正确。

范围：`src/cgroup.rs` 补全（run cgroup 创建、knob 写入、`cgroup.procs`、`cgroup.kill`、`populated=0` 等待、`rmdir`）；`supervise.rs` 的墙钟与 OLE 杀；`child.rs` 的 rlimits；`classify()`。

测试（`tests/test_limits.py`，marker `limits`；内存数值按远端机器调小）：CPU 死循环 `cpu=1000, wall=5000` → `TLE` 且 `signal=24`（SIGXCPU）或 9；`sleep 10` + `wall=300` → `TLE`；分配 256 MB + `memory=64M` → `MLE`；打印 1 MB + `stdout_limit=64K` → `OLE`；fork 炸弹 + `proc_limit=16` → 子进程 `EAGAIN`，主程序正常结束；`copy_out_limit_bytes` 超限 → `CopyOutError`（若 PR 5 未做 copy_out，此用例挪到 PR 5）。

完成标准：两套环境全绿；每个限制参数为 `None` 时对应 knob 确认未被写入（读 cgroup 文件断言 `max`）。

### PR 4 P2 加固

目标：seccomp denylist + Landlock 生效，攻击用例全部被拒。

范围：`src/exec/seccomp.rs`（design.md §9 列表，`seccompiler` 按 syscall 名生成；`clone3` → `ENOSYS`；`clone`/`unshare` masked 过滤；`socket` 域白名单）、`src/exec/landlock.rs` 完整规则。

测试（`tests/test_attack.py`，marker `attack`）：沙箱内 `unshare -U` / `clone(CLONE_NEWUSER)` 失败；`socket(AF_NETLINK)` → `EPERM`；`mount` → `EPERM`；写 `/usr/x` → `EROFS`；写 `/work/x` 成功；`echo > /dev/null` 成功；写 `/sys/x` 失败；`/proc` 只能看到自己的 pid；`/sys/fs/cgroup` 不存在；`ls /` 无宿主目录；`copy_out` 一个指向 `/etc/passwd` 的 symlink → `CopyOutError`（若 PR 5 未做，挪到 PR 5）。

### PR 5 P3 I/O 与文档

目标：`copy_in/copy_out`、`stdin_file/stdout_file/stderr_file`、`meta.json` 全部按 design.md §4.1/§10 工作；README 可照做。

范围：`src/exec/io.rs`（`openat2 RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS`，`copy_out_limit_bytes`，`CopyOutError.result`）；`child.stdio` 的文件分支与 `RLIMIT_FSIZE`；README（安装、rootfs 制作、`systemd-run` 用法、API 示例即 `docs/example.py`；不含任何机器信息）。

测试：补 `functional` 组的 copy_in/out、`*_file`、symlink 拒绝、`copy_out_limit_bytes`、目录/设备文件拒绝；`CopyOutError.result` 可访问。

### PR 6 P4 发布

目标：manylinux wheel，`pip install river` 开箱即用。

范围：在 docker 的 `ghcr.io/pyo3/maturin:latest`（manylinux）里 `maturin build --release`，x86_64 优先，aarch64 用 `cross`/`zigbuild`；版本号 `0.1.0`；README 补安装说明；CI 此时再建。

## 5. 早期需要验证的假设

PR 2 开始前（或进行中）用最小代价确认，结果回写到 design.md；具体命令见 `docs/environment.local.md`。

| # | 假设 | 验证方法 | 不成立时 | 结果 |
|---|---|---|---|---|
| V1 | WSL 内核允许非特权 userns + mount ns + pivot_root | `bwrap --unshare-all --ro-bind / / --proc /proc --dev /dev -- /bin/true` | WSL 只做编辑，构建测试全部去远端 | ✅ 通过（2026-11-23） |
| V2 | WSL 上从 `wsl.exe -e` 环境能用 `systemd-run --user --scope -p Delegate=yes` | 在该环境里 `systemd-run --user --scope -p Delegate=yes -- cat <自身 cgroup>/cgroup.controllers`，期望含 `cpu memory pids` | 改用登录 shell 或只在远端跑 | ✅ 通过；但 scope 内必须直接启动 `.venv/bin/python`（§2） |
| V3 | 远端非特权账号的 session scope 已委托 | 以该账号 `cat /sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)/cgroup.controllers`，且目录属主为该账号 | 一律用 `systemd-run --user --scope` | ⚠️ 部分：经 `sudo -u` 启动落在调用者（root）的 session scope，**非委托**；`systemd-run --user --scope -p Delegate=yes`（需 `XDG_RUNTIME_DIR`）已验证全绿。真正的登录 session 未测，一律按"不成立"处理 |
| V4 | `libc` 暴露 `clone3` + `clone_args` | `grep clone3 ~/.cargo/registry/src/*/libc-*/src/unix/linux_like/linux/gnu/mod.rs` | 用 `nix::sched::clone` 或手写 `syscall(SYS_clone3)` | ❌ 不成立（2026-11-24）：libc 0.2.191 的 gnu 目标没有 `clone3`/`clone_args` 绑定（仅 musl 有）→ 手写 `struct clone_args` + `libc::syscall(SYS_clone3, …)` 直调，不引入 nix |
| V5 | rustix 0.38 有 `mount_setattr` | docs.rs `rustix::mount` | `libc::syscall(SYS_mount_setattr, …)` | ❌ 不成立（2026-11-24）：rustix 0.38 未暴露 → `libc::syscall` 直调；且实测**对已挂接的 bind 修改属性恒 `EINVAL`**（内核 `MNT_LOCK_*` 语义），旧式 bind+remount 也会静默忽略 flag——最终采用 `open_tree(OPEN_TREE_CLONE)` 分离挂载 + `mount_setattr` + `move_mount` 配方（见 design.md §5 回写） |
| V6 | Landlock 在两套环境的 ABI 版本 | PR 1 的 `doctor()` 输出 `landlock_abi` | ABI 0 → Landlock 自动关闭并警告（design.md §9） | ✅ WSL（6.18）ABI v7，远端（7.0）ABI v8；§9 列出的全部权限都可用 |
| V7 | `/dev/ptmx` 从 `/dev/pts/ptmx` bind 后 `openpty` 可用 | PR 2 功能测试：沙箱内 `python -c "import pty; pty.openpty()"` | 改为 bind 宿主 `/dev/ptmx` | ✅ 通过（2026-11-24，WSL）：但 bind 的必须是**新实例自己的** `./dev/pts/ptmx`（bind 宿主 ptmx 会链到宿主 devpts 实例，`openpty` 拿不到 slave）；另外 Landlock 必须给设备授 `IOCTL_DEV`（`openpty` 的 `TIOCGPTN` ioctl），否则 `ENXIO` |
| V8 | docker 导出的 rootfs 以运行用户解压后 Python 能在沙箱内启动 | PR 2 的 hello world | 检查 `ld.so.cache`、`/usr/local/bin/python` 符号链接是否保留（`tar -p`） | ✅ 通过（2026-11-24，WSL）：hello world 在 `python:3.12-slim` rootfs 内 `AC` |
| V9 | user namespace 内能只读挂载 sysfs；Landlock 开启后 `/dev/null`、`/dev/urandom` 读写正常 | PR 2：沙箱内 `python -c "import os; os.write(os.open('/dev/null', os.O_WRONLY), b'x'); print(os.listdir('/sys')[:3])"` | sysfs 挂载失败 → 改为只读 bind 宿主 `/sys`；设备写入失败 → 补 Landlock `WRITE_FILE` 规则（design.md §9） | ✅ 通过（2026-11-24，WSL）：sysfs 只读挂载、`/dev/null` 可写、`/dev/urandom` 可读；6.6+ 内核在 userns 内挂 sysfs 会**自动挂 cgroup2** 到 `/sys/fs/cgroup`（视图暴露调用方 cgroup 子树），用 ro tmpfs 覆盖 `./sys/fs` 解决 |

## 6. 风险

| 风险 | 应对 |
|---|---|
| WSL 内核缺 Landlock / 其他特性 | 已实测 WSL Landlock ABI v7、远端 v8，未发生；doctor 仍把 Landlock 作为信息项而非失败项 |
| 远端机器内存较小（< 2 GB） | 测试用的内存限制 ≤ 256 MB；不要并行跑大内存用例 |
| `clone3` 后子进程里 Rust 运行时行为 | 子进程路径只放裸 syscall；PR 2 用 `RIVER_LOG=debug` 逐步打点确认每个 step |
| `/work` 在 `$XDG_RUNTIME_DIR` 下占满 tmpfs | `memory.max` 计入 tmpfs 页；exec 结束即删；PR 5 评估是否需要 `nr_inodes` |
| 调用方 Python 进程本身不在委托 cgroup 里 | 这是 fail-fast 的预期行为；doctor 消息给出 `systemd-run --user --scope -p Delegate=yes` 命令 |
| 委托 cgroup 里还有别的进程（外层 `uv run`/`make`、`sudo -u` 落进调用者的 session scope） | 第 5 步 `EBUSY` 时 doctor 列出残留进程；验证命令一律 `systemd-run ... -- .venv/bin/python`（§2），远端加 `XDG_RUNTIME_DIR` |
| 用户 scope 的委托表现随 systemd 版本变化（`Delegate=yes` 启用的控制器会留在父 slice，兄弟 scope 看起来也"已委托"） | 不用兄弟 scope 模拟非委托环境；负向用例用 `river/` 下无控制器的子 cgroup（design.md §7 第 5 步） |
