# river

[English](README.md) | 简体中文

river 是一个 Python 库：把任意程序放进一个以调用方提供的 rootfs 为基础搭建的无 root Linux 沙箱里运行，并给出评测级的资源占用与判定结果（`AC` / `RE` / `TLE` / `MLE` / `OLE`）。

- **无 root（rootless）** —— 不需要 root，不需要 setuid 辅助程序，也不依赖任何外部沙箱二进制；全程只有当前用户和内核参与。
- **低开销** —— 每次 `exec` 的开销在个位数毫秒；没有守护进程，也不做轮询。
- **限额与计量** —— CPU 时间、墙钟时间、内存、输出量、进程数都既强制执行，又如实计量；`None` 表示不限。
- **只面向较新的内核**（≥ 6.8）：用户命名空间、委派的 cgroup v2、Landlock 与 seccomp 全部默认开启；不为旧版本内核提供兼容回退。

下面的 API 一节就是完整接口说明。

## 环境要求

- Linux ≥ 6.8，x86_64。
- systemd，统一 cgroup v2 层级，并且有一棵委派给你的用户的 cgroup 子树。
- 非特权用户命名空间：`user.max_user_namespaces > 0`；在 Ubuntu ≥ 23.10 上还需要 `kernel.apparmor_restrict_unprivileged_userns = 0`。

`river.doctor()` 会检查每一项要求，把 Landlock ABI 作为提示信息列出，并打印出失败项对应的确切修复方法：

```python
import river
print(river.doctor())
```

## 安装

Linux x86_64，Python ≥ 3.12。PyPI 上的发行名是 `river-sandbox`，导入名仍然是 `river`：

```sh
pip install river-sandbox
```

通过 Docker 构建

```sh
git clone https://github.com/algoux/river.git
cd river
docker run --rm -v "$(pwd):/io" ghcr.io/pyo3/maturin:latest \
    build --release --locked -i python3.12 -o "$(pwd)/target/wheels"
pip install target/wheels/river_sandbox-*.whl
```

## 准备 rootfs

rootfs 是一个存放完整用户空间的目录，通常从容器镜像导出。**要以将来运行 river 的那个用户来解包**：沙箱会把你的 uid 映射成内部的 root。

```sh
mkdir -p /rootfs/python
docker create --name py python:3.12-slim
docker export py | tar -xp --no-same-owner -C /rootfs/python
docker rm py
printf '{"envs":{"PATH":"/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin","HOME":"/work"}}' > /rootfs/python/meta.json
```

`meta.json` 提供每次 `exec` 在未指定 `envs` 时使用的环境变量 —— `PATH` 决定了沙箱内 `executable="python"` 能否被搜索到。换成别的镜像也一样：river 只会创建缺失的挂载点（`proc`、`sys`、`dev/pts`、`tmp`、`work` 等），不会改动任何已有文件。

## 运行：被委派的 cgroup

river 需要一棵委派给你的用户的 cgroup v2 子树来施加限额、采集指标以及实现墙钟超时 kill；没有它 river 会直接拒绝运行。让解释器本身跑在被委派的 scope 里：

```sh
systemd-run --user --scope -p Delegate=yes -- python app.py
```

解释器必须是该 scope 里唯一的进程：会常驻的包装脚本（`uv run`、`make` 等）会在 cgroup 里留下第二个进程，river 无法在那里启用控制器 —— 出现这种情况时 `river.doctor()` 会准确地报出来。

## API

完整接口：

```python
from river import River

with River("/rootfs/python") as river:
    r = river.exec(
        "python",                          # str | os.PathLike; without '/' searched on the sandbox PATH
        args=["-c", "print('Hello, World!')"],
        cwd="/work",                       # sandbox-absolute working directory
        envs={                             # Mapping[str, str]; None -> meta.json envs
            "PATH": "/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        },
        cpu_time_limit_ms=1000,            # RLIMIT_CPU + cpu.stat verdict
        wall_time_limit_ms=2000,          # cgroup.kill at the deadline
        memory_limit_bytes=64 * 1024 * 1024,   # memory.max, OOM group kill
        stdout_limit_bytes=64 * 1024,      # pipe cap or RLIMIT_FSIZE for *_file
        stderr_limit_bytes=64 * 1024,
        copy_in={"input.txt": "1 2 3\n"},  # Mapping[<sandbox path>, bytes | str | os.PathLike]
        copy_out={},                       # Mapping[<sandbox path>, None | str | os.PathLike]
        copy_out_limit_bytes=64 * 1024,
        stdin_file="input.txt",            # sandbox path, relative to cwd; mutually exclusive with stdin
        stdout_file="stdout.txt",          # sandbox path; result.stdout is then None
        stderr_file="stderr.txt",
    )
    print("Status:", r.status)             # AC / RE / TLE / MLE / OLE
    print("Exit Code:", r.exit_code)       # None when killed by a signal
    print("Signal:", r.signal)             # e.g. 11 SIGSEGV, 31 SIGSYS, 9 river's own kill
    print("CPU Time Used (ms):", r.cpu_time_used_ms)
    print("Wall Time Used (ms):", r.wall_time_used_ms)
    print("Memory Used (bytes):", r.memory_used_bytes)
```

`ExecResult` 还带有 `stdout` / `stderr`（`bytes | None`，指定了 `*_file` 时为 `None`）、`files`（`copy_out` 中值为 `None` 的那些条目）以及 `error`（非 `AC` 判定背后的人类可读原因）。

判定：`AC` —— 退出码 0；`RE` —— 非零退出或被信号杀死（`signal` 指明是哪个）；`TLE` —— 墙钟时间或 CPU 预算耗尽；`MLE` —— cgroup 把整棵进程树 OOM 杀掉；`OLE` —— 输出超过上限。同时命中时按 `OLE` > `MLE` > `TLE` > `AC`/`RE` 优先。

沙箱内的任何结束状态都会落到 `ExecResult` 里；只有准备阶段的失败才抛异常 —— `ExecSetupError`（带失败步骤，例如 `child.mount.proc`）、`RootfsError`，以及 `CopyOutError`（它的 `.result` 保存了已完成的那次运行）。它们都继承自 `river.RiverError`，`KernelTooOldError`、`UserNamespaceDeniedError` 和 `CgroupNotDelegatedError`（`doctor()` 在第一个失败检查上抛出的那个）也一样。

有两个环境变量，只用于调试、不是配置项：`RIVER_LOG=debug` 会在 stderr 上跟踪父进程与子进程的每一步；`RIVER_HARDENING=off` 只关闭 seccomp 和 Landlock（命名空间、只读 rootfs 和能力集丢弃仍然保留），用来区分「程序本身有问题」和「加固层拦住了它」。

沙箱内部：程序是新 pid 命名空间里的 pid 1（它一死，整棵进程树跟着死）；`/work` 是唯一由宿主支撑的可写目录（`copy_in`/`copy_out`/`*_file` 的路径必须落在它下面）；rootfs 只读；`/proc` 与 `/sys` 是全新的实例；网络只有一个孤立的 `lo`；seccomp 对白名单（x86_64 上约 250 个，见 `src/exec/seccomp.rs`；`clone` 只在不带 namespace flag 时放行，`socket` 只放行 `AF_UNIX`/`AF_INET`/`AF_INET6`）之外的每一个 syscall 都答 `EPERM`，Landlock 则挡住所有可写挂载点之外的写入。

## 开发

仅 Linux。以将来运行 river 的那个非特权用户来构建和测试，并让进程处在被委派的 cgroup 里：

```sh
uv sync --extra test && uv run maturin develop
systemd-run --user --scope -p Delegate=yes -- .venv/bin/python -c "import river; print(river.doctor())"
systemd-run --user --scope -p Delegate=yes --setenv=RIVER_TEST_ROOTFS=<rootfs> -- .venv/bin/python -m pytest -x
```

代码格式与导入顺序统一交给 ruff：`uv run ruff check . && uv run ruff format .`。

