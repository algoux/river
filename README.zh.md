# river

[English](README.md) | 简体中文

river 是一个 Python 库：把任意程序放进一个以调用方提供的 rootfs 为基础搭建的
无 root Linux 沙箱里运行，并给出评测级的资源占用与判定结果（`AC` / `RE` /
`TLE` / `MLE` / `OLE`）。

- **无 root（rootless）** —— 不需要 root，不需要 setuid 辅助程序，也不依赖任何
  外部沙箱二进制；全程只有当前用户和内核参与。
- **低开销** —— 每次 `exec` 的开销在个位数毫秒；没有守护进程，也不做轮询。
- **限额与计量** —— CPU 时间、墙钟时间、内存、输出量、进程数都既强制执行，又
  如实计量；`None` 表示不限。
- **只面向较新的内核**（≥ 6.8）：用户命名空间、委派的 cgroup v2、Landlock 与
  seccomp 全部默认开启；不为旧版本内核提供兼容回退。

下面的 API 一节就是完整接口说明。

**状态：PyPI 上已发布 v0.1.1。** PyPI 上的发行名是 `river-sandbox` —— 那里 `river`
这个名字属于另一个（无关的）在线机器学习库 —— 而导入名仍然是 `river`。v0.1.0 的
wheel 也放在 [releases 页面](https://github.com/algoux/river/releases)。

## 环境要求

- Linux ≥ 6.8，x86_64（seccomp 拒绝清单目前是 x86_64 专用的）。
- systemd，统一 cgroup v2 层级，并且有一棵委派给你的用户的 cgroup 子树。
- 非特权用户命名空间：`user.max_user_namespaces > 0`；在 Ubuntu ≥ 23.10 上还需
  要 `kernel.apparmor_restrict_unprivileged_userns = 0`。

`river.doctor()` 会检查每一项要求，把 Landlock ABI 作为提示信息列出，并打印出
失败项对应的确切修复方法 —— 先跑它：

```python
import river
print(river.doctor())
```

## 安装

Linux x86_64，Python ≥ 3.12。PyPI 上的发行名是 `river-sandbox`，导入名仍然是
`river`：

```sh
pip install river-sandbox
```

已发布的 v0.1.0 wheel 也可以直接从 GitHub 取：

```sh
pip install https://github.com/algoux/river/releases/download/v0.1.0/river-0.1.0-cp312-abi3-manylinux2014_x86_64.manylinux_2_17_x86_64.whl
```

想从源码构建同一个 wheel，一条 docker 命令就够了 —— 不需要 Rust 工具链，因为
[pyo3/maturin 镜像](https://www.maturin.rs/distribution)本身就是 manylinux2014
（glibc 2.17）构建环境：

```sh
git clone https://github.com/algoux/river.git
cd river
docker run --rm -v "$(pwd):/io" ghcr.io/pyo3/maturin:latest \
    build --release --locked -i python3.12 -o "$(pwd)/target/wheels"
pip install target/wheels/river_sandbox-*.whl
```

`-i python3.12` 固定了解释器版本，于是 abi3 wheel 会带上与 `requires-python >=
3.12` 对应的 `cp312` tag：产物
`river_sandbox-<version>-cp312-abi3-manylinux_2_17_x86_64.whl` 可以装到任何
CPython ≥ 3.12 上。如果你已经有 Rust 工具链，也可以直接构建进当前虚拟环境
（`pip install maturin && maturin develop`）。推送 tag 时，同一个 wheel 会通过
[.github/workflows/release.yml](.github/workflows/release.yml) 挂到 GitHub
release 上。

不构建 aarch64 wheel：seccomp 拒绝清单里的若干项（`nfsservctl`、`sysfs`、
`iopl` 等）是 x86_64 专有的系统调用号，x32 ABI 守卫也是 x86_64 专有的 —— 要
移植得先按架构裁剪这份清单。

## 准备 rootfs

rootfs 是一个存放完整用户空间的目录，通常从容器镜像导出。**要以将来运行 river
的那个用户来解包**：沙箱会把你的 uid 映射成内部的 root，别人拥有的文件会显示
为损坏。

```sh
mkdir -p /rootfs/python
docker create --name py python:3.12-slim
docker export py | tar -xp --no-same-owner -C /rootfs/python
docker rm py
printf '{"envs":{"PATH":"/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin","HOME":"/work"}}' > /rootfs/python/meta.json
```

`meta.json` 提供每次 `exec` 在未指定 `envs` 时使用的环境变量 —— `PATH` 决定了
沙箱内 `executable="python"` 能否被搜索到。换成别的镜像也一样：river 只会创建
缺失的挂载点（`proc`、`sys`、`dev/pts`、`tmp`、`work` 等），不会改动任何已有
文件。

## 运行：被委派的 cgroup

river 需要一棵委派给你的用户的 cgroup v2 子树来施加限额、采集指标以及实现墙钟
超时 kill；没有它 river 会直接拒绝运行（抛 `CgroupNotDelegatedError`，而不是
悄悄丢掉所有限额）。让解释器本身跑在被委派的 scope 里：

```sh
systemd-run --user --scope -p Delegate=yes -- python app.py
```

解释器必须是该 scope 里唯一的进程：会常驻的包装脚本（`uv run`、`make` 等）会
在 cgroup 里留下第二个进程，river 无法在那里启用控制器 —— 出现这种情况时
`river.doctor()` 会准确地报出来。

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

`ExecResult` 还带有 `stdout` / `stderr`（`bytes | None`，指定了 `*_file` 时为
`None`）、`files`（`copy_out` 中值为 `None` 的那些条目）以及 `error`（非 `AC`
判定背后的人类可读原因）。

判定：`AC` —— 退出码 0；`RE` —— 非零退出或被信号杀死（`signal` 指明是哪个）；
`TLE` —— 墙钟时间或 CPU 预算耗尽；`MLE` —— cgroup 把整棵进程树 OOM 杀掉；
`OLE` —— 输出超过上限。同时命中时按 `OLE` > `MLE` > `TLE` > `AC`/`RE` 优先。

沙箱内的任何结束状态都会落到 `ExecResult` 里；只有准备阶段的失败才抛异常 ——
`ExecSetupError`（带失败步骤，例如 `child.mount.proc`）、`RootfsError`，以及
`CopyOutError`（它的 `.result` 保存了已完成的那次运行）。它们都继承自
`river.RiverError`，`KernelTooOldError`、`UserNamespaceDeniedError` 和
`CgroupNotDelegatedError`（`doctor()` 在第一个失败检查上抛出的那个）也一样。

有两个环境变量，只用于调试、不是配置项：`RIVER_LOG=debug` 会在 stderr 上跟踪
父进程与子进程的每一步；`RIVER_HARDENING=off` 只关闭 seccomp 和 Landlock
（命名空间、只读 rootfs 和能力集丢弃仍然保留），用来区分「程序本身有问题」和
「加固层拦住了它」。

沙箱内部：程序是新 pid 命名空间里的 pid 1（它一死，整棵进程树跟着死）；`/work`
是唯一由宿主支撑的可写目录（`copy_in`/`copy_out`/`*_file` 的路径必须落在它下面）；
rootfs 只读；`/proc` 与 `/sys` 是全新的实例；网络只有一个孤立的 `lo`；seccomp 与
Landlock 会挡住命名空间创建、非常规的 syscall 家族，以及所有可写挂载点之外的
写入。

## 开发

仅 Linux。以将来运行 river 的那个非特权用户来构建和测试，并让进程处在被委派的
cgroup 里：

```sh
uv sync --extra test && uv run maturin develop
systemd-run --user --scope -p Delegate=yes -- .venv/bin/python -c "import river; print(river.doctor())"
systemd-run --user --scope -p Delegate=yes --setenv=RIVER_TEST_ROOTFS=<rootfs> -- .venv/bin/python -m pytest -x
```

代码格式与导入顺序统一交给 ruff（它的 isort 规则取代了独立的 isort）：
`uv run ruff check . && uv run ruff format .`。

功能测试用的 rootfs 是 docker 导出的 `python:3.12-slim` 目录树（做法见上文）。
驱动这次实现的设计文档与 PR 计划在 0.1.0 发布后已删除 —— 两者仍可从 git 历史
里找回，直到 tag `v0.1.0` 为止。机器相关的笔记不会进仓库。
