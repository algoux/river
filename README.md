# river

English | [简体中文](README.zh.md)

river is a Python library that runs arbitrary programs inside a rootless Linux
sandbox built around a caller-supplied rootfs, and reports judge-grade resource
usage and verdicts (`AC` / `RE` / `TLE` / `MLE` / `OLE`).

- **rootless** — no root, no setuid helper, no external sandbox binary; only
  the current user and the kernel are involved.
- **low overhead** — single-digit milliseconds per `exec`; no daemon, no
  polling.
- **limits and accounting** — CPU time, wall clock, memory, output and process
  count are all enforced and measured; `None` means unlimited.
- **latest kernels only** (≥ 6.8): user namespaces, delegated cgroup v2,
  Landlock and seccomp are always on; no compatibility fallbacks.

The API section below is the complete surface, in one page.

## Requirements

- Linux ≥ 6.8, x86_64.
- systemd with the unified cgroup v2 hierarchy, and a cgroup subtree delegated
  to your user.
- Unprivileged user namespaces: `user.max_user_namespaces > 0`, and on Ubuntu
  ≥ 23.10 also `kernel.apparmor_restrict_unprivileged_userns = 0`.

`river.doctor()` checks every requirement, reports the Landlock ABI as an
informational item, and prints the exact fix for whatever fails:

```python
import river
print(river.doctor())
```

## Install

Linux x86_64, Python ≥ 3.12. The PyPI distribution is `river-sandbox`, the
import name stays `river`:

```sh
pip install river-sandbox
```

Build with Docker:

```sh
git clone https://github.com/algoux/river.git
cd river
docker run --rm -v "$(pwd):/io" ghcr.io/pyo3/maturin:latest \
    build --release --locked -i python3.12 -o "$(pwd)/target/wheels"
pip install target/wheels/river_sandbox-*.whl
```

## Preparing a rootfs

The rootfs is a directory holding a complete user space, typically exported
from a container image. Unpack it **as the user that will run river**: the
sandbox maps your uid to root inside.

```sh
mkdir -p /rootfs/python
docker create --name py python:3.12-slim
docker export py | tar -xp --no-same-owner -C /rootfs/python
docker rm py
printf '{"envs":{"PATH":"/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin","HOME":"/work"}}' > /rootfs/python/meta.json
```

`meta.json` provides the environment variables every `exec` uses when its
`envs` argument is not given — `PATH` is what makes `executable="python"`
searchable inside the sandbox. Any other image works the same way; river
always creates any missing mount points (`proc`, `sys`, `dev/pts`, `tmp`,
`work`, ...) and never touches existing files.

## Running: the delegated cgroup

river needs a cgroup v2 subtree delegated to your user for limits, metrics and
the wall-clock kill; it refuses to run without one. Start the program inside a
delegated scope — the interpreter itself or whatever wraps it:

```sh
systemd-run --user --scope -p Delegate=yes -- python app.py
```

Wrappers that stay alive (`uv run`, `make`, a shell, ...) are fine: river moves
every process of the cgroup into `<cgroup>/river` before enabling the
controllers, so only a process of another user can block it — `river.doctor()`
reports exactly that when it happens.

## API

The complete API:

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

`ExecResult` also carries `stdout` / `stderr` (`bytes | None`, `None` when a
`*_file` was given), `files` (the `copy_out` entries whose value was `None`)
and `error` (the human-readable reason behind any non-`AC` verdict).

Verdicts: `AC` — exited 0; `RE` — nonzero exit or killed by a signal (`signal`
names it); `TLE` — the wall clock or the CPU budget ran out; `MLE` — the
cgroup OOM-killed the tree; `OLE` — output past the cap. Ties resolve as
`OLE` > `MLE` > `TLE` > `AC`/`RE`.

Every end state inside the sandbox lands in the `ExecResult`; only setup
failures raise — `ExecSetupError` (with the failing step, e.g.
`child.mount.proc`), `RootfsError`, and `CopyOutError`, whose `.result` holds
the finished run. All of them derive from `river.RiverError`, as do
`KernelTooOldError`, `UserNamespaceDeniedError` and `CgroupNotDelegatedError`
(what `doctor()` raises on its first failed check).

Two environment variables exist for debugging, not configuration:
`RIVER_LOG=debug` traces every parent and child step on stderr;
`RIVER_HARDENING=off` disables only seccomp and Landlock (namespaces, the
read-only rootfs and the capability drop stay), for telling "the program is
broken" from "the hardening layers caught it".

Inside the sandbox: the program is pid 1 of a fresh pid namespace (its death
kills the whole tree), `/work` is the only host-backed writable directory
(`copy_in`/`copy_out`/`*_file` keys must resolve below it), the rootfs is
read-only, `/proc` and `/sys` are fresh instances, the network is a lone `lo`,
and seccomp answers `EPERM` to every syscall outside an explicit allowlist
(about 250 on x86_64, listed in `src/exec/seccomp.rs`; `clone` only without a
namespace flag, `socket` only for `AF_UNIX`/`AF_INET`/`AF_INET6`) while
Landlock blocks writes outside the writable mounts.

## Development

Linux only. Build and test as the unprivileged user that will run river, with
the process inside a delegated cgroup:

```sh
uv sync --extra test && uv run maturin develop
systemd-run --user --scope -p Delegate=yes -- .venv/bin/python -c "import river; print(river.doctor())"
systemd-run --user --scope -p Delegate=yes --setenv=RIVER_TEST_ROOTFS=<rootfs> -- .venv/bin/python -m pytest -x
```

Formatting and import order are ruff's job: `uv run ruff check . && uv run ruff format .`.
