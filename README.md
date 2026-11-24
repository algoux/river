# river

river is a Python library that runs arbitrary programs inside a rootless Linux
sandbox built around a caller-supplied rootfs, and reports judge-grade resource
usage and verdicts (`AC` / `RE` / `TLE` / `MLE` / `OLE`).

- **rootless** — like podman: no root, no setuid helper, no external binary
  (bwrap/nsjail/crun); only the current user and the kernel.
- **low overhead** — like nsjail: single-digit milliseconds per `exec`; no
  daemon, no polling.
- **limits and accounting** — like go-judge: CPU time, wall clock, memory,
  output, process count, all enforced and measured; `None` means unlimited.
- **latest kernels only** (≥ 6.8): user namespaces, delegated cgroup v2,
  Landlock and seccomp are always on; no compatibility fallbacks.

[docs/example.py](docs/example.py) is the complete API in one file.

**Status: v0.1.0 released.** Wheels live on the
[releases page](https://github.com/algoux/river/releases), not on PyPI — the
`river` name there belongs to the (unrelated) online machine learning
library.

## Requirements

- Linux ≥ 6.8, x86_64 (the seccomp denylist is x86_64-specific for now).
- systemd with the unified cgroup v2 hierarchy, and a cgroup subtree delegated
  to your user.
- Unprivileged user namespaces: `user.max_user_namespaces > 0`, and on Ubuntu
  ≥ 23.10 also `kernel.apparmor_restrict_unprivileged_userns = 0`.

`river.doctor()` checks every requirement, reports the Landlock ABI as an
informational item, and prints the exact fix for whatever fails — run it first:

```python
import river
print(river.doctor())
```

## Install

Linux x86_64, Python ≥ 3.12. Install the released wheel straight from GitHub:

```sh
pip install https://github.com/algoux/river/releases/download/v0.1.0/river-0.1.0-cp312-abi3-manylinux2014_x86_64.manylinux_2_17_x86_64.whl
```

To build the same wheel from source, one docker command suffices — no Rust
toolchain needed, because the
[pyo3/maturin image](https://www.maturin.rs/distribution) is a manylinux2014
(glibc 2.17) build environment:

```sh
git clone https://github.com/algoux/river.git
cd river
docker run --rm -v "$(pwd):/io" ghcr.io/pyo3/maturin:latest \
    build --release --locked -i python3.12 -o "$(pwd)/target/wheels"
pip install target/wheels/river-*.whl
```

`-i python3.12` pins the interpreter so the abi3 wheel carries the `cp312`
tag matching `requires-python >= 3.12`: the result,
`river-<version>-cp312-abi3-manylinux_2_17_x86_64.whl`, installs on any
CPython ≥ 3.12. With a Rust toolchain you can instead build straight into the
active virtualenv (`pip install maturin && maturin develop`). Tagged pushes
attach the same wheel to the GitHub release via
[.github/workflows/release.yml](.github/workflows/release.yml).

aarch64 wheels are not built: parts of the seccomp denylist (`nfsservctl`,
`sysfs`, `iopl`, ...) are x86_64-only syscall numbers and the x32 ABI guard is
x86_64-specific — porting means trimming the list per architecture first.

## Preparing a rootfs

The rootfs is a directory holding a complete user space, typically exported
from a container image. Unpack it **as the user that will run river**: the
sandbox maps your uid to root inside, and files owned by anyone else show up
broken.

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
the wall-clock kill; it refuses to run without one (`CgroupNotDelegatedError`
rather than silently losing every limit). Start the interpreter itself inside
a delegated scope:

```sh
systemd-run --user --scope -p Delegate=yes -- python app.py
```

The interpreter must be the scope's only process: wrappers that stay alive
(`uv run`, `make`, ...) leave a second process in the cgroup and river cannot
enable the controllers there — `river.doctor()` reports exactly that when it
happens.

## API

[docs/example.py](docs/example.py), complete:

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
and seccomp plus Landlock block namespace creation, unusual syscall families
and writes outside the writable mounts.

## Development

Linux only. Build and test as the unprivileged user that will run river, with
the process inside a delegated cgroup:

```sh
uv sync --extra test && uv run maturin develop
systemd-run --user --scope -p Delegate=yes -- .venv/bin/python -c "import river; print(river.doctor())"
systemd-run --user --scope -p Delegate=yes --setenv=RIVER_TEST_ROOTFS=<rootfs> -- .venv/bin/python -m pytest -x
```

The rootfs for the functional tests is a docker-exported `python:3.12-slim`
tree (recipe above). The design document and the PR plan that drove the
implementation were removed once 0.1.0 shipped — both stay recoverable from
git history, up to tag `v0.1.0`. Machine-specific notes never enter the
repository.
