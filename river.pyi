"""Static type stubs for the `river` sandbox module."""

import os
from collections.abc import Buffer, Mapping, Sequence
from typing import Literal, TypeAlias

__all__ = ["Sandbox", "Status", "capabilities", "doctor"]

_StrOrPath: TypeAlias = str | os.PathLike[str]
_CopyInSource: TypeAlias = Buffer | _StrOrPath
_Verdict: TypeAlias = Literal["AC", "TLE", "MLE", "OLE", "RE", "SE"]

_Capabilities: TypeAlias = dict[str, object]  # see capabilities() below

_ExcType: TypeAlias = type[BaseException] | None
_ExcValue: TypeAlias = BaseException | None
_Traceback: TypeAlias = object | None


class Status:
    """Result of `Sandbox.run`.

    Units are part of the API contract and mirrored in field names:
    `time_used_ms` / `wall_time_used_ms` are milliseconds (CPU / wall clock),
    `memory_used_kb` is kilobytes (peak committed memory of the process tree).
    """

    time_used_ms: int
    wall_time_used_ms: int
    memory_used_kb: int
    status: _Verdict
    signal: int  # 0 normally, 9 when killed by the sandbox (TLE/MLE/OLE)
    exit_code: int  # raw exit code; NTSTATUS on abnormal Windows termination
    oom_killed: bool  # Linux only: kernel OOM killer reaped a sandbox task
    stdout: bytes  # truncated to stdout_limit_kb
    stderr: bytes  # truncated to stderr_limit_kb
    stdout_truncated: bool
    stderr_truncated: bool


class Sandbox:
    """Sandbox for running untrusted executables with resource limits.

    Filesystem model:
      - a fresh private writable working directory per `run`;
      - each `runtimes` entry exposed read-only (+execute);
      - `copy_in` files provisioned into the working directory (read-only
        for the program by default);
      - everything else on the host is invisible to the sandboxed process.

    Internal safety ceilings (mechanism guarantees that stay in place when
    a run passes `None` limits) default to a 24h wall clock and 64 live
    processes; `max_wall_secs` / `max_processes` may tighten (never
    disable) them per Sandbox. Check `river.capabilities()` for the
    platform capability matrix instead of probing with try/except.

    Platform support: **Windows and Linux** are implemented (macOS is not
    yet). `rootfs` is not supported on Windows (processes always resolve
    system DLLs from the real `System32`) nor on Linux — use
    `runtimes` there instead.

    Linux specifics: the process runs as `nobody` inside mount/pid/net/ipc/
    uts/cgroup namespaces under a seccomp allowlist with `no_new_privs`;
    network access is always denied (empty network namespace); `executable`
    is a host path — if it is not already visible through `runtimes`/the
    system dirs it is bind-mounted read-only at `/cwd/.river/<name>`.
    Construction fails closed when cgroups v2, `memory.peak`,
    `memory.swap.max` or seccomp are unavailable (see `doctor()`); the
    backend must run as root.
    """

    def __init__(
        self,
        rootfs: _StrOrPath | None = None,
        runtimes: Sequence[_StrOrPath] | None = None,
        max_wall_secs: int | None = None,
        max_processes: int | None = None,
    ) -> None: ...

    def __enter__(self) -> Sandbox: ...

    def __exit__(
        self,
        exc_type: _ExcType,
        exc_value: _ExcValue,
        traceback: _Traceback,
    ) -> bool: ...

    def run(
        self,
        executable: _StrOrPath,
        args: Sequence[str] = [],
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        time_limit_ms: int | None = None,
        wall_time_limit_ms: int | None = None,
        memory_limit_kb: int | None = None,
        stdin: Buffer | None = None,
        stdin_file: _StrOrPath | None = None,
        copy_in: Mapping[str, _CopyInSource] | None = None,
        stdout_limit_kb: int | None = None,
        stderr_limit_kb: int | None = None,
        stdout_file: _StrOrPath | None = None,
        stderr_file: _StrOrPath | None = None,
    ) -> Status: ...


def capabilities() -> _Capabilities:
    """Capability matrix of the running backend (frozen keys):

    - `platform`: `"windows" | "linux" | "macos"`
    - `rootfs`: whether `Sandbox(rootfs=...)` is supported
    - `default_max_processes`: default live-process cap per run
    - `internal_wall_limit_secs`: safety wall-clock ceiling for
      caller-unlimited runs

    Network access is denied unconditionally on every platform, and a
    `Sandbox` may always be used from several threads concurrently (it is
    frozen; every run keeps its state in locals) — neither is a capability
    key.
    """
    ...


def doctor() -> dict[str, object]:
    """Deployment self-check (kernel / cgroup / seccomp / filesystem facts).

    Returns a dict with at least:

    - `platform`: `"windows" | "linux" | "macos"`
    - `ok`: whether every required mechanism is available
    - `errors`: list of blocking problems (empty when `ok`)

    Linux also reports `kernel`, `cgroup_root`, `cgroups_v2`, `controllers`,
    `memory_peak`, `memory_swap_max`, `cgroup_kill`, `seccomp`,
    `seccomp_actions` and `workdir_root`. `Sandbox(...)` runs the same
    checks and fails closed when `ok` is false.
    """
    ...
