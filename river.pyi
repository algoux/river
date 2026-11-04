"""Static type stubs for the `river` sandbox module."""

import os
import types
from collections.abc import Buffer, Mapping, Sequence
from typing import Literal, Self, TypeAlias

__all__ = ["Sandbox", "Status", "capabilities", "doctor"]

_StrOrPath: TypeAlias = str | os.PathLike[str]
_CopyInSource: TypeAlias = Buffer | _StrOrPath
_Verdict: TypeAlias = Literal["AC", "TLE", "MLE", "OLE", "RE", "SE"]

_Capabilities: TypeAlias = dict[str, object]  # see capabilities() below


class Status:
    """Result of `Sandbox.run`.

    Units are part of the API contract and mirrored in field names:
    `time_used_ms` / `wall_time_used_ms` are milliseconds (CPU / wall clock),
    `memory_used_kb` is kilobytes (peak committed memory of the process tree).

    `SE` has two shapes: a residual-descendant kill reports `signal=9` with
    the process' own exit code, while an infrastructure failure (spawn or
    cleanup error) reports `signal=0` and `exit_code=0xFFFFFFFF`.
    """

    time_used_ms: int
    wall_time_used_ms: int
    memory_used_kb: int
    status: _Verdict
    signal: int  # 0 normally, 9 when killed by the sandbox (TLE/MLE/OLE/SE)
    exit_code: int  # unsigned raw exit code; 0xFFFFFFFF = no exit code (infra SE)
    oom_killed: bool  # Linux only: kernel OOM killer reaped a sandbox task
    stdout: bytes  # truncated to stdout_limit_kb (or the internal capture ceiling)
    stderr: bytes  # truncated to stderr_limit_kb (or the internal capture ceiling)
    stdout_truncated: bool
    stderr_truncated: bool
    stdout_file_truncated: bool  # stdout_file archive stopped at the sink ceiling
    stderr_file_truncated: bool  # stderr_file archive stopped at the sink ceiling


class Sandbox:
    """Sandbox for running untrusted executables with resource limits.

    Filesystem model:
      - a fresh private writable working directory per `run`;
      - each `runtimes` entry exposed read-only (+execute);
      - `copy_in` files provisioned into the working directory (read-only
        for the program by default);
      - everything else on the host is invisible to the sandboxed process.

    Internal safety ceilings (mechanism guarantees that stay in place when
    a run passes `None` limits) default to a 24h wall clock, 64 live
    processes, a 64 MiB per-channel memory-capture ceiling and a 1 GiB
    per-channel file-sink ceiling; `max_wall_secs` / `max_processes` may
    tighten (never disable) the first two per Sandbox — larger values are
    clamped to the defaults and `0` raises `ValueError`. Check
    `river.capabilities()` for the platform capability matrix instead of
    probing with try/except.

    Platform support: **Windows and Linux** are implemented (macOS is not
    yet). `rootfs` is supported on Linux only: it replaces the sandbox root
    with a caller-supplied read-only root tree (see below). It is not
    supported on Windows (processes always resolve system DLLs from the real
    `System32`) or macOS.

    Linux specifics: the process runs as `nobody` inside mount/pid/net/ipc/
    uts/cgroup namespaces under a seccomp allowlist with `no_new_privs`;
    network access is always denied (empty network namespace). Without
    `rootfs`, `executable` is a host path — if it is not already visible
    through `runtimes`/the system dirs it is bind-mounted read-only at
    `/cwd/.river/<name>`; with `rootfs`, `executable` is a path *inside the
    rootfs* and the host system dirs are not merged in (the rootfs must be
    self-contained; it is mounted read-only via overlayfs — a directory
    tree, or a squashfs image file bound to a loop device — with the host
    tree never written and `runtimes` layered on top; the only writable
    place stays `/cwd`).
    `copy_in` values accept a host directory (provisioned recursively);
    `copy_out` maps sandbox-relative product paths to host destinations —
    collected after the run, never following symlinks, and `OLE` when the
    collected bytes pass `copy_out_limit_kb`.
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

    def __enter__(self) -> Self: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: types.TracebackType | None,
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
        copy_out: Mapping[str, _StrOrPath] | None = None,
        copy_out_limit_kb: int | None = None,
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


def doctor() -> dict[str, object]:
    """Deployment self-check (kernel / cgroup / seccomp / filesystem facts).

    Returns a dict with at least:

    - `platform`: `"windows" | "linux" | "macos"`
    - `ok`: whether every required mechanism is available
    - `errors`: list of blocking problems (empty when `ok`)
    - `warnings`: list of non-blocking caveats (may be non-empty when `ok`)

    Linux also reports `kernel`, `cgroup_root`, `cgroups_v2`, `controllers`,
    `memory_peak`, `memory_swap_max`, `cgroup_kill`, `seccomp`,
    `seccomp_actions`, `userns_allowed`, `apparmor_userns_restrict` and
    `workdir_root`. Windows reports `app_container`, `job_object` and
    `workdir_root`. `Sandbox(...)` runs the same checks and fails closed when
    `ok` is false.
    """
