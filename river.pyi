"""Static type stubs for the `river` sandbox module."""

import os
from collections.abc import Buffer, Mapping, Sequence
from typing import Literal, TypeAlias

__all__ = ["Sandbox", "Status"]

_StrOrPath: TypeAlias = str | os.PathLike[str]
_CopyInSource: TypeAlias = Buffer | _StrOrPath
_Verdict: TypeAlias = Literal["AC", "TLE", "MLE", "OLE", "RE", "SE"]

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

    Platform support: **Windows only** for now. On other platforms `run()`
    raises `NotImplementedError` (the Linux/macOS backends are not implemented
    yet). `rootfs` is not supported on Windows either (processes always
    resolve system DLLs from the real `System32`) — use `runtimes` there
    instead.
    """

    def __init__(
        self,
        rootfs: _StrOrPath | None = None,
        runtimes: Sequence[_StrOrPath] | None = None,
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
