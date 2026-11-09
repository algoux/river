import os
import types
from collections.abc import Mapping, Sequence
from typing import Literal, Self

__all__ = ["Sandbox", "Status"]

type _StrOrPath = str | os.PathLike[str]
type _Verdict = Literal["AC", "TLE", "MLE", "OLE", "RE", "SE"]

class Status:
    cpu_time_used_ms: int
    wall_time_used_ms: int
    memory_used_bytes: int
    status: _Verdict
    signal: int
    exit_code: int

class Sandbox:
    def __init__(
        self,
        rootfs: _StrOrPath | None = None,
        runtimes: Sequence[_StrOrPath] | None = None,
    ) -> None: ...
    def __enter__(self) -> Self: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: types.TracebackType | None,
    ) -> bool: ...
    def exec(
        self,
        executable: _StrOrPath,
        args: Sequence[str] = [],
        cwd: str | None = None,
        envs: Mapping[str, str] | None = None,
        cpu_time_limit_ms: int | None = None,
        wall_time_limit_ms: int | None = None,
        memory_limit_bytes: int | None = None,
        stdin_file: _StrOrPath | None = None,
        copy_in: Mapping[_StrOrPath, _StrOrPath] | None = None,
        copy_out: Mapping[_StrOrPath, _StrOrPath] | None = None,
        copy_out_limit_bytes: int | None = None,
        stdout_limit_bytes: int | None = None,
        stderr_limit_bytes: int | None = None,
        stdout_file: _StrOrPath | None = None,
        stderr_file: _StrOrPath | None = None,
    ) -> Status: ...
