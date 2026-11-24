"""Type stubs for the native module `river._river` (implementation: src/lib.rs)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from os import PathLike
from types import TracebackType

__all__ = [
    "River",
    "ExecResult",
    "RiverError",
    "KernelTooOldError",
    "UserNamespaceDeniedError",
    "CgroupNotDelegatedError",
    "RootfsError",
    "ExecSetupError",
    "CopyOutError",
    "run_doctor_checks",
]

_StrOrPath = str | PathLike[str]

class RiverError(RuntimeError): ...
class KernelTooOldError(RiverError): ...
class UserNamespaceDeniedError(RiverError): ...
class CgroupNotDelegatedError(RiverError): ...
class RootfsError(RiverError): ...
class ExecSetupError(RiverError): ...

class CopyOutError(RiverError):
    """Raised when a copy_out entry cannot be retrieved.

    `result` is the `ExecResult` of the run that finished before copy_out
    failed (its `files` is empty); river always sets it.
    """

    result: ExecResult

class ExecResult:
    status: str
    exit_code: int | None
    signal: int | None
    cpu_time_used_ms: int
    wall_time_used_ms: int
    memory_used_bytes: int
    stdout: bytes | None
    stderr: bytes | None
    files: dict[str, bytes]
    error: str | None

    def __init__(
        self,
        status: str,
        exit_code: int | None,
        signal: int | None,
        cpu_time_used_ms: int,
        wall_time_used_ms: int,
        memory_used_bytes: int,
        *,
        stdout: bytes | None = ...,
        stderr: bytes | None = ...,
        files: dict[str, bytes] | None = ...,
        error: str | None = ...,
    ) -> None: ...
    def __repr__(self) -> str: ...

class River:
    rootfs: str

    def __init__(self, rootfs: _StrOrPath) -> None: ...
    def __enter__(self) -> River: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool: ...
    def exec(
        self,
        executable: _StrOrPath,
        args: Sequence[str] = ...,
        *,
        cwd: str = ...,
        envs: Mapping[str, str] | None = ...,
        cpu_time_limit_ms: int | None = ...,
        wall_time_limit_ms: int | None = ...,
        memory_limit_bytes: int | None = ...,
        stdout_limit_bytes: int | None = ...,
        stderr_limit_bytes: int | None = ...,
        copy_in: Mapping[str, bytes | str | _StrOrPath] | None = ...,
        copy_out: Mapping[str, None | str | _StrOrPath] | None = ...,
        copy_out_limit_bytes: int | None = ...,
        stdin_file: str | None = ...,
        stdin: bytes | None = ...,
        stdout_file: str | None = ...,
        stderr_file: str | None = ...,
        proc_limit: int | None = ...,
        open_file_limit: int | None = ...,
        stack_limit_bytes: int | None = ...,
        address_space_limit_bytes: int | None = ...,
    ) -> ExecResult: ...
    def __repr__(self) -> str: ...

def run_doctor_checks(raise_on_fail: bool) -> list[tuple[str, bool, str, str | None]]: ...

# Test-suite only: the syscalls the seccomp allowlist lets through.
def _seccomp_table() -> list[tuple[str, int]]: ...
