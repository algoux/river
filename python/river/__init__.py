"""river: rootless Linux sandbox for untrusted programs.

See the README for a complete API example.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version

from river._river import (
    CgroupNotDelegatedError,
    CopyOutError,
    ExecResult,
    ExecSetupError,
    KernelTooOldError,
    River,
    RiverError,
    RootfsError,
    UserNamespaceDeniedError,
    run_doctor_checks,
)

try:
    __version__ = version("river")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0.0.0"


@dataclass(frozen=True)
class Check:
    """One preflight check.

    `remediation` is the fix for a failed check and `None` for a passed one.
    """

    name: str
    ok: bool
    detail: str
    remediation: str | None


@dataclass(frozen=True)
class DoctorReport:
    """Result of `doctor()`: the list of `Check`s; `str(report)` is a table."""

    checks: list[Check]

    @property
    def ok(self) -> bool:
        return all(check.ok for check in self.checks)

    def __str__(self) -> str:
        width = max(len(check.name) for check in self.checks)
        lines = [f"river {__version__}: doctor report"]
        for check in self.checks:
            state = "ok" if check.ok else "FAIL"
            lines.append(f"  [{state:<4}] {check.name:<{width}}  {check.detail}")
            if check.remediation is not None:
                lines.append(f"  {'':<6} {'':<{width}}  fix: {check.remediation}")
        if not self.ok:
            lines.append("river raises the exception of the first failed check.")
        return "\n".join(lines)


def doctor(raise_on_fail: bool = True) -> DoctorReport:
    """Run every preflight check.

    With `raise_on_fail` (the default) the first failed check raises the same
    exception `River()` would raise; otherwise every check is reported.
    """
    checks = [Check(*row) for row in run_doctor_checks(raise_on_fail)]
    return DoctorReport(checks=checks)


__all__ = [
    "__version__",
    "Check",
    "DoctorReport",
    "doctor",
    "River",
    "ExecResult",
    "RiverError",
    "KernelTooOldError",
    "UserNamespaceDeniedError",
    "CgroupNotDelegatedError",
    "RootfsError",
    "ExecSetupError",
    "CopyOutError",
]
