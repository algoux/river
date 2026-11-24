"""Shared fixtures and helpers for the river test suite."""

from __future__ import annotations

import os
from pathlib import Path

import pytest


def cgroup_base() -> Path:
    """This process's cgroup, accounting for doctor()'s parking step."""
    for line in Path("/proc/self/cgroup").read_text().splitlines():
        if line.startswith("0::"):
            base = Path("/sys/fs/cgroup") / line[3:].lstrip("/")
            # doctor()/River() park the process in <base>/river.
            return base.parent if base.name == "river" else base
    raise RuntimeError("no unified cgroup v2 hierarchy in /proc/self/cgroup")


def delegated() -> bool:
    """Cheap mirror of the cgroup preflight: controllers visible and writable."""
    try:
        base = cgroup_base()
        controllers = (base / "cgroup.controllers").read_text().split()
        return {"cpu", "memory", "pids"} <= set(controllers) and os.access(
            base, os.W_OK | os.X_OK
        )
    except (OSError, RuntimeError):
        return False


@pytest.fixture(scope="session")
def rootfs() -> str:
    value = os.environ.get("RIVER_TEST_ROOTFS")
    if not value:
        pytest.skip("RIVER_TEST_ROOTFS is not set")
    return value


@pytest.fixture(scope="session")
def river_(rootfs) -> "river.River":
    import river

    return river.River(rootfs)
