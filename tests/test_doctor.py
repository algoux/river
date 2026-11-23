"""river.doctor() and the preflight checks (marker: doctor)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

import river
from river import (
    CgroupNotDelegatedError,
    Check,
    CopyOutError,
    DoctorReport,
    ExecResult,
    ExecSetupError,
    KernelTooOldError,
    River,
    RiverError,
    RootfsError,
    UserNamespaceDeniedError,
)

pytestmark = pytest.mark.doctor

EXPECTED_CHECKS = {
    "platform",
    "kernel",
    "userns.max",
    "userns.apparmor",
    "userns.probe",
    "cgroup",
    "workdir",
    "landlock_abi",
}
CGROUP_FIX = "systemd-run --user --scope -p Delegate=yes"

MOUNT_DIRS = ["proc", "sys", "dev/pts", "dev/shm", "dev/mqueue", "tmp", "work"]
MOUNT_FILES = ["dev/null", "dev/zero", "dev/full", "dev/random", "dev/urandom", "dev/ptmx"]


def _cgroup_base() -> Path:
    for line in Path("/proc/self/cgroup").read_text().splitlines():
        if line.startswith("0::"):
            base = Path("/sys/fs/cgroup") / line[3:].lstrip("/")
            # doctor() parks this process in <base>/river (design.md §7 step 4).
            return base.parent if base.name == "river" else base
    raise RuntimeError("no unified cgroup v2 hierarchy in /proc/self/cgroup")


def _delegated() -> bool:
    """Cheap mirror of the preflight: controllers visible and the cgroup writable by us."""
    try:
        base = _cgroup_base()
        controllers = (base / "cgroup.controllers").read_text().split()
        return {"cpu", "memory", "pids"} <= set(controllers) and os.access(base, os.W_OK | os.X_OK)
    except (OSError, RuntimeError):
        return False


# ----------------------------------------------------------------- objects


def test_exception_hierarchy():
    assert issubclass(RiverError, RuntimeError)
    for exc in (
        KernelTooOldError,
        UserNamespaceDeniedError,
        CgroupNotDelegatedError,
        RootfsError,
        ExecSetupError,
        CopyOutError,
    ):
        assert issubclass(exc, RiverError)
        assert exc.__module__ == "river"
    assert set(river.__all__) == {
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
    }
    for name in river.__all__:
        assert getattr(river, name, None) is not None, name


def test_check_is_a_frozen_value():
    check = Check("x", True, "detail", None)
    assert check == Check("x", True, "detail", None)
    with pytest.raises(AttributeError):
        check.ok = False  # type: ignore[misc]


def test_exec_result_is_an_immutable_value_object():
    result = ExecResult("AC", 0, None, 1, 2, 3, stdout=b"hi")
    assert result.status == "AC"
    assert result.exit_code == 0
    assert result.signal is None
    assert result.cpu_time_used_ms == 1
    assert result.wall_time_used_ms == 2
    assert result.memory_used_bytes == 3
    assert result.stdout == b"hi"
    assert result.stderr is None
    assert result.files == {}
    assert result.error is None
    with pytest.raises(AttributeError):
        result.status = "RE"  # type: ignore[misc]
    assert "status='AC'" in repr(result) and "stdout=2 bytes" in repr(result)


# ------------------------------------------------------------------ doctor


def test_doctor_report_structure():
    report = river.doctor(raise_on_fail=False)
    assert isinstance(report, DoctorReport)
    names = [check.name for check in report.checks]
    assert EXPECTED_CHECKS == set(names)
    assert len(names) == len(set(names))
    for check in report.checks:
        assert isinstance(check, Check)
        assert isinstance(check.ok, bool)
        assert check.detail
        assert (check.remediation is not None) == (not check.ok)
    assert report.ok == all(check.ok for check in report.checks)
    text = str(report)
    assert "doctor report" in text
    for check in report.checks:
        assert check.name in text
        assert check.detail in text
        if check.remediation is not None:
            assert f"fix: {check.remediation}" in text


@pytest.mark.skipif(not _delegated(), reason="not in a delegated cgroup; run under systemd-run --user --scope -p Delegate=yes")
class TestDoctorInDelegatedEnvironment:
    def test_all_green_by_default(self):
        report = river.doctor()
        assert report.ok, str(report)
        assert {check.name for check in report.checks} == EXPECTED_CHECKS

    def test_raise_on_fail_false_reports_the_same(self):
        assert river.doctor(raise_on_fail=False) == river.doctor(raise_on_fail=True)

    def test_cgroup_singleton_is_established(self):
        river.doctor()
        base = _cgroup_base()
        assert str(os.getpid()) in (base / "river" / "cgroup.procs").read_text().split()
        enabled = (base / "cgroup.subtree_control").read_text().split()
        assert {"cpu", "memory", "pids"} <= set(enabled)

    def test_raises_in_a_cgroup_without_controllers(self):
        # A sibling scope is not a reliable "not delegated" environment (systemd keeps
        # the controllers it enabled for earlier Delegate=yes units). A fresh child of
        # <base>/river has no controllers enabled above it, which is what step 3 of the
        # preflight detects.
        nested = _cgroup_base() / "river" / "test-nondelegated"
        nested.mkdir()
        try:
            code = (
                f"import os; open({str(nested / 'cgroup.procs')!r}, 'w').write(str(os.getpid())); "
                "import river; river.doctor()"
            )
            proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
        finally:
            nested.rmdir()
        assert proc.returncode != 0, proc.stdout + proc.stderr
        assert "CgroupNotDelegatedError" in proc.stderr
        assert CGROUP_FIX in proc.stderr


@pytest.mark.skipif(_delegated(), reason="already in a delegated cgroup")
class TestDoctorInNonDelegatedEnvironment:
    def test_raises_with_the_fix_command(self):
        with pytest.raises(CgroupNotDelegatedError) as info:
            river.doctor()
        assert CGROUP_FIX in str(info.value)
        report = river.doctor(raise_on_fail=False)
        (cgroup,) = [check for check in report.checks if check.name == "cgroup"]
        assert not cgroup.ok
        assert cgroup.remediation is not None and CGROUP_FIX in cgroup.remediation
        assert not report.ok

    def test_river_init_raises_too(self, tmp_path):
        with pytest.raises(CgroupNotDelegatedError):
            River(tmp_path)


# ------------------------------------------------------------------- River


@pytest.mark.skipif(not _delegated(), reason="not in a delegated cgroup; run under systemd-run --user --scope -p Delegate=yes")
class TestRiverInit:
    def test_creates_missing_mount_points_only(self, tmp_path):
        (tmp_path / "proc").mkdir()
        (tmp_path / "dev").mkdir()
        (tmp_path / "dev/null").write_text("keep")
        (tmp_path / "keep.txt").write_text("keep")

        with River(tmp_path) as r:
            assert r.rootfs == str(tmp_path.resolve())
        assert repr(r) == f"River({str(tmp_path.resolve())!r})"

        for rel in MOUNT_DIRS:
            assert (tmp_path / rel).is_dir(), rel
        for rel in MOUNT_FILES:
            assert (tmp_path / rel).is_file(), rel
        assert (tmp_path / "dev/null").read_text() == "keep"
        assert (tmp_path / "keep.txt").read_text() == "keep"
        assert sorted(p.name for p in tmp_path.iterdir()) == sorted(
            ["dev", "keep.txt", "proc", "sys", "tmp", "work"]
        )

    def test_missing_or_non_directory_rootfs(self, tmp_path):
        with pytest.raises(RootfsError, match="No such file"):
            River(tmp_path / "nope")
        (tmp_path / "file").write_text("")
        with pytest.raises(RootfsError, match="not a directory"):
            River(tmp_path / "file")

    def test_meta_json(self, tmp_path):
        (tmp_path / "meta.json").write_text('{"envs": {"PATH": "/bin"}, "future_key": 1}')
        River(tmp_path)  # unknown keys are ignored
        (tmp_path / "meta.json").write_text('{"future_key": 1}')
        River(tmp_path)  # envs may be absent
        for bad in ('{"envs": {"PATH": 1}}', "{not json", "[]"):
            (tmp_path / "meta.json").write_text(bad)
            with pytest.raises(RootfsError, match="meta.json"):
                River(tmp_path)

    def test_real_rootfs(self):
        rootfs = os.environ.get("RIVER_TEST_ROOTFS")
        if not rootfs:
            pytest.skip("RIVER_TEST_ROOTFS is not set")
        with River(rootfs) as r:
            assert r.rootfs == str(Path(rootfs).resolve())
