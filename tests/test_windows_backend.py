"""End-to-end tests for the Windows backend.

Run with::

    uv run maturin develop
    uv run pytest tests/test_windows_backend.py
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

import river

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows backend tests")

COMSPEC = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "cmd.exe"
BUSY_LOOP = ["/c", "for /L %i in (1,1,400000000) do @rem x"]


def acl(path: Path) -> str:
    """The `icacls` view of `path`, used to prove grants are revoked."""
    result = subprocess.run(
        ["icacls", str(path)], check=False, capture_output=True, text=True
    )
    if result.returncode != 0:
        pytest.skip(f"icacls failed: {result.stderr.strip()}")
    return result.stdout


def runtime_dir(tmp_path: Path) -> tuple[Path, Path]:
    directory = tmp_path / "runtime"
    directory.mkdir()
    target = directory / "data.txt"
    target.write_text("original", encoding="utf-8")
    return directory, target


def test_public_surface():
    assert set(river.__all__) == {"Sandbox", "Status"}


def test_rootfs_is_rejected():
    with pytest.raises(ValueError, match="rootfs"):
        river.Sandbox(rootfs=str(Path(os.environ["SystemRoot"])))


def test_exec_with_runtimes_requires_a_session(tmp_path: Path):
    directory, _ = runtime_dir(tmp_path)
    with pytest.raises(RuntimeError, match="AppContainer sandbox is not active"):
        river.Sandbox(runtimes=[str(directory)]).exec(str(COMSPEC), ["/c", "echo", "x"])


def test_profile_lifecycle_is_bound_to_enter_and_exit(tmp_path: Path):
    directory, target = runtime_dir(tmp_path)
    before = acl(directory)
    box = river.Sandbox(runtimes=[str(directory)])

    for _ in range(2):
        with box:
            during = acl(directory)
            assert during != before
            assert "S-1-15-2-" in during
            assert box.workdir is not None
            assert box.exec(str(COMSPEC), ["/c", "type", str(target)]).status == "AC"
        assert acl(directory) == before

    with pytest.raises(RuntimeError, match="AppContainer sandbox is not active"):
        box.exec(str(COMSPEC), ["/c", "echo", "x"])


def test_missing_runtime_fails_at_enter_without_touching_acls(tmp_path: Path):
    directory, _ = runtime_dir(tmp_path)
    before = acl(directory)
    with (
        pytest.raises(OSError, match="does not exist"),
        river.Sandbox(runtimes=[str(directory), str(tmp_path / "missing")]),
    ):
        pass
    assert acl(directory) == before


def test_clean_run_is_ac_and_reports_stats():
    status = river.Sandbox().exec(str(COMSPEC), ["/c", "echo", "hello"])
    assert status.status == "AC"
    assert status.exit_code == 0
    assert status.signal == 0
    assert status.cpu_time_used_ms >= 0
    assert status.wall_time_used_ms >= 0
    assert status.memory_used_bytes > 0


def test_nonzero_exit_is_re():
    status = river.Sandbox().exec(str(COMSPEC), ["/c", "exit", "3"])
    assert status.status == "RE"
    assert status.exit_code == 3
    assert status.signal == 0


def test_wall_time_limit_is_tle():
    status = river.Sandbox().exec(str(COMSPEC), BUSY_LOOP, wall_time_limit_ms=800)
    assert status.status == "TLE"
    assert status.signal == 9
    assert status.wall_time_used_ms >= 700


@pytest.mark.slow
def test_cpu_time_limit_is_tle():
    status = river.Sandbox().exec(
        sys.executable,
        ["-c", "while True: pass"],
        cpu_time_limit_ms=300,
        wall_time_limit_ms=20_000,
    )
    assert status.status == "TLE"
    assert status.signal == 9
    assert status.cpu_time_used_ms >= 300
    # The native job-time limit terminates with one of these two codes.
    assert status.exit_code in {1816, 0xC0000044}


def test_memory_limit_is_mle():
    status = river.Sandbox().exec(
        sys.executable,
        ["-c", "bytearray(200 * 1024 * 1024)"],
        memory_limit_bytes=100 * 1024 * 1024,
    )
    assert status.status == "MLE"
    assert status.signal == 9
    assert status.memory_used_bytes >= 100 * 1024 * 1024


def test_memory_usage_is_measured():
    status = river.Sandbox().exec(sys.executable, ["-c", "bytearray(20 * 1024 * 1024)"])
    assert status.status == "AC"
    assert status.memory_used_bytes >= 20 * 1024 * 1024


def test_cpu_time_is_measured():
    status = river.Sandbox().exec(sys.executable, ["-c", "sum(range(20_000_000))"])
    assert status.status == "AC"
    assert status.cpu_time_used_ms > 0


def test_runtime_directory_is_read_only(tmp_path: Path):
    directory, target = runtime_dir(tmp_path)
    nested = directory / "nested"
    nested.mkdir()
    (nested / "inner.txt").write_text("inner", encoding="utf-8")
    before = acl(directory)

    with river.Sandbox(runtimes=[str(directory)]) as box:
        assert box.exec(str(COMSPEC), ["/c", "type", str(target)]).status == "AC"
        assert (
            box.exec(str(COMSPEC), ["/c", "type", str(nested / "inner.txt")]).status
            == "AC"
        )

        write = box.exec(str(COMSPEC), ["/c", "echo", "hacked", ">", str(target)])
        assert write.status == "RE"
        assert target.read_text(encoding="utf-8") == "original"

        create = box.exec(
            str(COMSPEC),
            ["/c", "echo", "new", ">", str(directory / "new.txt")],
        )
        assert create.status == "RE"
        assert not (directory / "new.txt").exists()

    assert acl(directory) == before


def test_file_runtime_is_scoped(tmp_path: Path):
    directory, target = runtime_dir(tmp_path)
    sibling = directory / "sibling.txt"
    sibling.write_text("sibling", encoding="utf-8")
    before_file = acl(target)
    before_directory = acl(directory)

    with river.Sandbox(runtimes=[str(target)]) as box:
        assert box.exec(str(COMSPEC), ["/c", "type", str(target)]).status == "AC"
        assert box.exec(str(COMSPEC), ["/c", "type", str(sibling)]).status == "RE"
        assert (
            box.exec(str(COMSPEC), ["/c", "echo", "x", ">", str(target)]).status == "RE"
        )

    assert acl(target) == before_file
    assert acl(directory) == before_directory


def test_workdir_relative_cwd_is_writable(tmp_path: Path):
    directory, _ = runtime_dir(tmp_path)
    with river.Sandbox(runtimes=[str(directory)]) as box:
        workdir = Path(box.workdir)
        (workdir / "sub").mkdir()
        status = box.exec(
            str(COMSPEC),
            ["/c", "echo", "scratch", ">", "out.txt"],
            cwd="sub",
        )
        assert status.status == "AC"
        assert (workdir / "sub" / "out.txt").read_text().startswith("scratch")


@pytest.mark.parametrize("cwd", [".", "..", r"C:\Windows", "a:b"])
def test_invalid_cwd_is_rejected(cwd: str):
    with pytest.raises(ValueError, match="cwd"):
        river.Sandbox().exec(str(COMSPEC), ["/c", "echo", "x"], cwd=cwd)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"stdin_file": "input.txt"},
        {"copy_in": {"input.txt": "input.txt"}},
        {"copy_out": {"output.txt": "output.txt"}},
        {"copy_out_limit_bytes": 1},
        {"stdout_limit_bytes": 1},
        {"stderr_limit_bytes": 1},
        {"stdout_file": "stdout.txt"},
        {"stderr_file": "stderr.txt"},
    ],
)
def test_unsupported_options_are_rejected(kwargs: dict):
    with pytest.raises(NotImplementedError):
        river.Sandbox().exec(str(COMSPEC), ["/c", "echo", "x"], **kwargs)


def test_without_runtimes_is_a_plain_process(tmp_path: Path):
    target = tmp_path / "plain.txt"
    status = river.Sandbox().exec(
        str(COMSPEC), ["/c", "echo", "plain", ">", str(target)]
    )
    assert status.status == "AC"
    assert target.read_text(encoding="utf-8").strip() == "plain"
