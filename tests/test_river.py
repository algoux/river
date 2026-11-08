"""End-to-end tests for the `river` sandbox extension.

The suite drives the public API only (`river.Sandbox`) and asserts the
frozen contract: the verdict letters, the units of the `Status` fields and
the filesystem model (`copy_in` / `copy_out`).

Run with:

    uv sync --extra test
    uv run maturin develop
    uv run pytest
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

import river

IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")

if IS_WINDOWS:
    COMSPEC = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "cmd.exe"
else:
    COMSPEC = Path("/bin/sh")


def echo_command(text: str) -> tuple[str, list[str]]:
    """A program that prints `text` on stdout and exits cleanly."""
    if IS_WINDOWS:
        return str(COMSPEC), ["/c", "echo", text]
    return str(COMSPEC), ["-c", f"echo {text}"]


def busy_loop_command() -> tuple[str, list[str]]:
    """A program that never terminates on its own (used by the limit tests).

    The loop count on Windows is deliberately huge: the program has to still
    be running when the limit fires, whatever the host speed is.
    """
    if IS_WINDOWS:
        return str(COMSPEC), ["/c", "for /L %i in (1,1,400000000) do @rem x"]
    return str(COMSPEC), ["-c", "while :; do :; done"]


def noisy_command() -> tuple[str, list[str]]:
    """A program that writes more to stdout than the capture ceiling allows."""
    if IS_WINDOWS:
        return str(COMSPEC), [
            "/c",
            "for /L %i in (1,1,200000) do "
            "@echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ]
    return str(COMSPEC), [
        "-c",
        "i=0; while [ $i -lt 100000 ]; do "
        "echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; i=$((i+1)); done",
    ]


def backend_usable() -> bool:
    """Whether the compiled-in backend can actually run a program here."""
    if IS_WINDOWS:
        return COMSPEC.exists()
    if IS_LINUX:
        # The Linux backend needs root (mount/namespace/cgroup writes) and
        # cgroups v2.
        return os.geteuid() == 0 and Path("/sys/fs/cgroup/cgroup.controllers").exists()
    return False


requires_backend = pytest.mark.skipif(
    not backend_usable(),
    reason="no usable backend on this host "
    "(Windows: cmd.exe missing; Linux: root + cgroups v2 required)",
)


# --- module surface (independent of the backend) ------------------------


def test_public_surface_is_sandbox_and_status():
    assert set(river.__all__) == {"Sandbox", "Status"}
    assert hasattr(river, "Sandbox")
    assert hasattr(river, "Status")


def test_removed_introspection_apis_are_gone():
    """`doctor` / `capabilities` were removed; they must not creep back."""
    assert not hasattr(river, "doctor")
    assert not hasattr(river, "capabilities")


# --- construction --------------------------------------------------------


def test_sandbox_constructs_with_defaults():
    box = river.Sandbox()
    assert repr(box).startswith("Sandbox(")


def test_sandbox_accepts_runtimes():
    box = river.Sandbox(runtimes=[str(Path(sys.executable).parent)])
    assert "runtimes" in repr(box)


def test_sandbox_is_a_context_manager():
    with river.Sandbox() as box:
        assert isinstance(box, river.Sandbox)


@pytest.mark.skipif(not IS_WINDOWS, reason="rootfs is rejected on Windows only")
def test_rootfs_is_rejected_on_windows():
    with pytest.raises(ValueError, match="rootfs"):
        river.Sandbox(rootfs=str(Path(os.environ.get("SystemRoot", r"C:\Windows"))))


# --- running -------------------------------------------------------------


@requires_backend
def test_clean_run_is_ac_and_captures_stdout():
    exe, args = echo_command("hello-river")
    status = river.Sandbox().run(exe, args)
    assert status.status == "AC"
    assert status.exit_code == 0
    assert status.signal == 0
    assert b"hello-river" in status.stdout
    assert status.stderr == b""


@requires_backend
def test_status_fields_carry_the_documented_units():
    exe, args = echo_command("units")
    status = river.Sandbox().run(exe, args)
    assert status.status in {"AC", "TLE", "MLE", "OLE", "RE", "SE"}
    assert status.time_used_ms >= 0
    assert status.wall_time_used_ms >= 0
    assert status.memory_used_kb >= 0
    assert isinstance(status.stdout, bytes)
    assert isinstance(status.stderr, bytes)
    assert status.stdout_truncated is False
    assert status.stderr_truncated is False


@requires_backend
def test_stderr_is_captured_separately():
    if IS_WINDOWS:
        exe, args = str(COMSPEC), ["/c", "echo oops 1>&2"]
    else:
        exe, args = str(COMSPEC), ["-c", "echo oops 1>&2"]
    status = river.Sandbox().run(exe, args)
    assert b"oops" in status.stderr
    assert b"oops" not in status.stdout


@requires_backend
def test_non_zero_exit_is_re():
    if IS_WINDOWS:
        exe, args = str(COMSPEC), ["/c", "exit 3"]
    else:
        exe, args = str(COMSPEC), ["-c", "exit 3"]
    status = river.Sandbox().run(exe, args)
    assert status.status == "RE"
    assert status.exit_code == 3
    assert status.signal == 0


@requires_backend
def test_stdin_reaches_the_program():
    if IS_WINDOWS:
        exe, args = str(COMSPEC), ["/c", "more"]
    else:
        exe, args = str(COMSPEC), ["-c", "cat"]
    status = river.Sandbox().run(exe, args, stdin=b"piped-line\n")
    assert b"piped-line" in status.stdout


@requires_backend
def test_env_reaches_the_program():
    if IS_WINDOWS:
        exe, args = str(COMSPEC), ["/c", "echo %RIVER_TEST_VAR%"]
    else:
        exe, args = str(COMSPEC), ["-c", "echo $RIVER_TEST_VAR"]
    status = river.Sandbox().run(exe, args, env={"RIVER_TEST_VAR": "env-value"})
    assert b"env-value" in status.stdout


# --- filesystem model ----------------------------------------------------


@requires_backend
def test_copy_in_provisions_a_readable_file(tmp_path: Path):
    source = tmp_path / "input.txt"
    source.write_text("copied-content", encoding="utf-8")
    if IS_WINDOWS:
        exe, args = str(COMSPEC), ["/c", "type input.txt"]
    else:
        exe, args = str(COMSPEC), ["-c", "cat input.txt"]
    status = river.Sandbox().run(exe, args, copy_in={"input.txt": str(source)})
    assert b"copied-content" in status.stdout


@requires_backend
def test_copy_out_collects_the_product(tmp_path: Path):
    destination = tmp_path / "product.txt"
    if IS_WINDOWS:
        exe, args = str(COMSPEC), ["/c", "echo produced > product.txt"]
    else:
        exe, args = str(COMSPEC), ["-c", "echo produced > product.txt"]
    status = river.Sandbox().run(exe, args, copy_out={"product.txt": str(destination)})
    assert status.status == "AC"
    assert destination.exists()
    assert b"produced" in destination.read_bytes()


# --- limits --------------------------------------------------------------


@requires_backend
@pytest.mark.slow
def test_wall_time_limit_is_tle():
    exe, args = busy_loop_command()
    status = river.Sandbox().run(exe, args, wall_time_limit_ms=1000)
    assert status.status == "TLE"
    assert status.signal == 9


@requires_backend
@pytest.mark.slow
def test_cpu_time_limit_is_tle():
    exe, args = busy_loop_command()
    status = river.Sandbox().run(exe, args, time_limit_ms=300)
    assert status.status == "TLE"
    assert status.signal == 9


@requires_backend
def test_stdout_limit_is_ole():
    exe, args = noisy_command()
    status = river.Sandbox().run(exe, args, stdout_limit_kb=1)
    assert status.status == "OLE"
    assert status.stdout_truncated is True


# --- argument validation -------------------------------------------------


def test_cwd_must_be_relative():
    exe, args = echo_command("x")
    with pytest.raises(ValueError, match="cwd"):
        river.Sandbox().run(exe, args, cwd=".")


def test_copy_out_keys_must_be_relative():
    exe, args = echo_command("x")
    with pytest.raises(ValueError, match="copy_out"):
        river.Sandbox().run(exe, args, copy_out={"/absolute": "out.txt"})


def test_stdin_and_stdin_file_are_mutually_exclusive():
    exe, args = echo_command("x")
    with pytest.raises(ValueError, match="mutually exclusive"):
        river.Sandbox().run(exe, args, stdin=b"x", stdin_file="y")
