"""End-to-end tests for the Linux backend.

Run on a root cgroups-v2 host with::

    uv run maturin develop
    uv run pytest tests/test_linux_backend.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

import river

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux backend tests")

SH = "/bin/sh"
# The host venv's python3 is a shim whose directory is not mounted inside
# the sandbox; the system interpreter merged from /usr is always there.
PYTHON = "/usr/bin/python3"

BUSY_LOOP = [
    "-c",
    "x = 0\nfor i in range(2 * 10**7):\n    x += i",
]
BIG_ALLOCATION = ["-c", "a = bytearray(500 * 1024 * 1024)"]


def has_python() -> bool:
    return Path(PYTHON).exists()


@pytest.fixture()
def session():
    with river.Sandbox() as sandbox:
        yield sandbox


def out_path(tmp_path: Path, name: str = "out.txt") -> str:
    return str(tmp_path / name)


# --- session lifecycle ------------------------------------------------------


def test_workdir_lifecycle():
    with river.Sandbox() as sandbox:
        workdir = Path(sandbox.workdir)
        assert workdir.is_dir()
    assert not workdir.exists()


def test_exec_requires_session():
    sandbox = river.Sandbox()
    with pytest.raises(RuntimeError, match="inside"):
        sandbox.exec(SH, args=["-c", "true"])


def test_rootfs_rejected():
    with pytest.raises(ValueError, match="rootfs"):
        river.Sandbox(rootfs="/tmp")


def test_cgroup_session_cleanup():
    with river.Sandbox():
        pass
    leftovers = list(Path("/sys/fs/cgroup").glob("river-*"))
    assert not leftovers


# --- basic verdicts ---------------------------------------------------------


def test_ac(session, tmp_path):
    out = out_path(tmp_path)
    status = session.exec(SH, args=["-c", "echo hello"], stdout_file=out)
    assert status.status == "AC"
    assert status.exit_code == 0
    assert status.signal == 0
    assert Path(out).read_text() == "hello\n"


def test_re_nonzero_exit(session):
    status = session.exec(SH, args=["-c", "exit 7"])
    assert status.status == "RE"
    assert status.exit_code == 7


def test_wall_tle(session):
    status = session.exec("/usr/bin/sleep", args=["30"], wall_time_limit_ms=500)
    assert status.status == "TLE"
    assert status.signal == 9
    assert 400 <= status.wall_time_used_ms < 5000


def test_missing_executable(session):
    with pytest.raises(OSError, match="execve"):
        session.exec("/no/such/binary")


# --- stdio ------------------------------------------------------------------


def test_stdout_stderr_split(session, tmp_path):
    out = out_path(tmp_path, "out.txt")
    err = out_path(tmp_path, "err.txt")
    status = session.exec(
        SH,
        args=["-c", "echo to-out; echo to-err 1>&2"],
        stdout_file=out,
        stderr_file=err,
    )
    assert status.status == "AC"
    assert Path(out).read_text() == "to-out\n"
    assert Path(err).read_text() == "to-err\n"


def test_stdin_file(session, tmp_path):
    stdin = tmp_path / "in.txt"
    stdin.write_text("42\n")
    out = out_path(tmp_path)
    status = session.exec(SH, args=["-c", "read x; echo got-$x"],
                          stdin_file=str(stdin), stdout_file=out)
    assert status.status == "AC"
    assert Path(out).read_text() == "got-42\n"


def test_output_limit_ole(session, tmp_path):
    out = out_path(tmp_path)
    status = session.exec(
        "/usr/bin/head",
        args=["-c", "1000000", "/dev/zero"],
        stdout_file=out,
        stdout_limit_bytes=10000,
        wall_time_limit_ms=30000,
    )
    assert status.status == "OLE"
    assert status.signal == 9


def test_output_exactly_at_limit_is_legal(session, tmp_path):
    out = out_path(tmp_path)
    status = session.exec(
        "/usr/bin/head",
        args=["-c", "10000", "/dev/zero"],
        stdout_file=out,
        stdout_limit_bytes=10000,
        wall_time_limit_ms=30000,
    )
    assert status.status == "AC"


# --- resource limits and accounting ------------------------------------------


@pytest.mark.skipif(not has_python(), reason="needs python3 in the sandbox")
def test_mle(session):
    status = session.exec(
        PYTHON,
        args=BIG_ALLOCATION,
        memory_limit_bytes=256 * 1024 * 1024,
        wall_time_limit_ms=60000,
    )
    assert status.status == "MLE"
    assert status.memory_used_bytes >= 256 * 1024 * 1024


@pytest.mark.skipif(not has_python(), reason="needs python3 in the sandbox")
def test_cpu_accounting(session):
    status = session.exec(PYTHON, args=BUSY_LOOP, wall_time_limit_ms=60000)
    assert status.status == "AC"
    assert status.cpu_time_used_ms >= 100


@pytest.mark.skipif(not has_python(), reason="needs python3 in the sandbox")
def test_cpu_limit_tle(session):
    status = session.exec(
        PYTHON,
        args=BUSY_LOOP,
        cpu_time_limit_ms=200,
        wall_time_limit_ms=60000,
    )
    assert status.status == "TLE"


def test_fork_bomb_contained(session):
    status = session.exec(
        SH,
        args=["-c", "i=0; while [ $i -lt 400 ]; do sleep 30 & i=$((i+1)); done; wait"],
        wall_time_limit_ms=30000,
    )
    # The pids ceiling makes the forks fail; the judged process then ends
    # abnormally on its own, never by exhausting the host.
    assert status.status in ("RE", "TLE", "MLE")


# --- copy_in / copy_out / cwd ------------------------------------------------


def test_copy_in_out_roundtrip(session, tmp_path):
    source = tmp_path / "prog.txt"
    source.write_text('echo product > result.txt\n')
    destination = tmp_path / "result.txt"

    status = session.exec(
        SH,
        args=["prog.txt"],
        copy_in={str(source): "prog.txt"},
        copy_out={"result.txt": str(destination)},
    )
    assert status.status == "AC"
    assert destination.read_text() == "product\n"


def test_copy_in_directory(session, tmp_path):
    directory = tmp_path / "data"
    directory.mkdir()
    (directory / "f.txt").write_text("deep")

    out = out_path(tmp_path)
    status = session.exec(
        SH,
        args=["-c", "cat data/f.txt"],
        copy_in={str(directory): "data"},
        stdout_file=out,
    )
    assert status.status == "AC"
    assert Path(out).read_text() == "deep"


def test_copy_out_missing_source_skipped(session, tmp_path):
    destination = tmp_path / "never.txt"
    status = session.exec(SH, args=["-c", "true"],
                          copy_out={"never.txt": str(destination)})
    assert status.status == "AC"
    assert not destination.exists()


def test_copy_out_limit(session, tmp_path):
    source = tmp_path / "big.txt"
    source.write_text("x" * 10000)
    destination = tmp_path / "collected.txt"

    status = session.exec(
        SH,
        args=["-c", "true"],
        copy_in={str(source): "big.txt"},
        copy_out={"big.txt": str(destination)},
        copy_out_limit_bytes=1000,
    )
    assert status.status == "OLE"
    assert status.signal == 9
    assert not destination.exists()


def test_copy_in_rejects_escape(session, tmp_path):
    source = tmp_path / "f.txt"
    source.write_text("x")
    with pytest.raises(ValueError, match="relative path"):
        session.exec(SH, args=["-c", "true"], copy_in={str(source): "/etc/passwd"})
    with pytest.raises(ValueError, match="relative path"):
        session.exec(SH, args=["-c", "true"], copy_in={str(source): "../escape"})


def test_copy_in_rejects_overlapping_destinations(session, tmp_path):
    source = tmp_path / "f.txt"
    source.write_text("x")
    with pytest.raises(ValueError, match="overlap"):
        session.exec(
            SH,
            args=["-c", "true"],
            copy_in={str(source): "a", str(source) + "2": "a/b"},
        )


def test_copy_in_rejects_duplicate_destinations(session, tmp_path):
    first = tmp_path / "f1.txt"
    second = tmp_path / "f2.txt"
    first.write_text("1")
    second.write_text("2")
    with pytest.raises(ValueError, match="same destination"):
        session.exec(
            SH,
            args=["-c", "true"],
            copy_in={str(first): "a", str(second): "a"},
        )


def test_cwd(session, tmp_path):
    out = out_path(tmp_path)
    # `cwd` must name an existing directory (same as the Windows backend);
    # the session workdir persists across runs, so an earlier run can create it.
    assert session.exec(SH, args=["-c", "mkdir -p sub/dir"]).status == "AC"
    status = session.exec(SH, args=["-c", "pwd"], cwd="sub/dir", stdout_file=out)
    assert status.status == "AC"
    assert Path(out).read_text().strip() == "/workspace/sub/dir"


def test_cwd_rejects_escape():
    with river.Sandbox() as sandbox:
        with pytest.raises(ValueError, match="relative path"):
            sandbox.exec(SH, args=["-c", "true"], cwd="/etc")


# --- environment -------------------------------------------------------------


def test_envs_override(session, tmp_path):
    out = out_path(tmp_path)
    status = session.exec(SH, args=["-c", "echo $RIVER_TEST"], envs={"RIVER_TEST": "v"},
                          stdout_file=out)
    assert status.status == "AC"
    assert Path(out).read_text().strip() == "v"


def test_tmpdir_points_into_scratch(session, tmp_path):
    out = out_path(tmp_path)
    status = session.exec(SH, args=["-c", "echo $TMPDIR; echo hi > $TMPDIR/w && echo writable"],
                          stdout_file=out)
    assert status.status == "AC"
    lines = Path(out).read_text().splitlines()
    assert lines[0] == "/workspace/tmp"
    assert lines[1] == "writable"


# --- isolation ---------------------------------------------------------------


def test_pid_namespace(session, tmp_path):
    out = out_path(tmp_path)
    status = session.exec(SH, args=["-c", "echo $$ $(cat /proc/1/comm)"],
                          stdout_file=out)
    assert status.status == "AC"
    pid, comm = Path(out).read_text().split()
    assert pid == "1"
    assert comm == "sh"


def test_filesystem_isolation(session, tmp_path):
    out = out_path(tmp_path)
    status = session.exec(
        SH,
        args=[
            "-c",
            "ls / | sort | tr '\\n' ' '; echo; "
            "echo x > /etc/pwned 2>/dev/null && echo etc-writable || echo etc-ro; "
            "echo ok > /workspace/w.txt && echo workspace-writable",
        ],
        stdout_file=out,
    )
    assert status.status == "AC"
    lines = Path(out).read_text().splitlines()
    entries = set(lines[0].split())
    assert entries == {"bin", "dev", "etc", "lib", "lib64", "proc", "runtime",
                       "sbin", "usr", "workspace"}
    assert lines[1] == "etc-ro"
    assert lines[2] == "workspace-writable"


def test_host_root_unreachable(session, tmp_path):
    # After pivot_root the host filesystem is unmounted: the old workdir
    # path under /tmp must not exist inside the sandbox.
    out = out_path(tmp_path)
    status = session.exec(SH, args=["-c", "test -e /.oldroot && echo leaked || echo isolated; "
                                    "ls /tmp 2>/dev/null | wc -l"],
                          stdout_file=out)
    assert status.status == "AC"
    lines = Path(out).read_text().splitlines()
    assert lines[0] == "isolated"


def test_seccomp_blocks_mount(session, tmp_path):
    out = out_path(tmp_path)
    probe = (
        "import ctypes, errno\n"
        "libc = ctypes.CDLL(None, use_errno=True)\n"
        "for name, nr in {'mount': 165, 'ptrace': 101, 'unshare': 272}.items():\n"
        "    ctypes.set_errno(0)\n"
        "    libc.syscall(nr, 0, 0, 0, 0, 0, 0)\n"
        "    assert ctypes.get_errno() == errno.EPERM, name\n"
        "print('blocked')\n"
    )
    status = session.exec(PYTHON, args=["-c", probe], stdout_file=out)
    assert status.status == "AC"
    assert Path(out).read_text().strip() == "blocked"


def test_seccomp_kernel_view(session, tmp_path):
    out = out_path(tmp_path)
    status = session.exec(SH, args=["-c", "grep -E '^(Seccomp|NoNewPrivs):' /proc/self/status"],
                          stdout_file=out)
    assert status.status == "AC"
    text = Path(out).read_text()
    assert "Seccomp:\t2" in text
    assert "NoNewPrivs:\t1" in text
