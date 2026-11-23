"""End-to-end sandbox behaviour (marker: functional).

Every test here needs a delegated cgroup (the `River()` preflight) and, for
the real-rootfs group, `RIVER_TEST_ROOTFS` pointing at a docker-exported
`python:3.12-slim` tree (see docs/development-plan.md §4, PR 2).
"""

from __future__ import annotations

import concurrent.futures

import pytest

from river import ExecSetupError, River

from conftest import delegated

pytestmark = [
    pytest.mark.functional,
    pytest.mark.skipif(
        not delegated(),
        reason="not in a delegated cgroup; run under systemd-run --user --scope -p Delegate=yes",
    ),
]

# The rootfs's meta.json provides these (docs/design.md §4.1).
META_PATH = "/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin"


def py(river_, code: str, **kwargs):
    """One `python -c <code>` run over the real rootfs."""
    return river_.exec("python", ["-c", code], **kwargs)


# ------------------------------------------------------------- happy paths


def test_hello_world(river_):
    result = py(river_, "print('Hello, World!')")
    assert result.status == "AC"
    assert result.exit_code == 0
    assert result.signal is None
    assert result.stdout == b"Hello, World!\n"
    assert result.stderr == b""
    assert result.files == {}
    assert result.error is None
    # 计量有值 (the interface is wired; accuracy arrives with PR 3's run cgroup).
    assert result.cpu_time_used_ms > 0
    assert result.wall_time_used_ms > 0
    assert result.memory_used_bytes > 0


def test_stdout_and_stderr_are_captured_separately(river_):
    result = py(
        river_,
        "import sys; sys.stdout.write('out1\\n'); sys.stderr.write('err1\\n');"
        " sys.stdout.write('out2\\n')",
    )
    assert result.status == "AC"
    assert result.stdout == b"out1\nout2\n"
    assert result.stderr == b"err1\n"


# ------------------------------------------------------------------- verdicts


def test_nonzero_exit_is_re(river_):
    result = py(river_, "import sys; sys.exit(7)")
    assert result.status == "RE"
    assert result.exit_code == 7
    assert result.signal is None
    assert result.error is not None and "code 7" in result.error


def test_signal_death_is_re_with_signal_number(river_):
    # The sandboxed program is pid 1 of the new pid namespace, and the kernel
    # drops handler-less *sent* signals to an init — os.kill(os.getpid(),
    # SIGSEGV) would be a no-op. A genuine hardware fault still kills it.
    result = py(river_, "import ctypes; ctypes.string_at(0)")
    assert result.status == "RE"
    assert result.signal == 11
    assert result.exit_code is None
    assert result.error is not None and "SIGSEGV" in result.error


# ------------------------------------------------------------------- cwd/envs


def test_default_cwd_is_work(river_):
    result = py(river_, "import os; print(os.getcwd())")
    assert result.stdout == b"/work\n"


def test_cwd(river_):
    result = river_.exec("python", ["-c", "import os; print(os.getcwd())"], cwd="/tmp")
    assert result.stdout == b"/tmp\n"


def test_envs_come_from_meta_json(river_):
    result = py(river_, "import os; print(os.environ.get('HOME'))")
    assert result.stdout == b"/work\n"


def test_explicit_envs_replace_meta_envs(river_):
    result = river_.exec(
        "python",
        ["-c", "import os; print(os.environ.get('FOO'), os.environ.get('HOME'))"],
        envs={"PATH": META_PATH, "FOO": "bar"},
    )
    assert result.stdout == b"bar None\n"


# ---------------------------------------------------------------------- stdio


def test_stdin_bytes(river_):
    result = river_.exec(
        "python",
        ["-c", "import sys; print(sys.stdin.read().strip().upper())"],
        stdin=b"hello",
    )
    assert result.stdout == b"HELLO\n"


def test_stdin_file_reads_a_copy_in_file(river_):
    result = river_.exec(
        "python",
        ["-c", "import sys; print(sys.stdin.read().strip())"],
        copy_in={"input.txt": "river"},
        stdin_file="input.txt",
    )
    assert result.stdout == b"river\n"


# ----------------------------------------------- V7/V9: sysfs, devices, ptmx


def test_sysfs_mounted_and_devices_usable(river_):
    """V9: sysfs mounts read-only inside the userns; bound devices write."""
    result = py(
        river_,
        "import os\n"
        "os.write(os.open('/dev/null', os.O_WRONLY), b'x')\n"
        "os.read(os.open('/dev/urandom', os.O_RDONLY), 16)\n"
        "assert os.listdir('/sys'), '/sys is empty'\n"
        "assert 'class' in os.listdir('/sys')\n"
        "assert not os.path.exists('/sys/fs/cgroup'), 'host cgroup leaked'\n"
        "print('sys-and-devices-ok')\n",
    )
    assert result.status == "AC", (result.stdout, result.stderr, result.error)
    assert result.stdout == b"sys-and-devices-ok\n"


def test_openpty_works(river_):
    """V7: /dev/ptmx bind gives a usable pseudo-terminal in the sandbox."""
    result = py(river_, "import pty; pty.openpty(); print('pty-ok')")
    assert result.status == "AC", (result.stdout, result.stderr, result.error)
    assert result.stdout == b"pty-ok\n"


# ------------------------------------------------------------ copy_in/copy_out


def test_copy_in_nested_path(river_):
    result = river_.exec(
        "python",
        ["-c", "print(open('sub/data.txt').read().strip())"],
        copy_in={"sub/data.txt": "42"},
    )
    assert result.stdout == b"42\n"


def test_copy_out_returns_files(river_):
    result = river_.exec(
        "python",
        ["-c", "open('out.txt', 'w').write('done')"],
        copy_out={"out.txt": None},
    )
    assert result.status == "AC"
    assert result.files == {"out.txt": b"done"}


# --------------------------------------------------------------- error paths


def test_executable_not_found(tmp_path):
    with River(tmp_path) as sandbox:
        with pytest.raises(ExecSetupError) as info:
            sandbox.exec("definitely-missing-exe-12345", envs={"PATH": "/usr/bin:/bin"})
    assert "child.execve" in str(info.value)
    assert "definitely-missing-exe-12345" in str(info.value)


def test_absolute_executable_not_found(tmp_path):
    with River(tmp_path) as sandbox:
        with pytest.raises(ExecSetupError, match="child.execve"):
            sandbox.exec("/no/such/file", envs={"PATH": META_PATH})


def test_cwd_does_not_exist(tmp_path):
    with River(tmp_path) as sandbox:
        with pytest.raises(ExecSetupError) as info:
            sandbox.exec("python", envs={"PATH": META_PATH}, cwd="/no/such/dir")
    assert "child.chdir" in str(info.value)
    assert "cwd does not exist" in str(info.value)


def test_stdin_file_missing(tmp_path):
    """The agreed semantics: a missing stdin_file fails fast (V4 of the
    example.py discussion)."""
    with River(tmp_path) as sandbox:
        with pytest.raises(ExecSetupError, match="child.stdio"):
            sandbox.exec("python", envs={"PATH": META_PATH}, stdin_file="missing.txt")


# --------------------------------------------------------------- concurrency


def test_eight_threads_concurrent_exec(river_):
    def one(i: int):
        return river_.exec("python", ["-c", f"print({i})"])

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(one, range(8)))
    assert len(results) == 8
    for i, result in zip(range(8), results):
        assert result.status == "AC", (i, result.stderr, result.error)
        assert result.stdout == f"{i}\n".encode()


# ------------------------------------------------- docs/example.py, as written


def test_example_py_call_shape(river_):
    """The exact call of docs/example.py: stdin_file is supplied via copy_in
    (the agreed fix), stdout/stderr go to files inside /work, metrics have
    values."""
    result = river_.exec(
        "python",
        args=["-c", "print('Hello, World!')"],
        cwd="/work",
        envs={"PATH": META_PATH},
        cpu_time_limit_ms=1000,
        wall_time_limit_ms=2000,
        memory_limit_bytes=64 * 1024 * 1024,
        stdout_limit_bytes=64 * 1024,
        stderr_limit_bytes=64 * 1024,
        copy_in={"input.txt": "1 2 3\n"},
        copy_out={},
        copy_out_limit_bytes=64 * 1024,
        stdin_file="input.txt",
        stdout_file="stdout.txt",
        stderr_file="stderr.txt",
    )
    assert result.status == "AC", (result.error,)
    assert result.exit_code == 0
    assert result.signal is None
    # stdout_file/stderr_file redirect the streams into /work, so the pipes
    # see nothing and the fields are None (design.md §4).
    assert result.stdout is None
    assert result.stderr is None
    assert result.files == {}
    assert result.cpu_time_used_ms > 0
    assert result.wall_time_used_ms > 0
    assert result.memory_used_bytes > 0
