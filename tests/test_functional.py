"""End-to-end sandbox behaviour (marker: functional).

Every test here needs a delegated cgroup (the `River()` preflight) and, for
the real-rootfs group, `RIVER_TEST_ROOTFS` pointing at a docker-exported
`python:3.12-slim` tree (see docs/development-plan.md §4, PR 2).
"""

from __future__ import annotations

import concurrent.futures

import pytest

from river import CopyOutError, ExecResult, ExecSetupError, River, RootfsError

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
#
# development-plan.md §4 PR 5: keys normalize below /work (relative ones
# against cwd), every host-side read of the work directory goes through
# openat2 RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS (design.md §10), and a
# copy_out failure raises CopyOutError with the finished run on `.result`.


def test_copy_in_nested_path(river_):
    result = river_.exec(
        "python",
        ["-c", "print(open('sub/data.txt').read().strip())"],
        copy_in={"sub/data.txt": "42"},
    )
    assert result.stdout == b"42\n"


def test_copy_in_keys_resolve_against_cwd(river_):
    # A relative key lands below cwd (which copy_in may have to create),
    # an absolute one is used as-is.
    result = river_.exec(
        "python",
        ["-c", "print(open('data.txt').read(), open('abs.txt').read())"],
        cwd="/work/job",
        copy_in={"data.txt": "rel", "/work/job/abs.txt": "abs"},
    )
    assert result.status == "AC", (result.stderr, result.error)
    assert result.stdout == b"rel abs\n"


def test_copy_in_from_host_file(tmp_path, river_):
    # An os.PathLike value copies the host file's *content* (design.md §10);
    # the host file is outside the sandbox and stays there.
    src = tmp_path / "data.bin"
    src.write_bytes(b"\x00\x01binary\xff")
    result = river_.exec(
        "python",
        ["-c", "import sys; sys.stdout.buffer.write(open('data.bin', 'rb').read())"],
        copy_in={"data.bin": src},
    )
    assert result.status == "AC", (result.stderr, result.error)
    assert result.stdout == b"\x00\x01binary\xff"


def test_copy_in_missing_host_file_is_rootfs_error(tmp_path, river_):
    with pytest.raises(RootfsError, match="copy_in"):
        river_.exec("python", copy_in={"data.txt": tmp_path / "missing.txt"})


@pytest.mark.parametrize("key", ["/etc/passwd", "/work", "../out", "/work/../etc/x", ""])
def test_copy_keys_must_stay_below_work(river_, key):
    for kwargs in ({"copy_in": {key: "x"}}, {"copy_out": {key: None}}):
        with pytest.raises(RootfsError, match="below /work|sandbox path"):
            river_.exec("python", **kwargs)


def test_copy_out_returns_files(river_):
    result = river_.exec(
        "python",
        ["-c", "open('out.txt', 'w').write('done')"],
        copy_out={"out.txt": None},
    )
    assert result.status == "AC"
    assert result.files == {"out.txt": b"done"}


def test_copy_out_nested_and_relative_keys(river_):
    # copy_in also has to create the cwd directory (the child chdirs into
    # /work/out before it can write there).
    result = river_.exec(
        "python",
        ["-c", "import os; os.mkdir('sub'); open('result.txt', 'w').write('42'); open('sub/other.txt', 'w').write('7')"],
        cwd="/work/out",
        copy_in={"seed.txt": ""},
        copy_out={"result.txt": None, "/work/out/sub/other.txt": None},
    )
    assert result.status == "AC", (result.stderr, result.error)
    assert result.files == {"result.txt": b"42", "/work/out/sub/other.txt": b"7"}


def test_copy_out_to_host_file_as_path_and_str(tmp_path, river_):
    # A host path (os.PathLike or str) as the value gets the content
    # written over it; `files` then only holds the `None` entries.
    dest, dest2, dest3 = (tmp_path / name for name in ("host.txt", "host2.txt", "host3.txt"))
    dest.write_text("old content that must be overwritten")
    result = river_.exec(
        "python",
        ["-c", "open('a.txt', 'w').write('A'); open('b.txt', 'w').write('B'); open('c.txt', 'w').write('C')"],
        copy_out={"a.txt": dest, "b.txt": str(dest2), "c.txt": None},
    )
    assert result.status == "AC", (result.stderr, result.error)
    assert result.files == {"c.txt": b"C"}
    assert dest.read_bytes() == b"A"
    assert dest2.read_bytes() == b"B"
    assert not dest3.exists()


def test_copy_out_failure_writes_nothing_to_the_host(tmp_path, river_):
    # Host destinations are written only after every entry was read: a
    # missing entry later in the mapping leaves earlier host files alone.
    dest = tmp_path / "host.txt"
    with pytest.raises(CopyOutError, match="is missing"):
        river_.exec(
            "python",
            ["-c", "open('a.txt', 'w').write('A')"],
            copy_out={"a.txt": dest, "missing.txt": None},
        )
    assert not dest.exists()


def test_copy_out_missing_file_is_rejected_with_the_run(river_):
    with pytest.raises(CopyOutError, match='copy_out "missing.txt": is missing') as info:
        py(river_, "import sys; sys.exit(3)", copy_out={"missing.txt": None})
    result = info.value.result
    assert isinstance(result, ExecResult)
    assert result.status == "RE"
    assert result.exit_code == 3
    assert result.signal is None
    assert result.files == {}
    assert result.error is not None and "code 3" in result.error
    assert result.wall_time_used_ms > 0


def test_copy_out_directory_is_rejected(river_):
    with pytest.raises(CopyOutError, match='"d": is not a regular file') as info:
        py(river_, "import os; os.mkdir('d')", copy_out={"d": None})
    assert info.value.result.status == "AC"


def test_copy_out_fifo_is_rejected(river_):
    # The non-regular class (device nodes cannot even be made inside the
    # sandbox, design.md §9): a FIFO must not block the host-side open.
    with pytest.raises(CopyOutError, match='"f": is not a regular file'):
        py(river_, "import os; os.mkfifo('f')", copy_out={"f": None})


def test_copy_out_limit_boundary(river_):
    # Exactly at the limit passes, one byte more raises (design.md §10).
    code = "open('out.txt', 'wb').write(b'x' * 64)"
    result = py(river_, code, copy_out={"out.txt": None}, copy_out_limit_bytes=64)
    assert result.files == {"out.txt": b"x" * 64}
    with pytest.raises(CopyOutError, match="65 bytes, above copy_out_limit_bytes=64") as info:
        py(
            river_,
            "open('out.txt', 'wb').write(b'x' * 65)",
            copy_out={"out.txt": None},
            copy_out_limit_bytes=64,
        )
    assert info.value.result.status == "AC"


def test_copy_out_without_limit_reads_large_files(river_):
    result = py(
        river_,
        "open('big.txt', 'wb').write(b'z' * (1024 * 1024))",
        copy_out={"big.txt": None},
    )
    assert result.files == {"big.txt": b"z" * (1024 * 1024)}


# ------------------------------------------------------ stdin_file / *_file
#
# design.md §5 `child.stdio`, §6: `*_file` paths are sandbox paths relative
# to cwd; the redirected streams come back as `None` and the files are
# fetched with copy_out (or land on the sandbox tmpfs when outside /work).


def test_stdout_file_and_stderr_file_content(river_):
    result = river_.exec(
        "python",
        ["-c", "import sys; print('to out'); print('to err', file=sys.stderr)"],
        stdout_file="out.txt",
        stderr_file="err.txt",
        copy_out={"out.txt": None, "err.txt": None},
    )
    assert result.status == "AC", (result.error,)
    assert result.stdout is None
    assert result.stderr is None
    assert result.files == {"out.txt": b"to out\n", "err.txt": b"to err\n"}


def test_stdout_file_leaves_stderr_on_the_pipe(river_):
    result = river_.exec(
        "python",
        ["-c", "import sys; print('to out'); print('to err', file=sys.stderr)"],
        stdout_file="out.txt",
        copy_out={"out.txt": None},
    )
    assert result.files == {"out.txt": b"to out\n"}
    assert result.stdout is None
    assert result.stderr == b"to err\n"


def test_std_file_paths_are_relative_to_cwd(river_):
    result = river_.exec(
        "python",
        ["-c", "import sys; sys.stdout.write(open('input.txt').read()); print('done')"],
        cwd="/work/job",
        copy_in={"input.txt": "the input\n"},
        stdin_file="input.txt",
        stdout_file="output.txt",
        stderr_file="/work/job/err.txt",
        copy_out={"output.txt": None, "/work/job/err.txt": None},
    )
    assert result.status == "AC", (result.error,)
    assert result.files == {"output.txt": b"the input\ndone\n", "/work/job/err.txt": b""}


def test_stdin_file_absolute_path(river_):
    result = river_.exec(
        "python",
        ["-c", "import sys; print(sys.stdin.read().strip())"],
        copy_in={"input.txt": "abs"},
        stdin_file="/work/input.txt",
    )
    assert result.stdout == b"abs\n"


def test_stdin_and_stdin_file_are_mutually_exclusive(river_):
    with pytest.raises(ValueError, match="mutually exclusive"):
        river_.exec("python", stdin=b"x", stdin_file="input.txt")


def test_stdout_file_outside_work(river_):
    # /tmp is the sandbox's own tmpfs: the stream goes there, nothing is
    # host-observable and the run is otherwise unaffected.
    result = py(river_, "print('gone')", stdout_file="/tmp/out.txt")
    assert result.status == "AC", (result.error,)
    assert result.stdout is None
    assert result.files == {}


def test_stdout_file_in_read_only_rootfs_is_exec_setup_error(river_):
    with pytest.raises(ExecSetupError, match="child.stdio"):
        py(river_, "print('x')", stdout_file="/usr/out.txt")


# ------------------------------------------------------------------ meta.json
#
# design.md §4.1: envs=None uses <rootfs>/meta.json; no file and no envs is
# a RootfsError (the real-rootfs half lives in test_envs_come_from_meta_json
# and test_explicit_envs_replace_meta_envs above; parsing errors in
# test_doctor.py).


def test_exec_without_envs_needs_meta_json(tmp_path):
    with River(tmp_path) as sandbox:
        with pytest.raises(RootfsError, match="meta.json"):
            sandbox.exec("python")
        # ... and explicit envs make the rootfs usable without one.
        with pytest.raises(ExecSetupError, match="child.execve"):
            sandbox.exec("python", envs={"PATH": META_PATH})


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
