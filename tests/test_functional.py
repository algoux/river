"""Functional tests: the frozen API contract behaves as documented.

Covers the sandbox's normal-operation surface:
- run() returns a real `Status` with the documented fields
- `copy_in` (bytes and host files), `cwd`, `env`
- stdin (bytes and file), stdout/stderr capture, `*_file` archives
- the `with` block protocol
- validation errors raise (not `SE`)
"""

import os
import sys

import pytest

import river


def test_plain_run_is_ac(sandbox, python_exe):
    r = sandbox.run(python_exe, ["-c", "print('hello')"])
    assert r.status == "AC"
    assert r.signal == 0
    assert r.exit_code == 0
    assert r.stdout.strip() == b"hello"
    assert not r.stdout_truncated
    assert not r.stderr_truncated
    assert r.wall_time_used_ms >= 0
    assert r.time_used_ms >= 0
    assert r.memory_used_kb > 0


def test_nonzero_exit_is_re(sandbox, python_exe):
    r = sandbox.run(python_exe, ["-c", "raise SystemExit(3)"])
    assert r.status == "RE"
    assert r.exit_code == 3


def test_stderr_is_captured_separately(sandbox, python_exe):
    r = sandbox.run(python_exe, ["-c", "import sys; sys.stderr.write('bad\\n')"])
    assert r.status == "AC"
    assert r.stderr.strip() == b"bad"
    assert r.stdout == b""


def test_copy_in_bytes_reaches_the_program(sandbox, python_exe):
    r = sandbox.run(
        python_exe,
        ["-c", "import sys; sys.stdout.write(open(sys.argv[1]).read())",
         "in.txt"],
        copy_in={"in.txt": b"payload"},
    )
    assert r.status == "AC"
    assert r.stdout == b"payload"


def test_copy_in_host_file_is_copied(sandbox, python_exe, tmp_path):
    src = tmp_path / "input.txt"
    src.write_bytes(b"from-host")
    r = sandbox.run(
        python_exe,
        ["-c", "import sys; sys.stdout.write(open(sys.argv[1]).read())",
         "input.txt"],
        copy_in={"input.txt": str(src)},
    )
    assert r.status == "AC"
    assert r.stdout == b"from-host"


def test_copy_in_is_immutable_for_the_program(sandbox, python_exe):
    # The program may read its input but must not modify it (DESIGN §3.3).
    # Clearing the read-only bit first is the regression: on Windows the
    # FILE_ATTRIBUTE_READONLY was clearable because the inherited cwd ACE
    # grants FILE_WRITE_ATTRIBUTES; on Linux the file used to be chowned to
    # the sandbox uid, so its owner could chmod it back to writable.
    code = (
        "import os, sys\n"
        "p = sys.argv[1]\n"
        "print('CONTENT', open(p).read())\n"
        "try:\n"
        "    os.chmod(p, 0o666)\n"
        "    print('CHMOD_OK')\n"
        "except OSError:\n"
        "    print('CHMOD_DENIED')\n"
        "try:\n"
        "    open(p, 'w').write('changed')\n"
        "    print('WRITE_OK')\n"
        "except OSError:\n"
        "    print('WRITE_DENIED')\n"
        "print('FINAL', open(p).read())\n"
    )
    r = sandbox.run(
        python_exe,
        ["-c", code, "in.txt"],
        copy_in={"in.txt": b"immutable"},
    )
    assert r.status == "AC", r.stderr
    out = r.stdout.decode()
    assert "CHMOD_DENIED" in out, out
    assert "WRITE_DENIED" in out, out
    assert "FINAL immutable" in out, out


@pytest.mark.skipif(
    not sys.platform.startswith("win"),
    reason="AppContainer profile slots are Windows-only",
)
def test_profile_state_does_not_survive_between_runs(sandbox, python_exe):
    """The per-run profile slot is wiped: nothing a run writes under
    `%LOCALAPPDATA%` may be visible to the next run (or on the host).

    A fixed AppContainer profile used to keep that folder (and everything the
    program wrote into it) for the lifetime of the machine.
    """
    write = (
        "import os\n"
        "p = os.path.join(os.environ['LOCALAPPDATA'], 'leak.txt')\n"
        "open(p, 'w').write('leak')\n"
        "print(os.environ['LOCALAPPDATA'])\n"
    )
    r1 = sandbox.run(python_exe, ["-c", write])
    assert r1.status == "AC", r1.stderr
    local = r1.stdout.decode().strip().splitlines()[-1]
    assert "river.sandbox." in local, local
    assert not os.path.exists(os.path.join(local, "leak.txt")), (
        "run state survived on disk"
    )

    read = (
        "import os\n"
        "p = os.path.join(os.environ['LOCALAPPDATA'], 'leak.txt')\n"
        "print('SEEN' if os.path.exists(p) else 'CLEAN')\n"
    )
    r2 = sandbox.run(python_exe, ["-c", read])
    assert r2.status == "AC", r2.stderr
    assert b"CLEAN" in r2.stdout, r2.stdout


@pytest.mark.skipif(
    not sys.platform.startswith("win"),
    reason="Windows directory copy_in uses an inheritable protected DACL",
)
def test_directory_copy_in_is_immutable_and_cleaned_up(sandbox, python_exe, tmp_path):
    """A directory `copy_in` is protected as a tree and still cleaned up.

    The protected ACL is inheritable (one DACL write for the whole tree), and
    it keeps `FILE_DELETE_CHILD` for the judger so cleanup can remove the
    entries — a regression here leaks one workdir per run.
    """
    import glob
    import tempfile

    src = tmp_path / "inputdir"
    (src / "sub").mkdir(parents=True)
    (src / "sub" / "data.txt").write_bytes(b"immutable")

    before = set(glob.glob(os.path.join(tempfile.gettempdir(), "river-*")))
    code = (
        "import os, sys\n"
        "p = sys.argv[1]\n"
        "print('CONTENT', open(p).read())\n"
        "try:\n"
        "    os.chmod(p, 0o666)\n"
        "    open(p, 'w').write('changed')\n"
        "    print('MUTABLE')\n"
        "except OSError:\n"
        "    print('DENIED')\n"
    )
    r = sandbox.run(
        python_exe,
        ["-c", code, "d/sub/data.txt"],
        copy_in={"d": str(src)},
    )
    assert r.status == "AC", r.stderr
    assert b"DENIED" in r.stdout, r.stdout

    leaked = {
        p
        for p in set(glob.glob(os.path.join(tempfile.gettempdir(), "river-*"))) - before
        if os.path.isdir(p)
    }
    assert not leaked, f"workdir leaked after a directory copy_in: {leaked}"


def test_copy_in_nested_paths_are_created(sandbox, python_exe):
    r = sandbox.run(
        python_exe,
        ["-c", "import sys; sys.stdout.write(open(sys.argv[1]).read())",
         "a/b/c.txt"],
        copy_in={"a/b/c.txt": b"nested"},
    )
    assert r.status == "AC"
    assert r.stdout == b"nested"


def test_cwd_is_inside_the_sandbox(sandbox, python_exe):
    r = sandbox.run(python_exe, ["-c", "import os; print(os.getcwd())"])
    assert r.status == "AC"
    # The cwd is the private per-run directory, never the host cwd.
    # (Backend-specific name: `river-*` on Windows, `/cwd` on Linux.)
    if __import__("sys").platform.startswith("linux"):
        assert r.stdout.strip() == b"/cwd"
    else:
        assert b"river-" in r.stdout


def test_env_is_merged_into_the_whitelist(sandbox, python_exe):
    r = sandbox.run(
        python_exe,
        ["-c", "import os; print(os.environ.get('RIVER_TEST'))"],
        env={"RIVER_TEST": "value-42"},
    )
    assert r.status == "AC"
    assert r.stdout.strip() == b"value-42"


def test_env_does_not_leak_the_host_environment(sandbox, python_exe):
    r = sandbox.run(
        python_exe,
        ["-c", "import os; print(len(os.environ))"],
        env={"RIVER_TEST": "1"},
    )
    assert r.status == "AC"
    # The environment block is a whitelist, not a copy of the host env.
    assert int(r.stdout.strip()) < 50


def test_stdin_bytes_are_fed(sandbox, python_exe):
    r = sandbox.run(
        python_exe,
        ["-c", "import sys; sys.stdout.write(sys.stdin.read())"],
        stdin=b"piped-input",
    )
    assert r.status == "AC"
    assert r.stdout == b"piped-input"


def test_stdin_file_is_fed(sandbox, python_exe, tmp_path):
    src = tmp_path / "input.bin"
    src.write_bytes(b"file-input")
    r = sandbox.run(
        python_exe,
        ["-c", "import sys; sys.stdout.write(sys.stdin.read())"],
        stdin_file=str(src),
    )
    assert r.status == "AC"
    assert r.stdout == b"file-input"


def test_stdin_and_stdin_file_are_mutually_exclusive(sandbox, python_exe, tmp_path):
    src = tmp_path / "input.bin"
    src.write_bytes(b"x")
    with pytest.raises(ValueError):
        sandbox.run(python_exe, ["-c", "pass"], stdin=b"a", stdin_file=str(src))


def test_stdout_file_keeps_the_full_stream(sandbox, python_exe, tmp_path):
    out = tmp_path / "full.out"
    r = sandbox.run(
        python_exe,
        ["-c", "import sys; sys.stdout.write('z' * 5000); sys.stdout.flush()"],
        stdout_limit_kb=1,
        stdout_file=str(out),
    )
    assert r.status == "OLE"  # past the kill threshold
    assert r.stdout_truncated
    assert len(r.stdout) == 1024
    # The archive holds everything written before the kill.
    assert out.stat().st_size >= 1024


def test_exactly_at_the_stdout_limit_is_ac(sandbox, python_exe):
    r = sandbox.run(
        python_exe,
        ["-c", "import sys; sys.stdout.write('z' * 1024); sys.stdout.flush()"],
        stdout_limit_kb=1,
    )
    assert r.status == "AC"
    assert not r.stdout_truncated
    assert len(r.stdout) == 1024


def test_stderr_limit_is_independent(sandbox, python_exe):
    r = sandbox.run(
        python_exe,
        ["-c", "import sys; sys.stderr.write('e' * 4096); sys.stderr.flush()"],
        stderr_limit_kb=1,
    )
    assert r.status == "OLE"
    assert r.stderr_truncated
    assert not r.stdout_truncated


@pytest.mark.skipif(
    not sys.platform.startswith("win"),
    reason="rootfs is rejected on Windows only; Linux supports it",
)
def test_rootfs_is_rejected_on_windows():
    with pytest.raises(ValueError):
        river.Sandbox(rootfs="/tmp")


def test_invalid_copy_in_key_raises(sandbox, python_exe):
    with pytest.raises(ValueError):
        sandbox.run(python_exe, ["-c", "pass"], copy_in={"../escape": b"x"})
    with pytest.raises(ValueError):
        sandbox.run(python_exe, ["-c", "pass"], copy_in={r"C:\abs": b"x"})


def test_with_block_never_suppresses_exceptions():
    sb = river.Sandbox()
    with pytest.raises(RuntimeError), sb:
        raise RuntimeError("boom")


def test_status_repr_mentions_the_verdict(sandbox, python_exe):
    r = sandbox.run(python_exe, ["-c", "pass"])
    assert "AC" in repr(r)


def test_the_working_directory_is_removed_after_the_run(sandbox, python_exe):
    import glob
    import tempfile

    pattern = os.path.join(tempfile.gettempdir(), "river-*")
    before = set(glob.glob(pattern))
    r = sandbox.run(python_exe, ["-c", "pass"])
    assert r.status == "AC"
    after = set(glob.glob(pattern))
    assert after - before == set(), "the per-run directory was left behind"


# ---------------------------------------------------------------------------
# copy_out: product recovery (collected after the run, never via links)
# ---------------------------------------------------------------------------


def test_copy_out_recovers_products(sandbox, python_exe, tmp_path):
    dst_file = tmp_path / "out" / "answer.txt"
    dst_dir = tmp_path / "out" / "tree"
    r = sandbox.run(
        python_exe,
        [
            "-c",
            (
                "from pathlib import Path\n"
                "Path('answer.txt').write_text('hello-product')\n"
                "Path('tree').mkdir()\n"
                "Path('tree/nested').mkdir()\n"
                "Path('tree/nested/x.bin').write_bytes(b'\\x01\\x02')\n"
            ),
        ],
        copy_out={
            "answer.txt": str(dst_file),
            "tree": str(dst_dir),
        },
    )
    assert r.status == "AC", r
    assert dst_file.read_text() == "hello-product"
    assert (dst_dir / "nested" / "x.bin").read_bytes() == b"\x01\x02"


def test_copy_out_missing_source_is_skipped(sandbox, python_exe, tmp_path):
    dst = tmp_path / "optional.txt"
    r = sandbox.run(
        python_exe, ["-c", "pass"], copy_out={"never-written.txt": str(dst)}
    )
    assert r.status == "AC", r
    assert not dst.exists()


def test_copy_out_quota_breach_is_ole(sandbox, python_exe, tmp_path):
    dst = tmp_path / "dump.bin"
    r = sandbox.run(
        python_exe,
        ["-c", "open('dump.bin', 'wb').write(b'x' * (64 * 1024))"],
        copy_out={"dump.bin": str(dst)},
        copy_out_limit_kb=1,
    )
    assert r.status == "OLE", r
    assert r.signal == 9
    assert not dst.exists(), "a file past the quota must not be collected"


def test_copy_out_within_quota_is_ac(sandbox, python_exe, tmp_path):
    dst = tmp_path / "small.txt"
    r = sandbox.run(
        python_exe,
        ["-c", "open('small.txt', 'wb').write(b'x' * 100)"],
        copy_out={"small.txt": str(dst)},
        copy_out_limit_kb=1,
    )
    assert r.status == "AC", r
    assert len(dst.read_bytes()) == 100


def test_invalid_copy_out_key_raises(sandbox, python_exe, tmp_path):
    with pytest.raises(ValueError):
        sandbox.run(
            python_exe, ["-c", "pass"], copy_out={"../escape": str(tmp_path / "x")}
        )
    with pytest.raises(ValueError):
        sandbox.run(
            python_exe, ["-c", "pass"], copy_out={r"C:\abs": str(tmp_path / "x")}
        )


def test_copy_in_directory_is_provisioned_recursively(sandbox, python_exe, tmp_path):
    src = tmp_path / "proj"
    (src / "data").mkdir(parents=True)
    (src / "config.txt").write_text("cfg")
    (src / "data" / "rows.csv").write_text("1,2,3")
    r = sandbox.run(
        python_exe,
        [
            "-c",
            (
                "from pathlib import Path\n"
                "print(Path('proj/config.txt').read_text())\n"
                "print(Path('proj/data/rows.csv').read_text())\n"
                "try:\n"
                "    Path('proj/config.txt').write_text('nope')\n"
                "except (PermissionError, OSError):\n"
                "    pass\n"
            ),
        ],
        copy_in={"proj": str(src)},
    )
    assert r.status == "AC", r
    assert r.stdout.decode().splitlines() == ["cfg", "1,2,3"]
