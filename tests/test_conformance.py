"""Cross-platform conformance suite: the frozen API contract, every backend.

These tests are deliberately **platform-neutral**: no NTSTATUS, no
AppContainer, no cgroup — only what DESIGN.md §2 freezes as the caller's
contract. The same file must run unchanged on Windows, Linux and macOS as
each backend lands, so a semantic divergence shows up as a red test here
rather than as two quietly different sandboxes.

What is *not* here on purpose:
- mechanism assertions (mitigation policies, ACLs, job limits) — those live
  in the per-backend Rust/Python suites;
- platform-behavior calibration (memory = commit vs RSS, timing jitter) —
  documented in DESIGN.md §5, not contractual.

Run: `uv run pytest tests/conformance.py -q`
"""

import pytest

import river

# ---------------------------------------------------------------------------
# river.capabilities() — the introspection contract
# ---------------------------------------------------------------------------

REQUIRED_CAPABILITY_KEYS = {
    "platform",
    "rootfs",
    "network_isolation",
    "concurrent_runs",
    "default_max_processes",
    "internal_wall_limit_secs",
}


def test_capabilities_has_the_frozen_keys():
    caps = river.capabilities()
    missing = REQUIRED_CAPABILITY_KEYS - set(caps)
    assert not missing, f"capabilities() is missing frozen keys: {missing}"


def test_capabilities_values_are_well_typed():
    caps = river.capabilities()
    assert caps["platform"] in ("windows", "linux", "macos")
    for key in ("rootfs", "network_isolation", "concurrent_runs"):
        assert isinstance(caps[key], bool), f"{key} must be bool"
    assert isinstance(caps["default_max_processes"], int)
    assert caps["default_max_processes"] > 0
    assert isinstance(caps["internal_wall_limit_secs"], int)
    assert caps["internal_wall_limit_secs"] > 0


# ---------------------------------------------------------------------------
# run() — normal operation
# ---------------------------------------------------------------------------


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
    assert r.signal == 0


def test_status_is_always_a_frozen_verdict(sandbox, python_exe):
    r = sandbox.run(python_exe, ["-c", "pass"])
    assert r.status in ("AC", "TLE", "MLE", "OLE", "RE", "SE")


def test_stderr_is_captured_separately(sandbox, python_exe):
    r = sandbox.run(python_exe, ["-c", "import sys; sys.stderr.write('bad\\n')"])
    assert r.status == "AC"
    assert r.stderr.strip() == b"bad"
    assert r.stdout == b""


# ---------------------------------------------------------------------------
# copy_in — the read-only provisioning contract (DESIGN §3.3)
# ---------------------------------------------------------------------------


def test_copy_in_bytes_reach_the_program(sandbox, python_exe):
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


def test_copy_in_is_read_only_for_the_program(sandbox, python_exe):
    r = sandbox.run(
        python_exe,
        ["-c", "import sys\n"
               "try:\n"
               "    open(sys.argv[1], 'w').write('x')\n"
               "    print('MUTABLE')\n"
               "except OSError:\n"
               "    print('READONLY')\n",
         "in.txt"],
        copy_in={"in.txt": b"immutable"},
    )
    assert r.status == "AC"
    assert r.stdout.strip() == b"READONLY"


def test_copy_in_nested_paths_are_created(sandbox, python_exe):
    r = sandbox.run(
        python_exe,
        ["-c", "import sys; sys.stdout.write(open(sys.argv[1]).read())",
         "a/b/c.txt"],
        copy_in={"a/b/c.txt": b"nested"},
    )
    assert r.status == "AC"
    assert r.stdout == b"nested"


# ---------------------------------------------------------------------------
# filesystem & environment visibility
# ---------------------------------------------------------------------------


def test_cwd_is_inside_the_private_sandbox(sandbox, python_exe):
    import os
    import sys

    r = sandbox.run(python_exe, ["-c", "import os; print(os.getcwd())"])
    assert r.status == "AC"
    # The cwd is the private per-run directory, never the host cwd. Its
    # *name* is backend-specific: Windows names the temp dir `river-*`,
    # Linux exposes it at the fixed sandbox path `/cwd`.
    out = r.stdout.strip()
    assert out != os.getcwd().encode()
    if sys.platform.startswith("linux"):
        assert out == b"/cwd", out
    else:
        assert b"river-" in out


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


# ---------------------------------------------------------------------------
# stdin
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# output limits: kill threshold / full archive / truncated sample
# ---------------------------------------------------------------------------


def test_stdout_limit_kills_with_ole_and_keeps_the_archive(
    sandbox, python_exe, tmp_path
):
    out = tmp_path / "full.out"
    r = sandbox.run(
        python_exe,
        ["-c", "import sys; sys.stdout.write('z' * 5000); sys.stdout.flush()"],
        stdout_limit_kb=1,
        stdout_file=str(out),
    )
    assert r.status == "OLE"
    assert r.signal == 9  # the sandbox killed the process
    assert r.stdout_truncated
    assert len(r.stdout) == 1024
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


# ---------------------------------------------------------------------------
# limits
# ---------------------------------------------------------------------------


def test_wall_timeout_is_tle_with_signal_9(sandbox, python_exe):
    r = sandbox.run(
        python_exe,
        ["-c", "import time; time.sleep(30)"],
        wall_time_limit_ms=500,
    )
    assert r.status == "TLE"
    assert r.signal == 9


# ---------------------------------------------------------------------------
# validation & lifecycle
# ---------------------------------------------------------------------------


def test_invalid_copy_in_keys_raise(sandbox, python_exe):
    with pytest.raises(ValueError):
        sandbox.run(python_exe, ["-c", "pass"], copy_in={"../escape": b"x"})
    # A Windows drive prefix is rejected on every platform (the frozen rule
    # is "no `..` components, no drive colon"; a bare POSIX `/abs` is only
    # absolute on POSIX, so it belongs in the per-backend suite instead).
    with pytest.raises(ValueError):
        sandbox.run(python_exe, ["-c", "pass"], copy_in={"C:\\abs": b"x"})


def test_rootfs_follows_the_capability_matrix():
    caps = river.capabilities()
    if caps["rootfs"]:
        pytest.skip("backend supports rootfs; rejection cannot be tested here")
    with pytest.raises(ValueError):
        river.Sandbox(rootfs="/tmp/whatever")


def test_with_block_never_suppresses_exceptions():
    sb = river.Sandbox()
    with pytest.raises(RuntimeError):
        with sb:
            raise RuntimeError("boom")


def test_the_working_directory_is_removed_after_the_run(sandbox, python_exe):
    import glob
    import os
    import tempfile

    pattern = os.path.join(tempfile.gettempdir(), "river-*")
    before = set(glob.glob(pattern))
    r = sandbox.run(python_exe, ["-c", "pass"])
    assert r.status == "AC"
    after = set(glob.glob(pattern))
    assert after - before == set(), "the per-run directory was left behind"


def test_status_repr_mentions_the_verdict(sandbox, python_exe):
    r = sandbox.run(python_exe, ["-c", "pass"])
    assert "AC" in repr(r)
