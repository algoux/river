"""Limit tests: every limit in the frozen contract behaves as specified.

Covers DESIGN.md §2.2 / §2.3:
- CPU time limit -> TLE
- wall clock limit -> TLE (including a *sleeping* program the CPU limit
  cannot catch)
- memory limit -> MLE (commit semantics on Windows)
- stdout/stderr limits -> OLE (kill threshold) with truncation flags
- `None` means "no caller limit" (the internal safety ceilings still exist)
- the wall limit defaults to `2 * time_limit + 1000` when only a CPU limit
  is given
- signal is synthesized (9 for sandbox kills, 0 otherwise)
"""

import time

import pytest

import river


def test_cpu_limit_produces_tle(sandbox, python_exe):
    r = sandbox.run(python_exe, ["-c", "while True: pass"], time_limit_ms=500)
    assert r.status == "TLE"
    assert r.signal == 9


def test_wall_limit_catches_a_sleeping_program(sandbox, python_exe):
    # The CPU limit cannot see a sleeping program; the wall watchdog must.
    r = sandbox.run(
        python_exe,
        ["-c", "import time; time.sleep(30)"],
        wall_time_limit_ms=1000,
    )
    assert r.status == "TLE"
    assert r.signal == 9


def test_the_wall_limit_defaults_to_twice_the_cpu_limit(sandbox, python_exe):
    # time_limit_ms=500 -> default wall = 2*500 + 1000 = 2000ms.
    r = sandbox.run(python_exe, ["-c", "while True: pass"], time_limit_ms=500)
    assert r.status == "TLE"
    assert r.wall_time_used_ms < 10_000, r.wall_time_used_ms


def test_memory_limit_produces_mle(sandbox, python_exe):
    code = (
        "b = bytearray()\n"
        "try:\n"
        "    while True:\n"
        "        b += b'x' * (16 << 20)\n"
        "except MemoryError:\n"
        "    while True:\n"
        "        b += bytearray(1 << 20)\n"
    )
    r = sandbox.run(python_exe, ["-c", code],
                    memory_limit_kb=256 * 1024, wall_time_limit_ms=20000)
    assert r.status == "MLE"
    assert r.signal == 9


def test_memory_usage_is_reported(sandbox, python_exe):
    r = sandbox.run(
        python_exe,
        ["-c", "x = bytearray(32 << 20)"],
        memory_limit_kb=256 * 1024,
        wall_time_limit_ms=20000,
    )
    assert r.status == "AC"
    assert r.memory_used_kb > 1024, r.memory_used_kb


def test_stdout_limit_kills_and_truncates(sandbox, python_exe):
    code = "import sys\nwhile True:\n    sys.stdout.write('x' * 65536)\n    sys.stdout.flush()\n"
    r = sandbox.run(python_exe, ["-c", code],
                    stdout_limit_kb=64, wall_time_limit_ms=15000)
    assert r.status == "OLE"
    assert r.signal == 9
    assert r.stdout_truncated
    assert len(r.stdout) == 64 * 1024


def test_stderr_limit_kills_and_truncates(sandbox, python_exe):
    code = "import sys\nwhile True:\n    sys.stderr.write('e' * 65536)\n    sys.stderr.flush()\n"
    r = sandbox.run(python_exe, ["-c", code],
                    stderr_limit_kb=64, wall_time_limit_ms=15000)
    assert r.status == "OLE"
    assert r.stderr_truncated
    assert len(r.stderr) == 64 * 1024


def test_exactly_at_the_limit_is_not_a_kill(sandbox, python_exe):
    code = "import sys; sys.stdout.write('x' * 1024); sys.stdout.flush()"
    r = sandbox.run(python_exe, ["-c", code], stdout_limit_kb=1)
    assert r.status == "AC"
    assert not r.stdout_truncated


def test_no_limits_means_the_program_finishes(sandbox, python_exe):
    r = sandbox.run(python_exe, ["-c", "print('done')"])
    assert r.status == "AC"
    assert r.stdout.strip() == b"done"


def test_a_generous_memory_limit_does_not_trip_mle(sandbox, python_exe):
    r = sandbox.run(python_exe, ["-c", "x = bytearray(8 << 20)"],
                    memory_limit_kb=512 * 1024, wall_time_limit_ms=20000)
    assert r.status == "AC"


def test_the_wall_limit_is_respected_within_tolerance(sandbox, python_exe):
    limit_ms = 800
    t0 = time.perf_counter()
    r = sandbox.run(python_exe, ["-c", "import time; time.sleep(30)"],
                    wall_time_limit_ms=limit_ms)
    elapsed_ms = (time.perf_counter() - t0) * 1000
    assert r.status == "TLE"
    # The kill must happen close to the limit (Windows timing jitter is
    # documented at 5-10%; allow generous slack for process startup).
    assert elapsed_ms < limit_ms + 3000, elapsed_ms


def test_cpu_time_is_reported_separately_from_wall_time(sandbox, python_exe):
    r = sandbox.run(python_exe, ["-c", "import time; time.sleep(1)"],
                    wall_time_limit_ms=10000)
    assert r.status == "AC"
    assert r.wall_time_used_ms >= 900, r.wall_time_used_ms
    # A sleeping program burns almost no CPU.
    assert r.time_used_ms < r.wall_time_used_ms, (
        r.time_used_ms, r.wall_time_used_ms
    )


def test_a_burning_program_reports_cpu_time(sandbox, python_exe):
    r = sandbox.run(python_exe, ["-c", "x = 0\nfor i in range(20_000_000): x += i"],
                    wall_time_limit_ms=10000)
    assert r.status == "AC"
    assert r.time_used_ms > 0, r.time_used_ms


def test_exit_code_is_passed_through(sandbox, python_exe):
    r = sandbox.run(python_exe, ["-c", "raise SystemExit(42)"])
    assert r.status == "RE"
    assert r.exit_code == 42


def test_an_abnormal_termination_is_re(sandbox, python_exe):
    # A NULL dereference surfaces as an NTSTATUS exit code.
    code = "import ctypes\nctypes.string_at(0)\n"
    r = sandbox.run(python_exe, ["-c", code])
    assert r.status == "RE"
    # Either the process died with an NTSTATUS or the interpreter trapped it.
    assert r.exit_code != 0
