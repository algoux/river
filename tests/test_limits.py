"""Resource limits and the TLE/MLE/OLE verdicts (marker: limits).

development-plan.md §4, PR 3: every limit parameter takes effect and the
verdict ladder (design.md §6: OLE > MLE > TLE > AC/RE) classifies runs the
judge-grade way. Needs a delegated cgroup and RIVER_TEST_ROOTFS, like the
functional group; memory sizes stay small for the 1.6 GB remote machine.
"""

from __future__ import annotations

import glob
import os
import threading
import time
from pathlib import Path

import pytest

from river import CopyOutError

from conftest import cgroup_base, delegated

pytestmark = [
    pytest.mark.limits,
    pytest.mark.skipif(
        not delegated(),
        reason="not in a delegated cgroup; run under systemd-run --user --scope -p Delegate=yes",
    ),
]

MB = 1024 * 1024


def py(river_, code: str, **kwargs):
    """One `python -c <code>` run with limit kwargs."""
    return river_.exec("python", ["-c", code], **kwargs)


# ---------------------------------------------------------------------- TLE


def test_cpu_deadloop_is_tle(river_):
    # cpu=1000, wall=5000 (development-plan.md §4): RLIMIT_CPU soft=1s sends
    # SIGXCPU (24); if pid 1 of the namespace drops it, the hard limit kills
    # at 9 — and the post-run cpu.stat check marks TLE either way.
    result = py(river_, "while True: pass", cpu_time_limit_ms=1000, wall_time_limit_ms=5000)
    assert result.status == "TLE", (result.error, result.stderr)
    assert result.signal in (24, 9)
    assert result.exit_code is None
    assert result.cpu_time_used_ms >= 900
    assert result.error is not None and "cpu" in result.error


def test_wall_deadline_is_tle(river_):
    result = py(river_, "import time; time.sleep(10)", wall_time_limit_ms=300)
    assert result.status == "TLE", (result.error,)
    assert result.signal == 9
    assert result.exit_code is None
    assert 250 <= result.wall_time_used_ms <= 5000
    assert result.error is not None and "wall" in result.error


# ---------------------------------------------------------------------- MLE


def test_memory_exceeded_is_mle(river_):
    # 256 MB against memory.max=64 MB with memory.oom.group=1: the kernel
    # OOM-kills the whole cgroup (design.md §6).
    result = py(river_, "a = bytearray(256 * 1024 * 1024)", memory_limit_bytes=64 * MB)
    assert result.status == "MLE", (result.error,)
    assert result.signal == 9
    assert result.memory_used_bytes >= 64 * MB
    assert result.error is not None and "memory" in result.error.lower()


# ---------------------------------------------------------------------- OLE


def test_stdout_over_limit_is_ole(river_):
    result = py(
        river_,
        "import sys; sys.stdout.buffer.write(b'x' * (1024 * 1024))",
        stdout_limit_bytes=64 * 1024,
    )
    assert result.status == "OLE", (result.error,)
    assert result.stdout == b"x" * 64 * 1024
    assert result.error is not None and "stdout" in result.error


def test_stdout_file_over_limit_is_ole(river_):
    # The file branch (design.md §6): RLIMIT_FSIZE clamps the write at the
    # cap and returns EFBIG — and pid 1 of the namespace drops the kernel's
    # SIGXFSZ (SIGNAL_UNKILLABLE), so the writer dies of the OSError
    # traceback (exit 1) instead of the signal. The file sits exactly at
    # 64K on an unclean exit, which classify treats as over the cap.
    result = py(
        river_,
        "import sys; sys.stdout.buffer.write(b'x' * (1024 * 1024))",
        stdout_file="out.txt",
        stdout_limit_bytes=64 * 1024,
    )
    assert result.status == "OLE", (result.error, result.stderr)
    assert result.exit_code == 1
    assert result.signal is None


# ------------------------------------------------------------------ proc cap


def test_fork_bomb_is_capped_by_proc_limit(river_):
    # proc_limit=16 (pids.max + RLIMIT_NPROC): once the tree holds 16
    # processes os.fork() fails with EAGAIN, the parent notices, prints and
    # exits cleanly — the bomb never gets out (development-plan.md §4).
    result = py(
        river_,
        "import os\n"
        "made = 0\n"
        "for _ in range(500):\n"
        "    try:\n"
        "        pid = os.fork()\n"
        "    except OSError:\n"
        "        break\n"
        "    made += 1\n"
        "    if pid == 0:\n"
        "        import time; time.sleep(30)\n"
        "print('forks', made)\n",
        proc_limit=16,
    )
    assert result.status == "AC", (result.stdout, result.stderr, result.error)
    line = result.stdout.decode().strip()
    assert line.startswith("forks "), line
    made = int(line.split()[1])
    assert 1 <= made <= 60


# --------------------------------------------------------------- copy_out cap


def test_copy_out_over_limit_raises(river_):
    # copy_out_limit_bytes is enforced on the opened file (design.md §10);
    # the error carries the run that finished before copy_out.
    with pytest.raises(CopyOutError, match="copy_out_limit_bytes=65536") as info:
        py(
            river_,
            "open('big.txt', 'w').write('x' * (1024 * 1024))",
            copy_out={"big.txt": None},
            copy_out_limit_bytes=64 * 1024,
        )
    assert info.value.result.status == "AC"
    assert info.value.result.files == {}


# ------------------------------------------------ knob writes, live observation


def _run_and_watch(river_, **kwargs):
    """Runs one sleeping exec in a thread and reads the live run cgroup's
    knobs once the child is attached — `cgroup.procs` non-empty means every
    knob was already written (design.md §3 steps 2/6)."""
    out = {}

    def target():
        out["result"] = py(river_, "import time; time.sleep(1.0)", **kwargs)

    thread = threading.Thread(target=target)
    thread.start()
    pattern = str(cgroup_base() / f"river-{os.getpid()}-*")
    knobs = None
    while knobs is None and thread.is_alive():
        for run_dir in glob.glob(pattern):
            try:
                procs = (Path(run_dir) / "cgroup.procs").read_text().split()
            except OSError:
                continue
            if procs:
                knobs = {
                    name: (Path(run_dir) / name).read_text().strip()
                    for name in (
                        "memory.max",
                        "memory.swap.max",
                        "memory.oom.group",
                        "pids.max",
                    )
                }
                break
        if knobs is None:
            time.sleep(0.02)
    thread.join()
    return out["result"], knobs


def test_unlimited_knobs_stay_at_defaults(river_):
    # development-plan.md PR 3 completion criterion: a limit of None never
    # writes its knob — the cgroup files stay at their defaults.
    result, knobs = _run_and_watch(river_)
    assert result.status == "AC", (result.error,)
    assert knobs is not None, "the live run cgroup was never observed"
    assert knobs["memory.max"] == "max"
    assert knobs["memory.swap.max"] == "max"
    assert knobs["memory.oom.group"] == "0"
    assert knobs["pids.max"] == "max"


def test_set_limits_write_their_knobs(river_):
    result, knobs = _run_and_watch(river_, memory_limit_bytes=32 * MB, proc_limit=16)
    assert result.status == "AC", (result.stderr, result.error)
    assert knobs is not None, "the live run cgroup was never observed"
    assert knobs["memory.max"] == str(32 * MB)
    assert knobs["memory.swap.max"] == "0"
    assert knobs["memory.oom.group"] == "1"
    assert knobs["pids.max"] == "16"
