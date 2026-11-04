"""Cleanup & lifecycle tests for the Linux backend.

What is asserted here (mirroring docs/windows-backend.md §7 item 9):

- a hard-killed judger leaves no sandboxed processes behind (PDEATHSIG chain
  + pid-namespace init death);
- directories/cgroups abandoned by a dead judger are reclaimed by the next
  sandbox's sweep;
- one `Sandbox` is safe to use from several threads at once.

Every probe is non-trivial: removing the mechanism under test (PDEATHSIG,
the sweep, the per-run cgroup) must make the corresponding test fail.
"""

from __future__ import annotations

import glob
import os
import subprocess
import sys
import tempfile
import time

import pytest

import river

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="Linux-specific lifecycle probes",
)

RUNTIMES = sorted(
    {
        os.path.dirname(sys.executable),
        sys.prefix,
        getattr(sys, "base_prefix", sys.prefix),
    }
)


def _marker_processes(marker: str) -> list[int]:
    """Host pids whose command line contains `marker`."""
    found = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/cmdline", "rb") as f:
                cmdline = f.read()
        except OSError:
            continue
        if marker.encode() in cmdline:
            found.append(int(entry))
    return found


def _wait_until(predicate, timeout: float, interval: float = 0.05) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def test_stale_workdir_from_a_dead_judger_is_swept(tmp_path):
    # A directory whose owner pid cannot exist any more (max pid) plus a
    # live-looking one owned by this process: only the dead one may go.
    dead = os.path.join(tempfile.gettempdir(), "river-4194303-0-dead")
    os.makedirs(dead, exist_ok=True)
    with open(os.path.join(dead, "junk"), "w") as f:
        f.write("x")

    live = os.path.join(tempfile.gettempdir(), f"river-{os.getpid()}-0-live")
    os.makedirs(live, exist_ok=True)

    with river.Sandbox():
        pass

    assert not os.path.exists(dead), "stale workdir was not swept"
    assert os.path.exists(live), "sweep removed a directory of a live owner"
    os.rmdir(live)


def test_stale_cgroup_from_a_dead_judger_is_swept():
    base = "/sys/fs/cgroup/river"
    if not os.path.isdir(base):
        pytest.skip("cgroups v2 river root not created yet (needs one run)")
    dead = os.path.join(base, "run-4194303-0")
    os.makedirs(dead, exist_ok=True)
    with river.Sandbox():
        pass
    assert not os.path.exists(dead), "stale cgroup was not swept"


def _run_cgroups() -> set[str]:
    return set(glob.glob("/sys/fs/cgroup/river/run-*"))


def test_sweep_does_not_kill_a_live_run_in_another_thread(sandbox, python_exe):
    """Regression: a live cgroup must be flock-owned, so the sweep skips it.

    Before the owner lock existed, `with river.Sandbox(): pass` in one thread
    reclaimed every cgroup it could open — including the one of a run that was
    still executing in another thread (observed: a 6s run died after ~30ms
    with `RE`/`SE`).
    """
    import threading

    result = {}

    def go():
        result["r"] = sandbox.run(
            python_exe,
            ["-c", "import time; time.sleep(3); print('slept')"],
            time_limit_ms=20000,
            wall_time_limit_ms=30000,
        )

    before = _run_cgroups()
    thread = threading.Thread(target=go)
    thread.start()
    try:
        assert _wait_until(lambda: bool(_run_cgroups() - before), 10), (
            "the run never created a cgroup"
        )
        # __enter__ runs the stale-cgroup sweep: the live run must survive.
        with river.Sandbox(runtimes=RUNTIMES):
            pass
        thread.join(60)
        r = result["r"]
        assert r.status == "AC", f"live run was disturbed: {r.status} {r.stderr[:400]}"
        assert r.wall_time_used_ms >= 2500, (
            f"live run was reaped early: {r.wall_time_used_ms}ms"
        )
    finally:
        thread.join(5)


def test_sweep_in_another_process_does_not_kill_a_live_run(tmp_path):
    """Two judge processes share the cgroup tree: neither may reap the other.

    The sweep must identify a live owner by the flock, not by "I could open
    the directory" — otherwise every worker's `with Sandbox()` kills the runs
    of every other worker.
    """
    script = tmp_path / "judger.py"
    script.write_text(
        "import sys\n"
        "import river\n"
        f"sb = river.Sandbox(runtimes={RUNTIMES!r})\n"
        "with sb:\n"
        "    r = sb.run(sys.executable,\n"
        "               ['-c', 'import time; time.sleep(4); print(\"slept\")'],\n"
        "               time_limit_ms=30000, wall_time_limit_ms=40000)\n"
        "    print('RESULT', r.status, r.wall_time_used_ms, flush=True)\n"
    )
    before = _run_cgroups()
    proc = subprocess.Popen(
        [sys.executable, str(script)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        assert _wait_until(lambda: bool(_run_cgroups() - before), 15), (
            "the child judger never created a cgroup"
        )
        # Our own sweep must leave the child's live run alone.
        with river.Sandbox(runtimes=RUNTIMES):
            pass
        out, _ = proc.communicate(timeout=60)
        line = [ln for ln in out.splitlines() if ln.startswith("RESULT")]
        assert line, out
        assert " AC " in line[0], f"live run in another process was killed: {line[0]}"
    finally:
        if proc.poll() is None:
            proc.kill()


def test_hard_killed_judger_leaves_no_processes_and_is_reclaimed():
    marker = f"river-lifecycle-{os.getpid()}"
    judger = os.path.join(tempfile.gettempdir(), f"river-judger-{os.getpid()}.py")
    with open(judger, "w") as f:
        f.write(
            "import sys\n"
            "import river\n"
            f"sb = river.Sandbox(runtimes={RUNTIMES!r})\n"
            "with sb:\n"
            "    sb.run(sys.executable,\n"
            f"           ['-c', 'import time; time.sleep(120)  # {marker}'],\n"
            "           wall_time_limit_ms=120000)\n"
        )

    proc = subprocess.Popen([sys.executable, judger])
    try:
        # Wait until the sandboxed program is actually running.
        assert _wait_until(lambda: bool(_marker_processes(marker)), 15), (
            "sandboxed program never started"
        )
        # Hard-kill the judger: Drop never runs, PDEATHSIG must clean up.
        proc.kill()
        proc.wait()
        assert _wait_until(lambda: not _marker_processes(marker), 10), (
            "sandboxed process survived the judger's death"
        )
        # Run a fresh sandbox: its __enter__ sweep must reclaim the dead
        # judger's directory (the run's own Drop never executed). The stale
        # directory is owned by the killed judger's pid.
        prefix = f"river-{proc.pid}-"
        left_before = set(glob.glob(os.path.join(tempfile.gettempdir(), "river-*")))
        stale_before = {d for d in left_before if os.path.basename(d).startswith(prefix)}
        assert stale_before, f"expected a stale workdir for pid {proc.pid}: {left_before}"
        with river.Sandbox():
            pass
        still_there = {d for d in stale_before if os.path.exists(d)}
        assert not still_there, f"stale directories were not reclaimed: {still_there}"
    finally:
        if proc.poll() is None:
            proc.kill()
        try:
            os.remove(judger)
        except OSError:
            pass


def test_concurrent_runs_on_one_sandbox_are_isolated(sandbox, python_exe):
    import concurrent.futures

    code = (
        "import os, sys\n"
        "open('own.txt', 'w').write(sys.argv[1])\n"
        "data = open('own.txt').read()\n"
        "print(os.getpid(), data)\n"
    )

    def one(i: int):
        return sandbox.run(python_exe, ["-c", code, f"task-{i}"]), i

    # 16 concurrent runs (8 workers) on one frozen Sandbox: every run must
    # see its own private cwd and its own cgroup.
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(one, range(16)))

    for r, i in results:
        assert r.status == "AC", (i, r.status, r.stderr[:400])
        pid, data = r.stdout.split()
        assert data == f"task-{i}".encode()
        assert pid.decode().isdigit()


def test_repeated_runs_leak_nothing(sandbox, python_exe):
    """A burst of runs leaves no workdirs, cgroups or sandbox processes.

    This is the Linux version of the M6 "no leaks after N runs" check,
    scaled to a CI-friendly N.
    """
    before_dirs = set(glob.glob(os.path.join(tempfile.gettempdir(), "river-*")))
    cgroup_base = "/sys/fs/cgroup/river"
    before_cgroups = (
        set(os.listdir(cgroup_base)) if os.path.isdir(cgroup_base) else set()
    )
    runs = 30
    for i in range(runs):
        r = sandbox.run(python_exe, ["-c", f"print({i})"])
        assert r.status == "AC", (i, r.status, r.stderr[:200])

    after_dirs = set(glob.glob(os.path.join(tempfile.gettempdir(), "river-*")))
    after_cgroups = (
        set(os.listdir(cgroup_base)) if os.path.isdir(cgroup_base) else set()
    )
    leaked_dirs = {d for d in after_dirs - before_dirs if "river-" in os.path.basename(d)}
    # Ignore artifacts this test itself wrote (judger script files).
    leaked_dirs = {d for d in leaked_dirs if os.path.isdir(d)}
    assert leaked_dirs == set(), f"leaked work directories: {leaked_dirs}"
    assert after_cgroups == before_cgroups, (
        f"leaked cgroups: {after_cgroups - before_cgroups}"
    )
