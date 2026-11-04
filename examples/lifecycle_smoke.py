"""Lifecycle smoke: exception paths + __exit__ hardening.

1. Killing the judger process tree mid-run leaves no orphan sandboxed
   processes (KILL_ON_JOB_CLOSE reaps them) while the per-run directory
   remains (Drop never ran).
2. The next Sandbox construction sweeps that abandoned directory.
3. Foreign / unparseable `river-*` dirs are untouched by the sweep
   (unit-tested too; repeated here end to end).

NOTE on pids: the venv `python.exe` is a launcher — the pid Popen returns is
not the pid of the interpreter (and thus not the pid our Rust code uses for
the per-run dir name). We therefore diff-glob the temp dir to find the
per-run dir and read its owner pid from the name.

Run: uv run python examples/lifecycle_smoke.py
"""

import glob
import os
import subprocess
import sys
import tempfile
import time

EXE = sys.executable
RUNTIMES = [sys.prefix, sys.base_prefix, EXE.rsplit("\\python.exe", 1)[0]]
TEMP = os.environ["TEMP"]


def check(name, cond, detail):
    print(f"[{'OK' if cond else 'FAIL'}] {name}: {detail}")
    return cond


def river_dirs():
    return {d for d in glob.glob(os.path.join(TEMP, "river-*")) if os.path.isdir(d)}


def sandboxed_python_cmdlines():
    """Command lines of running python.exe processes (PowerShell CIM)."""
    ps = (
        "Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" "
        "| ForEach-Object { $_.CommandLine }"
    )
    out = subprocess.run(["powershell", "-NoProfile", "-c", ps],
                         capture_output=True, text=True).stdout
    return [l for l in out.splitlines() if "sleep(60)" in l]


def main():
    import river
    results = []

    # --- 1. hard-kill the judger process tree mid-run --------------------
    judger_code = f"""
import river, sys, time
sb = river.Sandbox(runtimes={RUNTIMES!r})
with sb:
    r = sb.run(r'''{EXE}''', ['-c', 'import time; time.sleep(60)'],
               wall_time_limit_ms=60000)
    print('RUNNING', r.status, flush=True)
    time.sleep(60)
"""
    src = os.path.join(TEMP, "river-s11-judger.py")
    with open(src, "w") as f:
        f.write(judger_code)

    before = river_dirs()
    judger = subprocess.Popen([EXE, src], stderr=subprocess.PIPE)
    deadline = time.time() + 30
    new_dirs = set()
    while time.time() < deadline:
        new_dirs = river_dirs() - before
        if new_dirs or judger.poll() is not None:
            break
        time.sleep(0.2)
    if not new_dirs:
        err = judger.stderr.read().decode(errors="replace") if judger.poll() is not None else ""
        print(f"[FAIL] no per-run dir appeared; judger rc={judger.poll()}\n{err}")
        judger.kill()
        sys.exit(1)
    results.append(check(
        "judger mid-run with a per-run dir",
        True,
        f"new dir(s)={sorted(new_dirs)}",
    ))

    subprocess.run(["taskkill", "/PID", str(judger.pid), "/T", "/F"],
                   capture_output=True)
    judger.wait()
    time.sleep(2.0)  # give KILL_ON_JOB_CLOSE a moment

    results.append(check(
        "hard-killed judger: no orphan sandboxed python",
        not sandboxed_python_cmdlines(),
        f"orphans={sandboxed_python_cmdlines()}",
    ))

    # --- 2. the next Sandbox construction sweeps the residue -------------
    owner_pid = int(os.path.basename(sorted(new_dirs)[0]).split("-")[1])
    residue = sorted(d for d in new_dirs if os.path.isdir(d)
                     and os.path.basename(d).startswith(f"river-{owner_pid}-"))
    river.Sandbox()  # sweeps stale dirs
    results.append(check(
        "next Sandbox sweeps abandoned dirs",
        all(not os.path.isdir(d) for d in residue),
        f"residue before sweep={residue}, "
        f"still there={[d for d in residue if os.path.isdir(d)]}",
    ))

    # --- 3. unrelated river-* dirs are untouched by the sweep ------------
    foreign = os.path.join(TEMP, "river-not-a-judger-dir")
    os.makedirs(foreign, exist_ok=True)
    river.Sandbox()
    results.append(check(
        "sweep leaves foreign river-* dirs alone",
        os.path.isdir(foreign),
        f"{foreign} still present",
    ))
    os.rmdir(foreign)

    os.remove(src)
    print("lifecycle smoke:", "ALL PASS" if all(results) else "FAILURES PRESENT")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
