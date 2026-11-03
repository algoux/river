"""S10 smoke: OLE kill threshold + output archive/limit separation.

Run: uv run python examples/s10_smoke.py
"""

import sys
import river

EXE = sys.executable
RUNTIMES = [sys.prefix, sys.base_prefix, sys.executable.rsplit("\\python.exe", 1)[0]]


def run(code, stdout_limit_kb=None, wall_time_limit_ms=None):
    with river.Sandbox(runtimes=RUNTIMES) as sb:
        return sb.run(
            EXE,
            ["-c", code],
            stdout_limit_kb=stdout_limit_kb,
            wall_time_limit_ms=wall_time_limit_ms,
        )


def check(name, cond, detail):
    print(f"[{'OK' if cond else 'FAIL'}] {name}: {detail}")
    return cond


def main():
    results = []

    # 1. stdout fountain past the kill threshold -> reaped mid-run, OLE
    r = run("import sys\n"
            "while True:\n"
            "    sys.stdout.write('x' * 65536)\n"
            "    sys.stdout.flush()\n",
            stdout_limit_kb=64, wall_time_limit_ms=15000)
    results.append(check(
        "stdout fountain",
        r.status == "OLE" and r.signal == 9 and r.stdout_truncated
        and len(r.stdout) == 64 * 1024,
        f"status={r.status} signal={r.signal} exit={r.exit_code} "
        f"wall={r.wall_time_used_ms}ms truncated={r.stdout_truncated} "
        f"captured={len(r.stdout)}B",
    ))

    # 2. output is archived in stdout_file up to the kill; the returned
    #    sample stays capped at the limit. The program is reaped as soon as
    #    its total passes the threshold, so the archive holds >= 1 chunk.
    import os, tempfile
    path = os.path.join(tempfile.gettempdir(), "river-s10-ole-full.bin")
    with river.Sandbox(runtimes=RUNTIMES) as sb:
        r = sb.run(EXE, ["-c", "import sys\n"
                            "for _ in range(4):\n"
                            "    sys.stdout.write('y' * 65536)\n"
                            "    sys.stdout.flush()\n"],
                   stdout_limit_kb=64, stdout_file=path,
                   wall_time_limit_ms=15000)
    full = os.path.getsize(path)
    results.append(check(
        "full archive vs sample",
        r.status == "OLE" and full >= 65536 and full > len(r.stdout)
        and len(r.stdout) == 64 * 1024 and r.stdout_truncated,
        f"status={r.status} archive={full}B sample={len(r.stdout)}B "
        f"truncated={r.stdout_truncated}",
    ))
    os.remove(path)

    # 3. exactly at the limit (no more) stays AC — the threshold is strict
    r = run("import sys\nsys.stdout.write('z' * 65536)\nsys.stdout.flush()\n",
            stdout_limit_kb=64, wall_time_limit_ms=15000)
    results.append(check(
        "exactly-at-limit stays AC",
        r.status == "AC" and not r.stdout_truncated and len(r.stdout) == 65536,
        f"status={r.status} captured={len(r.stdout)}B truncated={r.stdout_truncated}",
    ))

    print("S10 smoke:", "ALL PASS" if all(results) else "FAILURES PRESENT")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
