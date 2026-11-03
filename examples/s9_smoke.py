"""S9 smoke: watchdog + TLE/MLE complete verdicts.

Acceptance cases from docs/windows-backend.md S9 row:
    while(1) -> TLE, sleep(inf) -> TLE, malloc bomb -> MLE
Run: uv run python examples/s9_smoke.py
"""

import sys
import river

EXE = sys.executable
RUNTIMES = [sys.prefix, sys.base_prefix, sys.executable.rsplit("\\python.exe", 1)[0]]


def run(code, time_limit_ms=None, wall_time_limit_ms=None, memory_limit_kb=None):
    with river.Sandbox(runtimes=RUNTIMES) as sb:
        r = sb.run(
            EXE,
            ["-c", code],
            time_limit_ms=time_limit_ms,
            wall_time_limit_ms=wall_time_limit_ms,
            memory_limit_kb=memory_limit_kb,
        )
    return r


def check(name, r, expect, extra=""):
    ok = r.status == expect
    print(
        f"[{'OK' if ok else 'FAIL'}] {name}: status={r.status} (want {expect}) "
        f"signal={r.signal} exit={r.exit_code} cpu={r.time_used_ms}ms "
        f"wall={r.wall_time_used_ms}ms mem={r.memory_used_kb}KB {extra}"
    )
    return ok


def main():
    results = []
    # 1. busy loop, CPU + wall limits -> TLE
    results.append(check(
        "while(1)",
        run("while True: pass", time_limit_ms=1000),
        "TLE",
    ))
    # 2. sleep forever, only wall limit -> TLE (watchdog catches idle hang)
    results.append(check(
        "sleep(inf)",
        run("import time; time.sleep(3600)", wall_time_limit_ms=1500),
        "TLE",
    ))
    # 3. malloc bomb, 256MB commit cap -> MLE (not RE from the crash code)
    results.append(check(
        "malloc bomb",
        run(
            "b = bytearray()\n"
            "try:\n"
            "    while True:\n"
            "        b += b'x' * (16 << 20)\n"
            "except MemoryError:\n"
            "    while True:\n"
            "        b += bytearray(1 << 20)\n",
            memory_limit_kb=256 * 1024,
            wall_time_limit_ms=20000,
        ),
        "MLE",
    ))
    # 4. sane program under a tight-but-adequate memory cap stays AC
    results.append(check(
        "small alloc stays AC",
        run("b = bytearray(1 << 20); print(len(b))",
            memory_limit_kb=64 * 1024, wall_time_limit_ms=10000),
        "AC",
    ))
    print("S9 smoke:", "ALL PASS" if all(results) else "FAILURES PRESENT")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
