"""Probe: each thread builds its own Sandbox (concurrent stale-dir sweeps).

The sweep walks the shared temp dir; concurrent sweeps must be serialized,
not surface as ERROR_SHARING_VIOLATION.

Run: uv run python examples/concurrent_sandbox_probe.py
"""

import os
import sys
import threading

EXE = sys.executable
RUNTIMES = [sys.prefix, sys.base_prefix, EXE.rsplit("\\python.exe", 1)[0]]


def main():
    import river
    errors = []
    statuses = []
    lock = threading.Lock()

    def worker(i):
        try:
            # Each thread constructs its own Sandbox -> concurrent sweeps.
            sb = river.Sandbox(runtimes=RUNTIMES)
            for _ in range(10):
                r = sb.run(EXE, ["-c", "print('ok')"], wall_time_limit_ms=30000)
                with lock:
                    statuses.append(r.status)
                    if r.status != "AC":
                        errors.append(r.stderr.decode(errors="replace")[:200])
        except Exception as e:  # noqa: BLE001
            with lock:
                errors.append(f"{type(e).__name__}: {e}")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    print(f"runs={len(statuses)} non-AC/err={len(errors)}")
    for e in errors[:5]:
        print("   ", e)
    ok = len(statuses) == 80 and not errors
    print("per-thread Sandbox:", "ALL PASS" if ok else "FAILURES PRESENT")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
