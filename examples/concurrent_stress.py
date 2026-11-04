"""Stress: 8-way concurrency x 50 rounds + timing-jitter baseline.

Verifies:
1. 8 threads x 50 rounds of concurrent runs — every run must produce a
   sane verdict (AC for the sample program), no SE, no exceptions.
2. Timing jitter baseline: wall-time measurements of a fixed program are
   stable enough to be usable as a limit reference (the documented
   5-10% relaxation on Windows).
3. No leftover working directories after the stress run.

Run: uv run python examples/concurrent_stress.py
"""

import glob
import os
import statistics
import sys
import threading
import time

EXE = sys.executable
RUNTIMES = [sys.prefix, sys.base_prefix, EXE.rsplit("\\python.exe", 1)[0]]
TEMP = os.environ["TEMP"]


def river_dirs():
    return {d for d in glob.glob(os.path.join(TEMP, "river-*")) if os.path.isdir(d)}


def main():
    import river

    threads_n = 8
    rounds = 50
    results = []
    errors = []
    lock = threading.Lock()

    sb = river.Sandbox(runtimes=RUNTIMES)
    before_dirs = river_dirs()

    def worker(i):
        local = []
        local_err = []
        for r in range(rounds):
            try:
                st = sb.run(EXE, ["-c", "print('ok')"], wall_time_limit_ms=30000)
                local.append(st.status)
                if st.status != "AC":
                    local_err.append((i, r, st.status, st.stderr[:200]))
            except Exception as e:  # noqa: BLE001
                local_err.append((i, r, "EXC", f"{type(e).__name__}: {e}".encode()))
        with lock:
            results.extend(local)
            errors.extend(local_err)

    t0 = time.time()
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(threads_n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.time() - t0

    total = threads_n * rounds
    ok = len(results) == total and not errors
    print(f"[{'OK' if ok else 'FAIL'}] stress {threads_n}x{rounds}: "
          f"{total} runs in {elapsed:.1f}s ({elapsed/total*1000:.0f} ms/run), "
          f"non-AC={len(errors)}")
    for e in errors[:5]:
        print("   ", e)

    # --- leftover directories ------------------------------------------
    leftover = river_dirs() - before_dirs
    print(f"[{'OK' if not leftover else 'FAIL'}] no leftover workdirs: {leftover}")

    # --- timing jitter baseline ----------------------------------------
    # A fixed program (busy loop of known duration) measured 11 times (the
    # first is a warm-up and is discarded). The baseline describes the
    # *typical* measurement spread, so it is measured as the median
    # absolute deviation from the median — a single host hiccup (Defender
    # scan, scheduler, another process) must not fail the baseline.
    #
    # The outlier count is reported separately: it is a property of the
    # host, not of the sandbox.
    samples = []
    for i in range(11):
        st = sb.run(EXE, ["-c", ("import time\nt=time.perf_counter()\n"
                                 "while time.perf_counter()-t < 0.30: pass")],
                    wall_time_limit_ms=30000)
        if i:  # skip the warm-up sample
            samples.append(st.wall_time_used_ms)
    samples.sort()
    median = statistics.median(samples)
    mad = statistics.median([abs(s - median) for s in samples])
    mad_pct = mad / median * 100 if median else 0.0
    outliers = [s for s in samples if s > median * 1.5]
    jitter_ok = mad_pct <= 10.0
    print(f"[{'OK' if jitter_ok else 'FAIL'}] timing jitter: "
          f"median={median}ms mad={mad_pct:.1f}% "
          f"min={samples[0]} max={samples[-1]} outliers={len(outliers)}")
    print(f"    samples: {samples}")

    all_ok = ok and not leftover and jitter_ok
    print("concurrency stress:", "ALL PASS" if all_ok else "FAILURES PRESENT")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
