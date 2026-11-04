# river

Sandbox for running untrusted executables with resource limits, as a Python
extension implemented in Rust.

```shell
uv tool install maturin
uv run maturin develop
uv run ./examples/example.py
```

## Documentation

- [DESIGN.md](DESIGN.md) — sandbox model, API contract, design decisions
- [docs/windows-backend.md](docs/windows-backend.md) — Windows backend details
  (AppContainer + Job Object + mitigation policies), decision log, pitfalls
- [docs/linux-backend.md](docs/linux-backend.md) — Linux backend details
  (namespaces + pivot_root + cgroups v2 + watchdog), decision log, pitfalls
- [docs/linux-plan.md](docs/linux-plan.md) — Linux backend development plan
  and progress log (frozen decisions, staged tasks L1–L6)

## Status

| Platform | Status |
|---|---|
| Windows | ✅ implemented (AppContainer + Job Object) |
| Linux | ✅ implemented (namespaces + pivot_root + cgroups v2) |
| macOS | 待更新 |

Both backends share the same frozen contract (`tests/test_conformance.py` runs
unchanged on both); platform-specific probes live in `tests/test_attack.py`
(Windows) and `tests/test_attack_linux.py` / `tests/test_cleanup_linux.py`
(Linux). The Linux backend is stage L5 of
[docs/linux-plan.md](docs/linux-plan.md); `rootfs` (stage L6) is not
implemented yet, so `capabilities()["rootfs"]` is `false`.

## Windows capability matrix

Everything below is verified by the test suite
(`tests/test_functional.py`, `tests/test_attack.py`, `tests/test_limits.py`).

### Isolation

| Capability | Mechanism |
|---|---|
| Identity | AppContainer (profile `river.sandbox`) |
| Filesystem | private writable cwd per run; `runtimes` read-only via ACE grants |
| Network | denied by default (no capability) |
| Registry | denied (HKCU/HKLM) |
| Kernel attack surface | win32k system calls + DLL-injection hook points disabled |
| Process tree | Job Object: max 64 live processes, `KILL_ON_JOB_CLOSE` |
| Residual children | killed + verdict `SE` (anti-cheat) |

### Limits and verdicts

| Limit | Parameter | Verdict |
|---|---|---|
| CPU time | `time_limit_ms` | `TLE` |
| Wall clock | `wall_time_limit_ms` (default `2 × time_limit + 1000`) | `TLE` |
| Memory (commit) | `memory_limit_kb` | `MLE` |
| stdout / stderr | `stdout_limit_kb` / `stderr_limit_kb` (kill threshold) | `OLE` |

`AC` clean exit · `TLE`/`MLE`/`OLE` limit exceeded · `RE` non-zero exit or
abnormal termination · `SE` sandbox anomaly. `signal` is synthesized (`9` when
the sandbox killed the process).

### Known limitations

- `rootfs` is not supported on Windows — use `runtimes`.
- Network access cannot be allowed (always denied).
- `copy_in` files are read-only for the program.
- Memory limits apply to *commit*, not RSS — a large `malloc` that is never
  written does not trigger `MLE`.
- Child processes are allowed by design; the guarantees are the 64-process cap
  and residual detection (`SE`).
- Timing jitter is larger than on Linux; allow 5-10% when using limits as
  thresholds.
- Ordinary Win32 GUI programs can put windows on the user's desktop.
- `ctypes` cannot be loaded inside the sandbox (a side effect of the win32k
  lockdown) — programs depending on ctypes/PowerShell/CLR fail at load time.

## Linux capability matrix

Verified by `tests/test_attack_linux.py` + `tests/test_cleanup_linux.py` +
the shared conformance suite, all run as **root** (namespaces, mounts and
cgroup writes need `CAP_SYS_ADMIN`).

### Isolation

| Capability | Mechanism |
|---|---|
| Identity | uid/gid drop to `nobody` + empty capability sets + `no_new_privs` + non-dumpable |
| Filesystem | mount namespace + `pivot_root` into a per-run tmpfs; `runtimes` and the system dirs bind-mounted read-only with `nosuid,nodev` |
| Network | empty network namespace: no interfaces at all (loopback included) |
| Process namespace | pid / cgroup namespaces: the program is PID 1, host pids and the host cgroup tree are invisible |
| System calls | seccomp-bpf allowlist, default-deny with `EPERM` (no sockets, no userns/mount/ptrace/keyctl/io_uring/flock side channels) |
| Process tree | cgroup `pids.max` + `kill(-pgid)` + `cgroup.kill` |
| Judger death | watchdog process kills the supervisor's group; flock-owned workdirs/cgroups are reclaimed by the next sweep |
| Host metadata | UTS hostname fixed to `river` |

### Limits and verdicts

| Limit | Parameter | Mechanism | Verdict |
|---|---|---|---|
| CPU time | `time_limit_ms` | `cpu.stat usage_usec` polled every 10 ms, killed at the limit; `RLIMIT_CPU` backstop | `TLE` |
| Wall clock | `wall_time_limit_ms` (default `2 × time_limit + 1000`) | 2 ms poll watchdog | `TLE` |
| Memory (RSS + page cache) | `memory_limit_kb` | cgroup `memory.max` + `memory.swap.max=0`; OOM kills read from `memory.events` and exposed as `Status.oom_killed` | `MLE` |
| File writes | — | `RLIMIT_FSIZE` 64 MB per file | `RE` on `SIGXFSZ`/`EFBIG` |
| Open files | — | `RLIMIT_NOFILE` 1024 | `RE` |
| stdout / stderr | `stdout_limit_kb` / `stderr_limit_kb` | pipe readers + kill threshold | `OLE` |

Executables that live outside every mounted runtime/system directory are
bind-mounted read-only into the sandbox at `/cwd/.river/<name>` and executed
from there, so `executable` really is a host path.

### Startup check

`Sandbox(...)` fails closed when a mechanism is missing (no cgroups v2, no
`memory.max`/`memory.peak`/`memory.swap.max`, no seccomp). `river.doctor()`
returns the same facts for deployment diagnosis.

### Known limitations

- `rootfs` is not implemented yet (stage L6): `capabilities()["rootfs"]` is
  false and passing `rootfs=` raises `ValueError`.
- Requires cgroups v2 (`/sys/fs/cgroup`) and Linux 5.9+ (`close_range`);
  `memory.peak`/`memory.swap.max` require 5.19+/5.0+.
- Memory limits are RSS + page cache — reading a large file counts against
  the limit (unlike the Windows commit semantics).
- `cwd` itself is a host directory: `RLIMIT_FSIZE` bounds a single file, but
  total `cwd` usage is not capped by the sandbox.
- The host `/etc` is bind-mounted read-only (whole directory); see
  docs/linux-backend.md for the exposure this implies.
- A signal-terminated process reports `exit_code = 128 + signo` (e.g. 137 for
  an OOM kill); the `signal` field stays synthesized (9 for sandbox kills).
- Children are allowed (bounded by `pids.max`); a program that hands work to
  a child which would outlive it cannot: the pid namespace kills descendants
  when the main process exits.

## Testing

**Every commit must pass `cargo fmt` first** (run `cargo fmt` before `git
commit`; unformatted code must not be committed).

```shell
uv sync --extra test
uv run maturin develop
uv run pytest                          # python suite (functional / attack / limits)
cargo test --lib -- --test-threads=1   # rust unit tests
```

On Linux the suite must run as root (`sudo -E uv run pytest`), because the
sandbox itself needs `CAP_SYS_ADMIN`.
