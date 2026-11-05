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
- [docs/windows-backend.md](docs/windows-backend.md) — Windows backend
  mechanisms (AppContainer + Job Object + mitigation policies)
- [docs/linux-backend.md](docs/linux-backend.md) — Linux backend mechanisms
  (namespaces + pivot_root + cgroups v2 + watchdog)

## Status

| Platform | Status |
|---|---|
| Windows | ✅ implemented (AppContainer + Job Object) |
| Linux | ✅ implemented (namespaces + pivot_root + cgroups v2) |
| macOS | not implemented |

Both backends share the same frozen contract (`tests/test_conformance.py` runs
unchanged on both); platform-specific probes live in `tests/test_attack.py`
(Windows) and `tests/test_attack_linux.py` / `tests/test_cleanup_linux.py`
(Linux). `rootfs` is supported on Linux (read-only overlayfs root
replacement) and rejected on Windows; `capabilities()["rootfs"]` reflects
this.

## Windows capability matrix

Everything below is verified by the test suite
(`tests/test_functional.py`, `tests/test_attack.py`, `tests/test_limits.py`).

### Isolation

| Capability | Mechanism |
|---|---|
| Identity | AppContainer (per-run profile slot `river.sandbox.<session>.<slot>`) |
| Filesystem | private writable cwd per run; `runtimes` read-only via ACE grants |
| Network | denied by default (no capability) |
| Registry | reads are visible (documented info exposure); writes denied (HKCU/HKLM) |
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
- Registry **reads** are visible to the sandboxed program: an AppContainer
  without capabilities can still read HKLM/HKCU keys (installed software,
  `ProductId`, `HKCU\Environment`, `RecentDocs`). Writes are denied. Closing
  this would need host-side ACL/capability changes, so treat the sandbox as
  protecting files and processes, not registry metadata.
- `copy_in` files are immutable in content for the program (a protected
  read-only DACL: the inherited write ACE would otherwise let the program
  clear the read-only attribute and rewrite its input). The program may still
  delete/rename an entry inside its own cwd — that changes nothing it reads
  and cannot leak; see DESIGN §3.3.
- AppContainer profiles come from a fixed slot pool (at most 60 per
  session, `river.sandbox.<session>.<slot>`; see
  `capabilities()["max_concurrent_runs"]`). Each run leases a slot
  exclusively and its `%LOCALAPPDATA%\Packages\<profile>\AC` folder is wiped
  before and after the run, so no file survives between runs. A run blocks
  while every slot is leased (concurrency is capped at the pool size, which
  is what a judge needs). A pre-1.0 installation may still have the legacy
  `river.sandbox` profile folder — delete it once when upgrading.
- Memory limits apply to *commit*, not RSS — a large `malloc` that is never
  written does not trigger `MLE`.
- The memory limit is enforced both per process and for the whole process
  tree (`JobMemoryLimit`): a multi-process program's total commit counts
  against the same `memory_limit_kb` budget (same semantics as the Linux
  cgroup).
- `stdout_limit_kb=None` does not mean unbounded: the returned sample is
  capped at the internal 64 MiB/channel ceiling (`*_truncated` set), and
  `*_file` archives stop at 1 GiB/channel (`*_file_truncated` set).
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
| Identity | per-run leased uid/gid (`[100000, 100064)` by default) + empty capability sets + `no_new_privs` + non-dumpable |
| Filesystem | mount namespace + `pivot_root` into a per-run tmpfs; `runtimes` and the system dirs bind-mounted read-only with `nosuid,nodev` |
| Network | always denied (unconditional): empty network namespace — no interfaces at all (loopback included) |
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
| Collected output | `copy_out_limit_kb` | total `copy_out` bytes measured by the collector; collection stops (no partial files) | `OLE` |
| File writes | — | `RLIMIT_FSIZE` 64 MB per file | `RE` on `SIGXFSZ`/`EFBIG` |
| Open files | — | `RLIMIT_NOFILE` 1024 | `RE` |
| stdout / stderr | `stdout_limit_kb` / `stderr_limit_kb` | pipe readers + kill threshold | `OLE` |

Executables that live outside every mounted runtime/system directory are
bind-mounted read-only into the sandbox at `/cwd/.river/<name>` and executed
from there, so `executable` really is a host path.

**`rootfs` mode** (`Sandbox(rootfs=<host dir>)`): the sandbox root is replaced
by a caller-supplied, self-contained root tree — mounted read-only via
overlayfs (the host tree is the lower layer and is never written, not even
mountpoint directories), with `runtimes` layered on top and `/cwd` the only
writable place. The host system directories are *not* merged in, and
`executable` becomes a path **inside the rootfs** (e.g. `/usr/bin/python3`).
The rootfs may also be a **squashfs image file** (verified by magic,
attached to a free loop device and mounted read-only; released with the
run). Requires overlayfs (universal on kernels ≥ 5.9); rootfs paths must
not contain `,` or `:`.

**Product recovery** (`copy_out`): sandbox-relative paths are collected to
host destinations after the run — recursively for directories, **never
following symlinks** (the collector runs as root; a program-planted link
is an exfiltration channel, so links are skipped). `copy_out_limit_kb`
caps the total collected bytes: the breach stops the collection (no
partial files) and the verdict is `OLE`. `copy_in` values also accept a
host directory (provisioned recursively, links skipped).

### Startup check

`Sandbox(...)` fails closed when a mechanism is missing (no cgroups v2, no
`memory.max`/`memory.peak`/`memory.swap.max`, no seccomp). `river.doctor()`
returns the same facts for deployment diagnosis.

### Known limitations

- With `rootfs=` the caller's tree must be self-contained (dynamic loader,
  libc, shell); nothing from the host is merged in. `executable` is resolved
  inside the rootfs, and rootfs paths containing `,`/`:` are rejected.
- Requires cgroups v2 (`/sys/fs/cgroup`) and Linux 5.9+ (`close_range`);
  `memory.peak`/`memory.swap.max` require 5.19+/5.0+. `rootfs=` additionally
  requires overlayfs.
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
- The workdir is 0700 owned by the run's leased uid; `copy_in` entries are
  root-owned 0444/0755, so the program can read but never chmod or overwrite
  them. The program still owns the workdir root, so it can delete/rename an
  entry in its own cwd (content cannot be changed). Each run leases an
  exclusive uid from a fixed high range (`RIVER_UID_BASE`/`RIVER_UID_COUNT`,
  default `[100000, 100064)`), so **other runs and unrelated host processes
  are locked out** — the old fixed `nobody` identity let any same-uid host
  process read *and overwrite* a live run's workdir (verified). The pool
  blocks when exhausted, like the Windows slot pool; `doctor()` fails
  construction if the range collides with an account in `/etc/passwd`.

## Testing

**Every commit must pass `cargo fmt` first** (run `cargo fmt` before `git
commit`; unformatted code must not be committed).

```shell
uv sync --extra test
uv run maturin develop
uv run pytest                          # python suite (functional / attack / limits)
cargo test --lib -- --test-threads=1   # rust unit tests
```

On Windows, `cargo test --lib` links against the CPython DLL: put the
interpreter's directory on `PATH` first (e.g.
`$env:PATH = "$(Split-Path (python -c 'import sys; print(sys.executable)'));$env:PATH"`),
otherwise the test binary exits with `STATUS_DLL_NOT_FOUND` (0xc0000135).

On Linux the suite must run as root (`sudo -E uv run pytest`), because the
sandbox itself needs `CAP_SYS_ADMIN`.
