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

## Status

| Platform | Status |
|---|---|
| Windows | ✅ implemented (AppContainer + Job Object) |
| Linux | 待更新 |
| macOS | 待更新 |

Windows is the current target; the other platforms follow the same model and
are updated later.

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

## Testing

```shell
uv sync --extra test
uv run maturin develop
uv run pytest                          # python suite (functional / attack / limits)
cargo test --lib -- --test-threads=1   # rust unit tests
```
