# river

Cross-platform sandbox for running untrusted executables with resource limits,
as a Python extension implemented in Rust.

```shell
uv tool install maturin
uv run maturin develop
uv run ./examples/example.py
```

## Documentation

- [DESIGN.md](DESIGN.md) — frozen API contract and the unified cross-platform
  model (private cwd + read-only runtimes + copy_in + env)
- [docs/windows-backend.md](docs/windows-backend.md) — Windows backend
  technical design (AppContainer + Job Object + mitigation policies),
  verdict semantics, decision log and implementation history

## Status

| Area | Linux | macOS | Windows |
|---|---|---|---|
| Implementation | planned | planned | **done** (AppContainer + Job Object) |
| Tests | — | — | 53 Rust unit tests + 59 pytest tests |

## Windows capability matrix

Everything below is verified by the test suite
(`tests/test_functional.py`, `tests/test_attack.py`, `tests/test_limits.py`).

### Isolation

| Capability | Mechanism | Verified by |
|---|---|---|
| Identity | AppContainer (`PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`), profile `river.sandbox` | `test_attack.py` (file/registry/network denials) |
| Filesystem | private writable cwd per run; `runtimes` read-only via ACE grants | `test_functional.py::test_cwd_is_inside_the_sandbox` |
| Network | denied by default (no capability) | `test_attack.py::test_outbound_network_is_denied` |
| Registry | denied (HKCU/HKLM) | `test_attack.py::test_registry_write_is_denied` |
| Kernel attack surface | `WIN32K_SYSTEM_CALL_DISABLE` + `EXTENSION_POINT_DISABLE` | `test_attack.py::test_win32k_calls_are_denied` / `..._gui_and_shutdown_apis_are_unreachable` |
| Process tree | Job Object: max 64 live processes, `KILL_ON_JOB_CLOSE` | `test_attack.py::test_fork_bomb_is_bounded` |
| Residual children | killed + verdict `SE` (anti-cheat) | `test_attack.py::test_residual_children_are_reported_as_se` |
| Judger death | `KILL_ON_JOB_CLOSE` reaps the tree; stale dirs swept | `test_attack.py::test_an_interrupted_judger_leaves_no_orphan_process` |

### Limits and verdicts

| Limit | Parameter | Verdict |
|---|---|---|
| CPU time | `time_limit_ms` | `TLE` |
| Wall clock | `wall_time_limit_ms` (default `2 × time_limit + 1000`) | `TLE` |
| Memory (commit) | `memory_limit_kb` | `MLE` |
| stdout / stderr | `stdout_limit_kb` / `stderr_limit_kb` (kill threshold) | `OLE` |

Verdicts: `AC` (clean exit), `TLE`, `MLE`, `OLE`, `RE` (non-zero exit or
abnormal termination), `SE` (sandbox anomaly). `signal` is synthesized (`9`
when the sandbox killed the process), `exit_code` is the raw code — an NTSTATUS
on abnormal Windows termination.

### Known limitations (Windows, first version)

- `rootfs` is not supported on Windows (processes always resolve system DLLs
  from the real `System32`) — use `runtimes` instead.
- Network access cannot be allowed yet (always denied).
- `copy_in` files are read-only for the program (no writable allowlist yet).
- Memory limits apply to *commit*, not RSS — a large `malloc` that is never
  written does not trigger `MLE`.
- Child processes are allowed by design (ordinary wrappers must work); the
  guarantees are the 64-process cap and residual detection (`SE`).
- Timing jitter on Windows is larger than on Linux (measured MAD 0–0.5% for
  a 300ms program, but the host occasionally hiccups); allow 5-10% when
  using limits as thresholds.
- Ordinary Win32 GUI programs can put windows on the user's desktop
  (isolation via a private desktop is not implemented).
- `ctypes` cannot be loaded inside the sandbox (a side effect of the win32k
  lockdown) — programs depending on ctypes/PowerShell/CLR fail at load time.

## Testing

```shell
uv sync --extra test
uv run maturin develop
uv run pytest                          # python suite (functional / attack / limits)
cargo test --lib -- --test-threads=1   # rust unit tests
```

The Python suite runs real programs inside the sandbox, so each test costs a
process spawn. `examples/` additionally holds per-step smoke scripts
(`s7_smoke.py` … `s12_stress.py`) used during development.
