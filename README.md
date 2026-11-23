# river

river is a Python library that runs arbitrary programs inside a rootless Linux
sandbox built around a caller-supplied rootfs, and reports judge-grade resource
usage and verdicts (`AC` / `RE` / `TLE` / `MLE` / `OLE`).

**Status: in development.** This tree is the skeleton of the rootless rewrite.
The design in [docs/design.md](docs/design.md) is the single source of truth;
[docs/development-plan.md](docs/development-plan.md) holds the implementation
plan and PR breakdown, and [docs/example.py](docs/example.py) is the target API.

- **rootless**: no root, no setuid helper, no external binary — only the current
  user and the kernel.
- **low overhead**: single-digit milliseconds per `exec`; no daemon, no polling.
- **limits and accounting**: CPU time, wall clock, memory, output, process
  count; `None` means unlimited.
- **latest kernels only** (≥ 6.8), no compatibility fallbacks.

## Development

Linux only. Build and test as the unprivileged user that will run river, with
the process inside a delegated cgroup:

```sh
uv sync --extra test && uv run maturin develop
systemd-run --user --scope -p Delegate=yes -- .venv/bin/python -c "import river; print(river.doctor())"
systemd-run --user --scope -p Delegate=yes --setenv=RIVER_TEST_ROOTFS=<rootfs> -- .venv/bin/python -m pytest -x
```

Put the interpreter itself inside the scope: a wrapper that stays alive (`uv run`,
`make`, …) leaves a second process in the cgroup and river cannot enable the
controllers there (`river.doctor()` reports exactly that).

`river.doctor()` reports every kernel, user-namespace and cgroup prerequisite
and the fix for anything that fails. The rootfs is a directory exported from a
container image and unpacked as the running user; see design.md §11.
