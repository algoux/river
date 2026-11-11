# river

A cross-platform sandbox for running untrusted programs: a `Sandbox` Python
class that executes a child with verdict-grade limits and accounting
(`AC` / `RE` / `TLE` / `MLE` / `OLE`), output capture, and file copy in/out.

## Backends

| Platform | Mechanism |
|----------|-----------|
| Linux | PID/mount/UTS/IPC/network namespaces + `pivot_root`, cgroups v2 (cpu/memory/pids), seccomp denylist, pidfd control. Needs root on a cgroups v2 host; every `exec` requires an active session. |
| Windows | AppContainer + Job Object; `runtimes=[...]` grants read-only directories. |
| macOS | Not implemented yet. |

## Linux sandbox layout (per run)

```
/                       tmpfs (per-run)
├── workspace/          the session workdir (rw): cwd, copy_in/out, TMPDIR
├── proc/               new procfs for the private PID namespace
├── dev/                tmpfs with null/zero/random/urandom
├── runtime/<name>/     caller runtime dirs (ro)
└── usr bin sbin lib lib64 etc   host system dirs (ro)
```

`rootfs=` (a caller-supplied container root) is planned; the current backend
rejects it.

## Testing

```shell
uv sync --extra test
uv run maturin develop
uv run pytest
```

Linux tests run as root on the target host; Windows tests skip elsewhere and
vice versa.

## Examples

See `examples/` for standalone demos of the underlying mechanisms
(clone3/pidfd, namespaces, pivot_root, cgroups v2, seccomp, output capture)
on each platform.
