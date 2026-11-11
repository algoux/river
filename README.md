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

`rootfs=` accepts a caller-supplied container root: a directory is mounted
writable-side-up via `overlayfs` (private tmpfs upper layer, host tree stays
frozen read-only), a squashfs image (detected by the `hsqs` magic) is attached
through a loop device and used as the read-only lower layer. In `rootfs=` mode
the host system directories are not mounted in; the root must be self-contained
(`runtimes=[...]` still composes, mounted at `/runtime/<name>`).

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
