"""Linux rootfs tests: a caller-supplied root tree replaces the sandbox root.

Contract (DESIGN §1/§2.1):

  - `river.capabilities()["rootfs"]` is True on Linux; passing `rootfs=` to
    `Sandbox` is accepted there and rejected on the other platforms.
  - With `rootfs=`, the sandbox root is the caller's tree, mounted
    **read-only** (overlayfs: the host tree is the lower layer and is never
    written — not even mountpoint directories are created inside it). The
    host system directories are *not* merged; the rootfs must be
    self-contained.
  - `runtimes` are still layered on top, read-only.
  - `executable` is a path *inside the rootfs* (e.g. `/bin/sh`).
  - The only writable place stays the per-run `/cwd`.

Like the other Linux suites this must run as **root**
(`sudo -E uv run pytest tests/test_rootfs_linux.py`).
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import sys

import pytest

import river

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="Linux-specific rootfs suite",
)

#: Host directories hardlinked into the fixture rootfs (those the current
#: non-rootfs backend bind-mounts as the "System32 is readable" rule).
SYSTEM_DIRS = ("/bin", "/sbin", "/lib", "/lib64", "/usr", "/etc")


def _copy_tree(src: str, dst: str, _seen: set[str] | None = None) -> None:
    """Copy `src` to `dst` with hardlinks where possible, falling back to
    real copies across filesystems (a judger rootfs fixture is disposable;
    a debootstrap-style tree is all we need). Symlinked directories (Ubuntu's
    merged-usr: /bin -> usr/bin) are copied by *content*, because absolute
    symlinks would resolve inside the rootfs and dangle there."""
    if _seen is None:
        _seen = set()
    real = os.path.realpath(src)
    if real in _seen:  # symlink cycle guard
        return
    _seen = _seen | {real}
    mode = stat.S_IMODE(os.stat(src).st_mode)
    try:
        os.mkdir(dst, mode)
    except FileExistsError:
        pass
    for name in os.listdir(src):
        s = os.path.join(src, name)
        d = os.path.join(dst, name)
        try:
            st = os.lstat(s)
            if stat.S_ISLNK(st.st_mode):
                target = os.readlink(s)
                resolved = os.path.realpath(s)
                if os.path.isdir(resolved):
                    # Absolute dir symlink (/bin -> /usr/bin): materialize
                    # the content, or it would dangle inside the rootfs.
                    _copy_tree(resolved, d, _seen)
                else:
                    os.symlink(target, d)
            elif stat.S_ISDIR(st.st_mode):
                _copy_tree(s, d, _seen)
            else:
                try:
                    os.link(s, d)
                except OSError:
                    shutil.copy2(s, d, follow_symlinks=False)
        except OSError:
            # Skip entries a disposable fixture cannot reproduce (agent
            # sockets, dangling special files); the rootfs only needs the
            # loader/libc/shell closure anyway.
            continue


@pytest.fixture(scope="module")
def rootfs(tmp_path_factory):
    """A minimal but self-contained root tree: the host system dirs,
    hardlinked (cheap on the same filesystem)."""
    base = tmp_path_factory.mktemp("rootfs")
    root = base / "root"
    root.mkdir()
    for d in SYSTEM_DIRS:
        if os.path.isdir(d):  # follows merged-usr symlinks (/bin -> usr/bin)
            _copy_tree(d, str(root / d.strip("/")))
    os.makedirs(root / "home", exist_ok=True)
    return root


def _snapshot(root) -> dict[str, str]:
    """Cheap integrity fingerprint of the fixture rootfs (names + hashes of
    the small files a test could try to tamper with)."""
    out: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ("usr", "lib", "lib64")]
        for name in filenames:
            p = os.path.join(dirpath, name)
            try:
                with open(p, "rb") as f:
                    out[p] = hashlib.sha256(f.read(4096)).hexdigest()
            except OSError:
                continue
    return out


# ---------------------------------------------------------------------------
# capabilities & construction
# ---------------------------------------------------------------------------


def test_linux_reports_rootfs_capability():
    caps = river.capabilities()
    assert caps["platform"] == "linux"
    assert caps["rootfs"] is True


def test_invalid_rootfs_paths_are_rejected(rootfs):
    with pytest.raises(ValueError):
        river.Sandbox(rootfs="relative/path")
    with pytest.raises(ValueError):
        river.Sandbox(rootfs="/")
    with pytest.raises(ValueError):
        river.Sandbox(rootfs=str(rootfs / "does-not-exist"))


# ---------------------------------------------------------------------------
# basic execution in rootfs coordinates
# ---------------------------------------------------------------------------


def _sb(rootfs, runtime=None):
    runtimes = [runtime] if runtime else None
    sb = river.Sandbox(rootfs=str(rootfs), runtimes=runtimes)
    sb.__enter__()
    return sb


def test_sh_runs_from_rootfs(rootfs):
    with _sb(rootfs) as sb:
        r = sb.run("/bin/sh", ["-c", "echo from-rootfs"])
        assert r.status == "AC", r
        assert r.stdout.strip() == b"from-rootfs", r


def test_executable_outside_rootfs_fails(rootfs):
    # `/nonexistent` is not in the rootfs: exec fails, it is *not* silently
    # injected from the host (the rootfs defines what is executable).
    # A spawn/exec failure surfaces as `SE` per the frozen contract.
    with _sb(rootfs) as sb:
        r = sb.run("/nonexistent/river-probe", [])
        assert r.status == "SE", r


def test_host_filesystem_is_invisible(rootfs, tmp_path):
    secret = tmp_path / "host-secret.txt"
    secret.write_bytes(b"host-only")
    with _sb(rootfs) as sb:
        r = sb.run(
            "/bin/sh",
            ["-c", "ls /; test -d /tmp && echo TMP_VISIBLE || echo TMP_ABSENT"],
        )
        assert r.status == "AC", r
        assert b"TMP_ABSENT" in r.stdout, r
        assert b"TMP_VISIBLE" not in r.stdout, r
        names = set(r.stdout.decode().split())
        # rootfs contents + the sandbox layout, nothing else from the host.
        expected = {d.strip("/") for d in SYSTEM_DIRS if os.path.isdir(d)}
        expected |= {"cwd", "proc", "dev", "home", "TMP_ABSENT"}
        assert names <= expected, f"unexpected root entries: {names - expected}"


def test_rootfs_is_read_only(rootfs):
    with _sb(rootfs) as sb:
        r = sb.run("/bin/sh", ["-c", "echo tampered > /etc/river-tamper && echo WROTE"])
        assert r.status == "RE", r  # EROFS: read-only filesystem
        assert b"WROTE" not in r.stdout, r
    # ...and the host tree really was not touched.
    assert not (rootfs / "etc" / "river-tamper").exists()


def test_cwd_is_the_only_writable_place(rootfs):
    with _sb(rootfs) as sb:
        r = sb.run("/bin/sh", ["-c", "echo persisted > /cwd/f && cat /cwd/f"])
        assert r.status == "AC", r
        assert r.stdout.strip() == b"persisted", r
        # copy_in lands in /cwd as usual (host path value, sandbox key).
        r = sb.run("/bin/sh", ["-c", "cat in.txt"], copy_in={"in.txt": b"copied"})
        assert r.status == "AC" and r.stdout == b"copied", r


# ---------------------------------------------------------------------------
# runtimes layer on top of the rootfs
# ---------------------------------------------------------------------------


def test_runtimes_overlay_onto_rootfs(rootfs, tmp_path):
    rt = tmp_path / "runtime"
    rt.mkdir()
    (rt / "marker.txt").write_bytes(b"runtime-marker")
    with _sb(rootfs, runtime=str(rt)) as sb:
        # The runtime is mounted at its own absolute path (in rootfs view
        # coordinates, provisioned in the overlay upper layer).
        r = sb.run("/bin/sh", ["-c", f"cat {rt}/marker.txt"])
        assert r.status == "AC" and r.stdout.strip() == b"runtime-marker", r
        # ...and it is read-only, like every runtime mount.
        r = sb.run(
            "/bin/sh",
            ["-c", f"echo x > {rt}/marker.txt 2>/dev/null && echo WROTE"],
        )
        assert r.status == "RE" or b"WROTE" not in r.stdout, r
    assert (rt / "marker.txt").read_bytes() == b"runtime-marker"


# ---------------------------------------------------------------------------
# the host rootfs is never modified
# ---------------------------------------------------------------------------


def test_host_rootfs_tree_is_never_written(rootfs):
    before = _snapshot(rootfs)
    with _sb(rootfs) as sb:
        # Try the plausible escapes: write system files, create the dirs a
        # naive implementation would need as mountpoints.
        probes = [
            "echo x > /etc/passwd",
            "echo x > /bin/river-tamper",
            "mkdir /proc2",
            "echo x > /cwd/../river-leak",
            "rm -f /etc/hostname",
        ]
        for code in probes:
            sb.run("/bin/sh", ["-c", f"{code} 2>/dev/null; true"])
    after = _snapshot(rootfs)
    assert before == after, "the host rootfs tree was modified"
    # No stray files or leftover mountpoint dirs either.
    assert not (rootfs / "river-leak").exists()
    assert not (rootfs / "proc2").exists()


# ---------------------------------------------------------------------------
# squashfs image rootfs
# ---------------------------------------------------------------------------


def _mksquashfs_available() -> bool:
    import shutil

    return shutil.which("mksquashfs") is not None


@pytest.mark.skipif(not _mksquashfs_available(), reason="mksquashfs not installed")
def test_squashfs_image_rootfs(rootfs, tmp_path):
    import subprocess

    image = tmp_path / "root.sqsh"
    subprocess.run(
        ["mksquashfs", str(rootfs), str(image), "-noappend", "-no-progress"],
        check=True,
        capture_output=True,
    )
    before = image.stat().st_mtime_ns
    with _sb(image) as sb:
        r = sb.run("/bin/sh", ["-c", "echo from-squashfs; cat /etc/hostname 2>/dev/null; true"])
        assert r.status == "AC", r
        assert b"from-squashfs" in r.stdout, r
        # The image view is read-only like the directory rootfs.
        r = sb.run("/bin/sh", ["-c", "echo tampered > /etc/river-tamper 2>/dev/null && echo WROTE"])
        assert r.status == "RE" or b"WROTE" not in r.stdout, r
        # /cwd stays writable.
        r = sb.run("/bin/sh", ["-c", "echo persisted > /cwd/f && cat /cwd/f"])
        assert r.status == "AC" and r.stdout.strip() == b"persisted", r
    assert image.stat().st_mtime_ns == before, "the image file must not be touched"
    # The loop device was released: a second run over the same image works.
    with _sb(image) as sb:
        r = sb.run("/bin/sh", ["-c", "echo second-run"])
        assert r.status == "AC" and b"second-run" in r.stdout, r


def test_non_squashfs_image_is_rejected(rootfs, tmp_path):
    fake = tmp_path / "fake.sqsh"
    fake.write_bytes(b"definitely not a squashfs image" * 4)
    with _sb(fake) as sb:
        r = sb.run("/bin/sh", ["-c", "echo hi"])
        assert r.status == "SE", r  # bad magic → spawn fails closed


# ---------------------------------------------------------------------------
# limits still bind in rootfs mode
# ---------------------------------------------------------------------------


def test_time_limit_still_enforced(rootfs):
    with _sb(rootfs) as sb:
        r = sb.run("/bin/sh", ["-c", "while true; do :; done"], time_limit_ms=300)
        assert r.status == "TLE", r
        assert r.signal == 9, r
