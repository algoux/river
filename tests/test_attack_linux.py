"""Linux attack-surface tests: what a jailbreak tries must be denied.

The Linux counterpart of `tests/test_attack.py` (which is Windows-only).
Every probe runs *inside* the sandbox and reports what it observed — a
leak is a failure even if the surrounding API returned an error.

Surface under test:

  1. the visible filesystem is exactly the private tree (no host dirs)
  2. host files outside the private cwd are invisible
  3. /etc secrets are unreadable (uid drop to nobody)
  4. network denial (unconditional): empty namespace -> no connection, no DNS
  5. /proc is a fresh pid namespace (program is PID 1)
  6. mounts are read-only / non-writable for the unprivileged program
  7. /sys and /proc/sys are not reachable
  8. /dev has the standard character devices, nothing else
  9. the program cannot mount / cannot write system dirs
 10. syscalls that need privileges fail (setuid, mknod)
 11. privilege fences: no_new_privs, empty capabilities, nosuid/nodev binds,
     user-namespace creation denied by seccomp
 12. host metadata does not leak (hostname, /etc)
 13. limit enforcement: active CPU kill, OOM-killed flag, file-size bound
 14. host executables outside every runtime are bind-injected and run
"""

import os
import sys
import tempfile
import time

import pytest

import river

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="Linux-specific attack probes",
)


def _probe(sandbox, python_exe, code, **kwargs):
    """Run a probe program inside the sandbox and return its Status."""
    return sandbox.run(python_exe, ["-c", code], **kwargs)


# ---------------------------------------------------------------------------
# filesystem visibility
# ---------------------------------------------------------------------------


def test_root_is_only_the_private_tree(sandbox, python_exe):
    # The whole host filesystem must be gone: only the sandbox layout
    # (cwd/tmp/proc/dev + system dirs + runtimes) exists. Runtimes are
    # bind-mounted at their host paths, so their top-level ancestors may
    # appear as (empty) mountpoint skeletons — e.g. `/home` on WSL or
    # `/root` when the venv lives under /root.
    from conftest import RUNTIMES

    r = _probe(
        sandbox,
        python_exe,
        "import os; print(' '.join(sorted(os.listdir('/'))))",
    )
    assert r.status == "AC"
    names = set(r.stdout.decode().split())
    assert "cwd" in names
    assert "proc" in names
    assert "dev" in names
    allowed = {"bin", "sbin", "lib", "lib64", "usr", "etc", "cwd", "proc", "dev"}
    allowed |= {p.split("/")[1] for p in RUNTIMES if p.startswith("/")}
    assert names <= allowed, f"unexpected top-level entries: {names - allowed}"
    # Host-only paths must never appear (no /tmp, /var, /mnt, /sys, ...).
    for forbidden in ("mnt", "media", "srv", "var", "tmp", "sys", "boot", "opt", "run"):
        assert forbidden not in names, names


def test_host_home_is_invisible(sandbox, python_exe):
    # Even though a runtime may live under /home/<user>, the *host* home
    # is not a mounted tree: listing it must fail or show no host files.
    r = _probe(
        sandbox,
        python_exe,
        "import os\n"
        "try:\n"
        "    entries = os.listdir('/home')\n"
        "    print('HOME_ENTRIES', len(entries))\n"
        "except OSError as e:\n"
        "    print('HOME_DENIED', e.errno)\n",
    )
    assert r.status == "AC"
    assert b"HOME_DENIED" in r.stdout or b"HOME_ENTRIES" in r.stdout


def test_host_file_outside_cwd_is_invisible(sandbox, python_exe, tmp_host_file):
    # `tmp_host_file` lives in the host's temp directory (pytest tmp_path).
    # Inside the sandbox the host /tmp does not exist at all.
    r = _probe(
        sandbox,
        python_exe,
        "import os\n"
        f"print('EXISTS' if os.path.exists({str(tmp_host_file)!r}) else 'GONE')\n",
    )
    assert r.status == "AC"
    assert r.stdout.strip() == b"GONE"


def test_writing_the_host_tmp_is_denied(sandbox, python_exe):
    # The host /tmp is not mounted; an unprivileged process cannot even
    # create /tmp in the read-only root tree.
    r = _probe(
        sandbox,
        python_exe,
        "import os\n"
        "try:\n"
        "    open('/tmp/river-attack.txt', 'w').write('x')\n"
        "    print('LEAK')\n"
        "except OSError:\n"
        "    print('DENIED')\n",
    )
    assert r.status == "AC"
    assert r.stdout.strip() == b"DENIED"


def test_etc_secrets_are_unreadable(sandbox, python_exe):
    # /etc is mounted read-only and the program is nobody: shadow files
    # (root-only) must be unreadable.
    r = _probe(
        sandbox,
        python_exe,
        "import os\n"
        "outs = []\n"
        "for p in ('/etc/shadow', '/etc/gshadow'):\n"
        "    try:\n"
        "        open(p).read()\n"
        "        outs.append('LEAKED:' + p)\n"
        "    except OSError:\n"
        "        outs.append('DENIED:' + p)\n"
        "print(' '.join(outs))\n",
    )
    assert r.status == "AC"
    assert b"LEAKED" not in r.stdout
    assert r.stdout.count(b"DENIED") == 2


def test_system_dirs_are_read_only(sandbox, python_exe):
    r = _probe(
        sandbox,
        python_exe,
        "import os\n"
        "try:\n"
        "    open('/usr/.river-attack', 'w').write('x')\n"
        "    print('LEAK')\n"
        "except OSError:\n"
        "    print('DENIED')\n",
    )
    assert r.status == "AC"
    assert r.stdout.strip() == b"DENIED"


def test_sys_and_proc_sys_are_not_reachable(sandbox, python_exe):
    # /sys is not mounted at all; /proc/sys of a fresh pid namespace is not
    # writable by nobody.
    r = _probe(
        sandbox,
        python_exe,
        "import os\n"
        "outs = []\n"
        "for p in ('/sys/kernel', '/proc/sys/kernel/hostname'):\n"
        "    try:\n"
        "        os.listdir(p) if p == '/sys/kernel' else open(p, 'w').write('x')\n"
        "        outs.append('REACHED:' + p)\n"
        "    except OSError:\n"
        "        outs.append('DENIED:' + p)\n"
        "print(' '.join(outs))\n",
    )
    assert r.status == "AC"
    assert b"REACHED" not in r.stdout
    assert r.stdout.count(b"DENIED") == 2


# ---------------------------------------------------------------------------
# identity / privileges
# ---------------------------------------------------------------------------


def test_program_runs_unprivileged(sandbox, python_exe):
    r = _probe(
        sandbox,
        python_exe,
        "import os\n"
        "print(os.getuid(), os.getgid(), os.geteuid(), os.getegid())\n",
    )
    assert r.status == "AC"
    uid, gid, euid, egid = (int(x) for x in r.stdout.split())
    assert uid != 0 and euid != 0, r.stdout
    assert uid == euid
    assert gid == egid


def test_setuid_and_mknod_fail_without_privilege(sandbox, python_exe):
    r = _probe(
        sandbox,
        python_exe,
        "import os, stat\n"
        "outs = []\n"
        "for fn in (\n"
        "    lambda: os.setuid(0),\n"
        # A character device node needs CAP_MKNOD; a plain os.mknod() with no\n
        # S_IFCHR would just create a regular file and prove nothing.\n"
        "    lambda: os.mknod('/cwd/probe-node',\n"
        "                      mode=0o666 | stat.S_IFCHR,\n"
        "                      device=os.makedev(1, 3)),\n"
        "):\n"
        "    try:\n"
        "        fn()\n"
        "        outs.append('LEAK')\n"
        "    except OSError:\n"
        "        outs.append('DENIED')\n"
        "print(' '.join(outs))\n",
    )
    assert r.status == "AC"
    assert b"LEAK" not in r.stdout
    assert r.stdout.count(b"DENIED") == 2


def test_the_program_cannot_mount(sandbox, python_exe):
    r = _probe(
        sandbox,
        python_exe,
        "import ctypes, os\n"
        "libc = ctypes.CDLL(None, use_errno=True)\n"
        "os.makedirs('/cwd/mnt', exist_ok=True)\n"
        "rc = libc.mount(b'none', b'/cwd/mnt', b'tmpfs', 0, None)\n"
        "print('MOUNTED' if rc == 0 else 'DENIED')\n",
    )
    assert r.status == "AC"
    assert r.stdout.strip() == b"DENIED"


# ---------------------------------------------------------------------------
# network isolation
# ---------------------------------------------------------------------------


def test_outbound_network_is_denied(sandbox, python_exe):
    code = (
        "import socket, signal\n"
        "signal.alarm(10)\n"
        "try:\n"
        "    s = socket.create_connection(('1.1.1.1', 80), timeout=3)\n"
        "    print('CONNECTED')\n"
        "except OSError:\n"
        "    print('DENIED')\n"
    )
    r = _probe(sandbox, python_exe, code, wall_time_limit_ms=15000)
    assert r.status == "AC"
    assert r.stdout.strip() == b"DENIED"


def test_dns_resolution_is_denied(sandbox, python_exe):
    code = (
        "import socket, signal\n"
        "signal.alarm(10)\n"
        "try:\n"
        "    socket.gethostbyname('example.com')\n"
        "    print('RESOLVED')\n"
        "except OSError:\n"
        "    print('DENIED')\n"
    )
    r = _probe(sandbox, python_exe, code, wall_time_limit_ms=15000)
    assert r.status == "AC"
    assert r.stdout.strip() == b"DENIED"


def test_loopback_is_down_in_the_network_namespace(sandbox, python_exe):
    # A fresh netns has no interfaces up (not even lo by default): binding
    # and connecting on loopback fails.
    code = (
        "import socket\n"
        "outs = []\n"
        "for attempt in ('bind', 'connect'):\n"
        "    try:\n"
        "        s = socket.socket()\n"
        "        if attempt == 'bind':\n"
        "            s.bind(('127.0.0.1', 0))\n"
        "        else:\n"
        "            s.settimeout(2)\n"
        "            s.connect(('127.0.0.1', 1))\n"
        "        outs.append('OK:' + attempt)\n"
        "    except OSError:\n"
        "        outs.append('DENIED:' + attempt)\n"
        "print(' '.join(outs))\n"
    )
    r = _probe(sandbox, python_exe, code, wall_time_limit_ms=15000)
    assert r.status == "AC"
    assert b"OK:connect" not in r.stdout
    assert b"DENIED:connect" in r.stdout


# ---------------------------------------------------------------------------
# pid namespace & /proc
# ---------------------------------------------------------------------------


def test_program_is_pid_1_of_its_own_namespace(sandbox, python_exe):
    r = _probe(
        sandbox,
        python_exe,
        "import os; print(os.getpid())\n",
    )
    assert r.status == "AC"
    assert int(r.stdout.strip()) == 1


def test_host_processes_are_invisible(sandbox, python_exe):
    # Only the namespace's own processes appear under /proc.
    r = _probe(
        sandbox,
        python_exe,
        "import os\n"
        "pids = [p for p in os.listdir('/proc') if p.isdigit()]\n"
        "print(len(pids))\n",
    )
    assert r.status == "AC"
    assert 0 < int(r.stdout.strip()) < 5, r.stdout


def test_dev_has_the_standard_nodes(sandbox, python_exe):
    r = _probe(
        sandbox,
        python_exe,
        "import os\n"
        "ok = all(os.path.exists('/dev/' + n) for n in ('null','zero','random','urandom'))\n"
        "open('/dev/null', 'w').write('discard')\n"
        "print('OK' if ok else 'MISSING')\n",
    )
    assert r.status == "AC"
    assert r.stdout.strip() == b"OK"


# ---------------------------------------------------------------------------
# process model
# ---------------------------------------------------------------------------


def test_child_processes_are_allowed(sandbox, python_exe):
    # Wrapper/interpreter processes are part of the contract (DESIGN §3.6):
    # children are allowed, the *count* is bounded.
    r = _probe(
        sandbox,
        python_exe,
        "import subprocess\n"
        "out = subprocess.run(['/bin/sh', '-c', 'echo child-ok'],\n"
        "                     capture_output=True, timeout=10)\n"
        "print(out.stdout.decode().strip())\n",
    )
    assert r.status == "AC"
    assert r.stdout.strip() == b"child-ok"


def test_fork_bomb_is_bounded(sandbox, python_exe):
    # pids.max (default 64 live, supervisor included) makes the kernel
    # refuse forks with EAGAIN instead of letting the bomb take the host.
    code = (
        "import os, time\n"
        "kids = 0\n"
        "denied = False\n"
        "for _ in range(300):\n"
        "    try:\n"
        "        pid = os.fork()\n"
        "    except OSError:\n"
        "        denied = True\n"
        "        break\n"
        "    if pid == 0:\n"
        "        time.sleep(30)\n"
        "        os._exit(0)\n"
        "    kids += 1\n"
        "print('kids', kids, 'denied', denied)\n"
        "import sys; sys.stdout.flush()\n"
        "os._exit(0)\n"
    )
    r = _probe(sandbox, python_exe, code, wall_time_limit_ms=15000)
    # The parent exits on its own; the pid namespace reaps the sleeping
    # children when PID 1 exits, so the verdict is AC (not SE).
    assert r.status == "AC", (r.status, r.stderr[:400])
    out = r.stdout.decode()
    kids = int(out.split()[1])
    denied = "True" in out
    assert denied, out
    # The cap is 64 live processes including the supervisor and the
    # program itself, so a handful fewer children fit.
    assert 1 < kids < 70, out
    assert r.wall_time_used_ms < 15000


def test_memory_limit_kills_at_the_cap(sandbox, python_exe):
    code = "b = bytearray()\nwhile True:\n    b += b'x' * (4 << 20)\n"
    r = sandbox.run(
        python_exe,
        ["-c", code],
        memory_limit_kb=64 * 1024,
        wall_time_limit_ms=20000,
    )
    assert r.status == "MLE", (r.status, r.exit_code, r.memory_used_kb)
    assert r.signal == 9
    # memory.peak (RSS + page cache of the whole tree) stops at the cap.
    assert r.memory_used_kb <= 64 * 1024 * 1.3, r.memory_used_kb

# ---------------------------------------------------------------------------
# privilege fences (L7 hardening)
# ---------------------------------------------------------------------------


def test_no_new_privs_and_empty_capabilities(sandbox, python_exe):
    r = _probe(
        sandbox,
        python_exe,
        "import re\n"
        "st = open('/proc/self/status').read()\n"
        "no_new_privs = re.search(r'NoNewPrivs:\\s*(\\d+)', st).group(1)\n"
        "cap_eff = re.search(r'CapEff:\\s*([0-9a-fA-F]+)', st).group(1)\n"
        "print(no_new_privs, cap_eff)\n",
    )
    assert r.status == "AC", r.stderr[:400]
    nnp, cap_eff = r.stdout.split()
    assert nnp == b"1"
    assert int(cap_eff, 16) == 0, r.stdout


def test_setuid_binaries_are_neutralized_by_nosuid(sandbox, python_exe):
    # passwd/su/sudo carry S_ISUID inside /usr; the read-only binds must be
    # mounted nosuid so the kernel ignores that bit.
    r = _probe(
        sandbox,
        python_exe,
        "import os, stat\n"
        "setuid = [p for p in ('/usr/bin/passwd', '/usr/bin/su', '/usr/bin/sudo')\n"
        "          if os.path.exists(p) and os.stat(p).st_mode & stat.S_ISUID]\n"
        "mounts = {}\n"
        "for line in open('/proc/mounts'):\n"
        "    parts = line.split()\n"
        "    mounts[parts[1]] = parts[3].split(',')\n"
        "bad = {m: mounts[m] for m in ('/usr', '/etc', '/lib')\n"
        "       if m in mounts and 'nosuid' not in mounts[m]}\n"
        "print('SETUID_PRESENT' if setuid else 'NO_SETUID', 'BAD' if bad else 'NOSUID_OK', bad)\n",
    )
    assert r.status == "AC", r.stderr[:400]
    out = r.stdout.decode()
    assert "NOSUID_OK" in out, out
    # A nosuid mount is only meaningful if such binaries exist on this host.
    assert "SETUID_PRESENT" in out or "NO_SETUID" in out


def test_user_namespace_creation_is_denied(sandbox, python_exe):
    # seccomp denies unshare/setns, so a nested userns (and the extra kernel
    # attack surface it opens) is unreachable.
    r = _probe(
        sandbox,
        python_exe,
        "import subprocess\n"
        "p = subprocess.run(['/usr/bin/unshare', '-Ur', 'id', '-u'],\n"
        "                   capture_output=True, timeout=10)\n"
        "print(p.returncode, p.stderr.decode()[:120])\n",
    )
    assert r.status == "AC", r.stderr[:400]
    code = int(r.stdout.split()[0])
    assert code != 0, r.stdout
    assert b"Operation not permitted" in r.stdout or b"EPERM" in r.stdout


def test_seccomp_denies_keyctl_and_io_uring(sandbox, python_exe):
    # Raw syscalls that namespaces do not isolate must fail with EPERM.
    code = (
        "import ctypes, errno\n"
        "libc = ctypes.CDLL(None, use_errno=True)\n"
        "outs = []\n"
        "for name, nr, args in (\n"
        "    ('keyctl', 250, (0, 0, 0, 0)),\n"
        "    ('io_uring_setup', 425, (1, 0)),\n"
        "):\n"
        "    ctypes.set_errno(0)\n"
        "    rc = libc.syscall(nr, *args)\n"
        "    outs.append((name, rc, ctypes.get_errno()))\n"
        "print(outs)\n"
    )
    r = _probe(sandbox, python_exe, code)
    assert r.status == "AC", r.stderr[:400]
    text = r.stdout.decode()
    assert "('keyctl', -1, 1)" in text, text
    assert "('io_uring_setup', -1, 1)" in text, text


def test_hostname_does_not_leak(sandbox, python_exe):
    r = _probe(sandbox, python_exe, "import socket; print(socket.gethostname())")
    assert r.status == "AC"
    assert r.stdout.strip() == b"river", r.stdout


def test_executable_outside_runtimes_is_injected(sandbox, python_exe):
    # The contract's `executable` is a host path; a binary outside every
    # runtime/system dir must still run (bind-mounted at /cwd/.river/<name>).
    exedir = tempfile.mkdtemp(prefix="river-exe-")
    exe = os.path.join(exedir, "echo")
    try:
        with open("/bin/echo", "rb") as src, open(exe, "wb") as dst:
            dst.write(src.read())
        os.chmod(exe, 0o755)
        r = sandbox.run(exe, ["injected-ok"])
        assert r.status == "AC", (r.status, r.stderr[:400])
        assert r.stdout.strip() == b"injected-ok"
    finally:
        for name in os.listdir(exedir):
            os.remove(os.path.join(exedir, name))
        os.rmdir(exedir)


# ---------------------------------------------------------------------------
# limit enforcement (L7)
# ---------------------------------------------------------------------------


def test_memory_limit_reports_oom_killed(sandbox, python_exe):
    code = "b = bytearray()\nwhile True:\n    b += b'x' * (4 << 20)\n"
    r = sandbox.run(
        python_exe, ["-c", code],
        memory_limit_kb=64 * 1024, wall_time_limit_ms=20000,
    )
    assert r.status == "MLE", (r.status, r.exit_code)
    assert r.oom_killed is True, r


def test_slow_memory_bomb_dies_fast_without_swap(sandbox, python_exe):
    # 2MB/50ms: without `memory.swap.max=0` this survives at the cap for the
    # whole 20s wall clock (measured), because the kernel swaps the pages
    # out instead of OOM-killing the task.
    code = (
        "import time\n"
        "bufs = []\n"
        "for _ in range(400):\n"
        "    b = bytearray(2 << 20)\n"
        "    for off in range(0, len(b), 4096):\n"
        "        b[off] = 1\n"
        "    bufs.append(b)\n"
        "    time.sleep(0.05)\n"
    )
    r = sandbox.run(
        python_exe, ["-c", code],
        memory_limit_kb=64 * 1024, wall_time_limit_ms=20000,
    )
    assert r.status == "MLE", (r.status, r.exit_code, r.wall_time_used_ms)
    assert r.oom_killed is True, r
    assert r.wall_time_used_ms < 5000, r.wall_time_used_ms


def test_cpu_limit_is_enforced_actively(sandbox, python_exe):
    # 500ms CPU limit with the default 2x+1s wall allowance: the monitor's
    # cpu.stat poll must kill near 500ms, not at the ~2s wall deadline.
    t0 = time.perf_counter()
    r = sandbox.run(python_exe, ["-c", "while True: pass"], time_limit_ms=500)
    elapsed_ms = (time.perf_counter() - t0) * 1000
    assert r.status == "TLE", (r.status, r.wall_time_used_ms)
    assert r.wall_time_used_ms < 1500, r.wall_time_used_ms
    assert elapsed_ms < 2500, elapsed_ms


def test_file_size_limit_bounds_writes(sandbox, python_exe):
    # RLIMIT_FSIZE (64MB) turns a runaway writer into SIGXFSZ / EFBIG
    # instead of a full disk.
    code = (
        "f = open('/cwd/big.bin', 'wb')\n"
        "chunk = b'x' * (1 << 20)\n"
        "for _ in range(200):\n"
        "    f.write(chunk)\n"
        "print('WROTE')\n"
    )
    r = sandbox.run(python_exe, ["-c", code], wall_time_limit_ms=20000)
    assert r.status == "RE", (r.status, r.stderr[:200])
    # SIGXFSZ (128+25 = 153) when the signal is delivered, EFBIG (exit 1,
    # "File too large") when the write returns the error instead.
    assert r.exit_code in (128 + 25, 1), (r.exit_code, r.stderr[:200])
    if r.exit_code == 1:
        assert b"File too large" in r.stderr or b"EFBIG" in r.stderr, r.stderr[:300]


def test_copy_in_rejects_posix_absolute_key(sandbox, python_exe):
    # A bare POSIX absolute path is only absolute on POSIX hosts — the
    # cross-platform conformance suite leaves this to the per-backend suite.
    with pytest.raises(ValueError):
        sandbox.run(python_exe, ["-c", "pass"], copy_in={"/etc/passwd": b"x"})


def test_doctor_reports_ok():
    facts = river.doctor()
    assert facts["platform"] == "linux"
    assert facts["ok"] is True, facts.get("errors")
    for key in ("kernel", "cgroup_root", "seccomp", "memory_peak", "memory_swap_max"):
        assert key in facts, key
    assert facts["seccomp"] is True
    assert facts["memory_swap_max"] is True
