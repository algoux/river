"""Attack-surface tests: what the sandbox must refuse (marker: attack).

The seccomp allowlist and the Landlock rules are always on, every attack
below is rejected, and the
legitimate operations around each one keep working. Like the functional
group, these need a delegated cgroup and `RIVER_TEST_ROOTFS`; the raw
syscall numbers in the table are x86_64 (the rootfs is too).
"""

from __future__ import annotations

import errno
import json
import os

import pytest

from conftest import delegated
from river import CopyOutError
from river._river import _seccomp_table

pytestmark = [
    pytest.mark.attack,
    pytest.mark.skipif(
        not delegated(),
        reason="not in a delegated cgroup; run under systemd-run --user --scope -p Delegate=yes",
    ),
]

EPERM = errno.EPERM
ENOSYS = errno.ENOSYS
EROFS = errno.EROFS
EACCES = errno.EACCES

# Shared prologue for the in-sandbox probes: a raw `syscall(2)` wrapper
# reporting (return value, errno) through ctypes.
PROLOGUE = """\
import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
def syscall(nr, *args):
    ctypes.set_errno(0)
    r = libc.syscall(ctypes.c_long(nr), *args)
    return r, ctypes.get_errno()
def attempt(fn, *args):
    try:
        fn(*args)
        return 'ok'
    except OSError as e:
        return e.errno
"""


def py(river_, code: str, **kwargs):
    """One `python -c <code>` run over the real rootfs."""
    return river_.exec("python", ["-c", code], **kwargs)


def run_table(river_, table, prologue=PROLOGUE):
    """Runs `table` (name -> expression evaluating to an errno or 'ok')
    inside one sandbox and returns the name -> value mapping."""
    lines = [prologue, "import json", "results = {}"]
    lines += [f"results[{name!r}] = {call}" for name, call in table]
    lines.append("print(json.dumps(results))")
    result = py(river_, "\n".join(lines) + "\n")
    assert result.status == "AC", (result.stdout, result.stderr, result.error)
    return json.loads(result.stdout)


def wrong(got, expected):
    """The entries whose value differs, spelled out for the assertion."""
    return {
        name: f"got {errno.errorcode.get(got[name], got[name])}, expected "
        f"{errno.errorcode.get(want, want)}"
        for name, want in expected.items()
        if got.get(name) != want
    }


# ------------------------------------------------------ seccomp: the allowlist

# (name, call) — one raw probe per syscall outside the allowlist, each
# judged by the errno it answers. The probes are chosen so that *without*
# the filter several of them would simply succeed (open_tree, ptrace
# TRACEME, process_vm_*v on self, add_key, settimeofday(NULL, NULL), ...);
# reboot is left out because a success inside a pid namespace signals pid 1.
RAW_REFUSED = [
    ("mount", "syscall(165, b'none', b'/tmp/mnt', b'tmpfs', 0, None)"),
    ("umount2", "syscall(166, b'/tmp', 0)"),
    ("pivot_root", "syscall(155, b'/tmp', b'/tmp')"),
    ("chroot", "syscall(161, b'/')"),
    ("fsopen", "syscall(430, b'tmpfs', 0)"),
    ("fsconfig", "syscall(431, -1, 0, None, 0)"),
    ("fsmount", "syscall(432, -1, 0, 0)"),
    ("move_mount", "syscall(429, -1, b'', -1, b'', 0)"),
    ("open_tree", "syscall(428, -100, b'/tmp', 0)"),
    ("mount_setattr", "syscall(442, -1, b'', 0, None, 0)"),
    ("ptrace", "syscall(101, 0, 0, None, None)"),
    ("process_vm_readv", "syscall(310, os.getpid(), None, 0, None, 0, 0)"),
    ("process_vm_writev", "syscall(311, os.getpid(), None, 0, None, 0, 0)"),
    ("bpf", "syscall(321, 0, None, 0)"),
    ("perf_event_open", "syscall(298, None, -1, 0, -1, 0)"),
    ("keyctl", "syscall(250, 0, -2, 0)"),
    ("add_key", "syscall(248, b'user', b'river', b'x', 1, -2)"),
    ("request_key", "syscall(249, b'user', b'river', b'x', -2)"),
    ("userfaultfd", "syscall(323, os.O_CLOEXEC)"),
    ("io_uring_setup", "syscall(425, 1, None)"),
    ("io_uring_enter", "syscall(426, -1, 0, 0, 0, None)"),
    ("io_uring_register", "syscall(427, -1, 0, None, 0)"),
    ("kcmp", "syscall(312, os.getpid(), -1, os.getpid(), -1, 0)"),
    ("pidfd_getfd", "syscall(438, -1, 0, 0)"),
    ("name_to_handle_at", "syscall(303, -100, b'/tmp', None, None, 0)"),
    ("open_by_handle_at", "syscall(304, -1, None, 0)"),
    ("memfd_secret", "syscall(447, 0)"),
    ("kexec_load", "syscall(246, 0, 0, None, 0)"),
    ("init_module", "syscall(175, None, 0, b'')"),
    ("finit_module", "syscall(313, -1, b'', 0)"),
    ("delete_module", "syscall(176, b'nosuch', 0)"),
    ("swapon", "syscall(167, b'/tmp/x', 0)"),
    ("swapoff", "syscall(168, b'/tmp/x')"),
    ("settimeofday", "syscall(164, None, None)"),
    ("clock_settime", "syscall(227, 0, None)"),
    ("clock_adjtime", "syscall(305, 0, None)"),
    ("adjtimex", "syscall(159, None)"),
    ("sethostname", "syscall(170, b'x', 1)"),
    ("setdomainname", "syscall(171, b'x', 1)"),
    ("acct", "syscall(163, None)"),
    ("quotactl", "syscall(179, 0, None, -1, None)"),
    ("nfsservctl", "syscall(180, 0, None, None)"),
    ("ioperm", "syscall(173, 0x378, 3, 1)"),
    ("iopl", "syscall(172, 3)"),
    ("syslog", "syscall(103, 3, None, 0)"),
    ("sysfs", "syscall(139, 0, 0)"),
    ("_sysctl", "syscall(156, None)"),
    ("uselib", "syscall(134, b'/tmp/x')"),
    ("vhangup", "syscall(153)"),
    ("fanotify_init", "syscall(300, 0, 0)"),
    ("fanotify_mark", "syscall(301, -1, 0, 0, -1, b'')"),
]


def test_unlisted_syscalls_answer_eperm(river_):
    table = [(name, f"({call})[1]") for name, call in RAW_REFUSED]
    got = run_table(river_, table)
    assert wrong(got, dict.fromkeys([name for name, _ in table], EPERM)) == {}


# -------------------------------------------------- seccomp: the whole table

# Every x86_64 number, probed with harmless (zero) arguments against the
# table the extension exports: the allowlist really is a whitelist. Each
# probe runs in a forked child and reports the errno through a pipe, so a
# syscall the kernel itself kills or never returns from (vfork corrupts
# the suspended parent, rseq's neighbour uretprobe answers SIGILL) only
# counts as "not EPERM" instead of taking the probe down.
#
# Numbers that would block the child forever with zero arguments.
SKIP_PROBES = {23, 270, 271, 34}  # select, pselect6, ppoll, pause
# clone/fork with flags 0 go through like fork: the copy leaves at once.
FORKING = {56, 57, 58}
# Outside the table, yet not the filter's EPERM: clone3 (ENOSYS, for
# glibc's fallback) and uretprobe/uprobe, the one exception the kernel
# makes for every seccomp filter (`seccomp_uprobe_exception`).
KERNEL_EXEMPT = {435: ENOSYS, 335: None, 336: None}
# Listed, yet the kernel itself answers EPERM with these arguments:
# fchmod/fchown on fd 0 (host-owned /dev/null when no stdin is given),
# setsid (a process group leader), setgroups (the idmap denies it),
# mlock/mlock2/mlockall (RLIMIT_MEMLOCK of 0 on the host).
KERNEL_EPERM = {91, 93, 112, 116, 149, 151, 325}

PROBE = f"""\
import select
def probe(nr):
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        rr, e = syscall(nr, 0, 0, 0, 0, 0, 0)
        if rr == 0 and nr in {FORKING!r}:
            os._exit(0)
        os.write(w, str(e).encode())
        os._exit(0)
    os.close(w)
    ready, _, _ = select.select([r], [], [], 2)
    if ready:
        data = os.read(r, 16).decode()
    else:
        os.kill(pid, 9)
        data = "hang"
    os.close(r)
    os.waitpid(pid, 0)
    return data
"""


def test_whole_syscall_table(river_):
    listed = {nr for _, nr in _seccomp_table()}
    code = (
        PROLOGUE
        + PROBE
        + "import json\n"
        + "results = {}\n"
        + "for nr in range(512):\n"
        + f"    if nr not in {SKIP_PROBES!r}:\n"
        + "        results[nr] = probe(nr)\n"
        + "print(json.dumps(results))\n"
    )
    result = py(river_, code)
    assert result.status == "AC", (result.stdout, result.stderr, result.error)
    got = {int(nr): e for nr, e in json.loads(result.stdout).items()}
    # The probe really walked the table.
    assert len(got) == 512 - len(SKIP_PROBES)
    # Outside the table: the filter's EPERM, clone3 and the kernel's
    # uprobe exception aside.
    refused = {nr: e for nr, e in got.items() if nr not in listed and nr not in KERNEL_EXEMPT}
    assert got[435] == str(ENOSYS), got[435]
    assert wrong(refused, dict.fromkeys(refused, str(EPERM))) == {}
    # Inside the table: never the filter's EPERM.
    listed_eperm = {nr for nr, e in got.items() if nr in listed and e == str(EPERM)}
    assert listed_eperm <= KERNEL_EPERM, sorted(listed_eperm - KERNEL_EPERM)


# Raw clone(2) probes: a clone that went through (it never must) continues
# in the copy like fork would, so the child leaves at once.
CLONE_PROBES = """\
def CLONE_PROBE(flags):
    r, e = syscall(56, flags, 0, None, None, 0, 0)
    if r == 0:
        os._exit(0)
    return r, e
def CLONE3_PROBE():
    r, e = syscall(435, ctypes.create_string_buffer(64), 64)
    if r == 0:
        os._exit(0)
    return r, e
"""

SIGCHLD = 0x11  # the exit signal every clone needs


def test_nested_namespaces_are_denied(river_):
    # unshare(2)/setns(2) through the os module (3.12+), clone(2) with each
    # kind of namespace flag (what unshare(1) and bwrap do), and clone3(2),
    # which answers ENOSYS on purpose so glibc falls back to clone.
    table = {
        "unshare": "attempt(os.unshare, os.CLONE_NEWUSER)",
        "setns": "attempt(os.setns, os.open('/proc/self/ns/user', os.O_RDONLY))",
        "clone.newuser": f"(CLONE_PROBE({0x10000000 | SIGCHLD:#x}))[1]",
        "clone.newns": f"(CLONE_PROBE({0x00020000 | SIGCHLD:#x}))[1]",
        "clone.newpid": f"(CLONE_PROBE({0x20000000 | SIGCHLD:#x}))[1]",
        "clone.newnet": f"(CLONE_PROBE({0x40000000 | SIGCHLD:#x}))[1]",
        "clone3": "(CLONE3_PROBE())[1]",
    }
    got = run_table(river_, list(table.items()), prologue=PROLOGUE + CLONE_PROBES)
    assert wrong(got, {**dict.fromkeys(table, EPERM), "clone3": ENOSYS}) == {}


def test_x32_syscalls_are_killed(river_):
    # The x32 ABI shares AUDIT_ARCH_X86_64 with the native one, only
    # __X32_SYSCALL_BIT (0x40000000) in nr tells them apart. No allowlist
    # rule matches such a number (EPERM already); the guard in front of the
    # clone3 program escalates it to a kill (SIGSYS,
    # SECCOMP_RET_KILL_PROCESS).
    result = py(river_, PROLOGUE + "syscall(0x40000000 | 41, 1, 1, 0)\n")
    assert result.status == "RE", (result.stdout, result.stderr, result.error)
    assert result.signal == 31, (result.signal, result.error)
    assert "SIGSYS" in result.error


def test_disallowed_socket_families_are_denied(river_):
    table = {
        name: f"attempt(socket.socket, {family}, socket.SOCK_RAW)"
        for name, family in [
            ("AF_NETLINK", 16),  # nf_tables attack surface (CVE-2024-1086)
            ("AF_PACKET", 17),
            ("AF_ALG", 38),
            ("AF_VSOCK", 40),
            ("AF_XDP", 44),
        ]
    }
    got = run_table(river_, list(table.items()), prologue="import socket\n" + PROLOGUE)
    assert wrong(got, dict.fromkeys(table, EPERM)) == {}


def test_allowed_socket_families_still_work(river_):
    # AF_UNIX, AF_INET (bound on the up loopback) and AF_INET6; AF_UNSPEC is
    # on the allowlist too but the kernel itself refuses to create it.
    result = py(
        river_,
        "import socket\n"
        "socket.socketpair()[0].close()\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "s.bind(('127.0.0.1', 0)); s.listen(1)\n"
        "socket.socket(socket.AF_INET6, socket.SOCK_STREAM).close()\n"
        "print('sockets-ok')\n",
    )
    assert result.status == "AC", (result.stderr, result.error)
    assert result.stdout == b"sockets-ok\n"


def test_process_creation_and_pidfd_still_work(river_):
    # fork/vfork/pthread_create all go through clone3 first: it must answer
    # ENOSYS (not EPERM) for glibc to fall back to clone. pidfd_open and
    # pidfd_send_signal are kept on purpose.
    result = py(
        river_,
        PROLOGUE
        + """\
import subprocess, threading
pid = os.fork()
if pid == 0:
    os._exit(3)
_, status = os.waitpid(pid, 0)
assert os.WEXITSTATUS(status) == 3
subprocess.run(['/bin/true'], check=True)
t = threading.Thread(target=lambda: None); t.start(); t.join()
fd, _ = syscall(434, os.getpid(), 0)
assert fd >= 0
assert syscall(424, fd, 0, None, 0)[0] == 0
print('process-ok')
""",
    )
    assert result.status == "AC", (result.stdout, result.stderr, result.error)
    assert result.stdout == b"process-ok\n"


# ------------------------------------------------------ seccomp: state & proof


def status_lines(river_, **kwargs):
    """The `Seccomp:`/`NoNewPrivs:` fields of /proc/self/status, by name."""
    code = (
        "import json\n"
        "print(json.dumps({l.split(':')[0]: l.split()[1] for l in open('/proc/self/status')"
        " if l.startswith(('Seccomp:', 'NoNewPrivs:'))}))\n"
    )
    result = py(river_, code, **kwargs)
    assert result.status == "AC", (result.stderr, result.error)
    return json.loads(result.stdout)


def test_hardening_layers_are_active(river_):
    # Seccomp: 2 = SECCOMP_MODE_FILTER; NoNewPrivs: 1 (`child.nnp`,
    # `child.seccomp`).
    assert status_lines(river_) == {"Seccomp": "2", "NoNewPrivs": "1"}


def test_hardening_off_is_the_control(river_, monkeypatch):
    # RIVER_HARDENING=off switches off seccomp and Landlock only
    # (the variable is read by the host process). This is the
    # control for the whole group: two attacks that the layers above stop
    # go through here — an AF_NETLINK socket, and a write under /proc,
    # where Landlock has no rule.
    monkeypatch.setenv("RIVER_HARDENING", "off")
    assert status_lines(river_) == {"Seccomp": "0", "NoNewPrivs": "1"}
    got = run_table(
        river_,
        [
            ("AF_NETLINK", "attempt(socket.socket, 16, socket.SOCK_RAW)"),
            ("/proc/self/comm", "attempt(open, '/proc/self/comm', 'w')"),
        ],
        prologue="import socket\n" + PROLOGUE,
    )
    assert got == {"AF_NETLINK": "ok", "/proc/self/comm": "ok"}


# ------------------------------------------------------------------- Landlock


def test_filesystem_write_matrix(river_):
    # /work, /tmp and /dev/shm get every handled right; the
    # device nodes and /dev/pts get WRITE_FILE (+ IOCTL_DEV); everything
    # else — the read-only rootfs, /sys, /proc — refuses writes.
    table = {
        path: f"attempt(open, {path!r}, 'w')"
        for path in [
            "/usr/x",
            "/etc/x",
            "/meta.json",
            "/sys/x",
            "/proc/self/comm",
            "/work/x",
            "/tmp/x",
            "/dev/shm/x",
            "/dev/null",
        ]
    }
    got = run_table(river_, list(table.items()))
    assert (
        wrong(
            got,
            {
                "/usr/x": EROFS,
                "/etc/x": EROFS,
                "/meta.json": EROFS,
                "/sys/x": EROFS,
                "/proc/self/comm": EACCES,
                "/work/x": "ok",
                "/tmp/x": "ok",
                "/dev/shm/x": "ok",
                "/dev/null": "ok",
            },
        )
        == {}
    )


def test_device_nodes_cannot_be_made_in_work(river_):
    # Landlock grants /work MAKE_REG/MAKE_DIR/MAKE_SYM/... but not
    # MAKE_CHAR; the capability check says the same.
    code = (
        "import os, stat\n"
        "try:\n"
        "    os.mknod('/work/null', 0o600 | stat.S_IFCHR, os.makedev(1, 3))\n"
        "    print('made')\n"
        "except OSError as e:\n"
        "    print(e.errno)\n"
    )
    result = py(river_, code)
    assert result.status == "AC", (result.stderr, result.error)
    assert result.stdout.strip() in {b"1", b"13"}, result.stdout  # EPERM / EACCES


# ----------------------------------------------------------- host invisibility


def test_proc_shows_only_the_sandbox(river_):
    host_pid = os.getpid()  # the pytest process: the sandbox's grandparent
    code = (
        "import os, json\n"
        "pids = sorted(int(p) for p in os.listdir('/proc') if p.isdigit())\n"
        f"print(json.dumps([os.getpid(), os.getppid(), pids,"
        f" os.path.exists('/proc/{host_pid}')]))\n"
    )
    result = py(river_, code)
    assert result.status == "AC", (result.stderr, result.error)
    assert json.loads(result.stdout) == [1, 0, [1], False]


def test_proc_sys_is_not_writable(river_):
    got = run_table(
        river_,
        [("/proc/sys/kernel/hostname", "attempt(open, '/proc/sys/kernel/hostname', 'w')")],
    )
    assert got["/proc/sys/kernel/hostname"] != "ok"


def test_host_cgroup_is_invisible(river_):
    # `child.mount.sys`: /sys/fs is covered by a tmpfs, so the
    # cgroup2 the kernel auto-mounts there inside a userns is not visible.
    result = py(
        river_,
        "import os\n"
        "print(os.path.exists('/sys/fs/cgroup'), os.path.isdir('/sys/class'),"
        " os.path.isdir('/sys/fs'))\n",
    )
    assert result.status == "AC", (result.stderr, result.error)
    assert result.stdout == b"False True True\n"


def test_root_is_exactly_the_rootfs(river_, rootfs):
    # "/" is the rootfs plus the mount points river adds inside it — nothing
    # of the host's directory tree is reachable.
    result = py(river_, "import os, json; print(json.dumps(sorted(os.listdir('/'))))\n")
    assert result.status == "AC", (result.stderr, result.error)
    assert set(json.loads(result.stdout)) <= set(os.listdir(rootfs)) | {"work"}
    # The rootfs's empty /home and /mnt stay empty: no host tree behind them.
    result = py(
        river_,
        "import os, json; print(json.dumps([os.listdir('/home'), os.listdir('/mnt')]))\n",
    )
    assert result.status == "AC", (result.stderr, result.error)
    assert json.loads(result.stdout) == [[], []]


# ------------------------------------------------------------------ copy_out


def test_copy_out_symlink_is_rejected(river_):
    # A symlink planted in /work must not make the host read /etc/passwd
    # (non-regular files -> CopyOutError).
    with pytest.raises(CopyOutError, match="not a regular file"):
        py(
            river_,
            "import os; os.symlink('/etc/passwd', 'passwd.txt')\n",
            copy_out={"passwd.txt": None},
        )


def test_copy_out_symlinked_directory_does_not_leak_host_files(river_):
    # The symlink in an *intermediate* position: on the host the work
    # directory is a plain directory tree, so `<work>/etc -> /etc` points at
    # the host's /etc and a stat-then-read pair would hand the caller the
    # host's /etc/passwd. openat2 RESOLVE_NO_SYMLINKS refuses the whole
    # lookup (ELOOP) and the error still carries the finished run.
    with pytest.raises(CopyOutError, match="symlink") as info:
        py(
            river_,
            "import os; os.symlink('/etc', 'etc')\n",
            copy_out={"etc/passwd": None},
        )
    assert info.value.result.status == "AC"
