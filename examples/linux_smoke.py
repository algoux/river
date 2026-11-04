"""Linux backend smoke test (stages L1-L5).

Run as **root** (namespaces/mounts/cgroups need CAP_SYS_ADMIN):

    sudo -E uv run python examples/linux_smoke.py

Checks, in order: the capability matrix, an AC run, wall-clock TLE, memory
MLE, output OLE, copy_in, network isolation and the sandbox filesystem
shape. Exits non-zero on the first mismatch.
"""

import os
import sys

import river

RUNTIMES = sorted(
    {
        os.path.dirname(sys.executable),
        sys.prefix,
        getattr(sys, "base_prefix", sys.prefix),
    }
)


def main() -> int:
    caps = river.capabilities()
    print("capabilities:", caps)
    assert caps["platform"] == "linux", caps
    assert caps["rootfs"] is True, "rootfs is supported on Linux"

    facts = river.doctor()
    print("doctor:", {k: facts[k] for k in facts if k != "controllers"})
    assert facts["ok"] is True, facts.get("errors")
    assert facts["seccomp"] is True, facts

    with river.Sandbox(runtimes=RUNTIMES) as sb:
        r = sb.run(sys.executable, ["-c", "print('hello')"])
        print("AC run:", r)
        assert r.status == "AC" and r.stdout.strip() == b"hello", r

        r = sb.run(
            sys.executable, ["-c", "import time; time.sleep(30)"],
            wall_time_limit_ms=500,
        )
        print("wall timeout:", r)
        assert r.status == "TLE" and r.signal == 9, r

        r = sb.run(
            sys.executable, ["-c", "b = bytearray()\nwhile True: b += b'x' * (4 << 20)"],
            memory_limit_kb=64 * 1024, wall_time_limit_ms=15000,
        )
        print("memory cap:", r)
        assert r.status == "MLE", r

        r = sb.run(
            sys.executable,
            ["-c", "import sys; sys.stdout.write('z' * 4096)"],
            stdout_limit_kb=1,
        )
        print("output cap:", r)
        assert r.status == "OLE" and r.stdout_truncated, r

        r = sb.run(
            sys.executable,
            ["-c", "import sys; sys.stdout.write(open(sys.argv[1]).read())", "in.txt"],
            copy_in={"in.txt": b"payload"},
        )
        print("copy_in:", r)
        assert r.stdout == b"payload", r

        r = sb.run(
            sys.executable,
            [
                "-c",
                ("import socket\n"
                 "try:\n"
                 "    socket.create_connection(('1.1.1.1', 80), timeout=2)\n"
                 "    print('NETWORK')\n"
                 "except OSError:\n"
                 "    print('ISOLATED')\n"),
            ],
            wall_time_limit_ms=15000,
        )
        print("network:", r)
        assert r.stdout.strip() == b"ISOLATED", r

        r = sb.run(
            sys.executable, ["-c", "import os; print(' '.join(sorted(os.listdir('/'))))"]
        )
        names = set(r.stdout.decode().split())
        print("root listing:", sorted(names))
        assert {"cwd", "proc", "dev"} <= names, names
        assert "tmp" not in names, names  # host /tmp is never mounted

    # rootfs: a caller-supplied root tree replaces the sandbox root. Here we
    # smoke-test with a minimal tree (an empty rootfs must make exec fail,
    # proving `executable` is resolved inside the rootfs, not on the host).
    import tempfile

    with tempfile.TemporaryDirectory() as empty_root:
        with river.Sandbox(rootfs=empty_root) as sb:
            r = sb.run("/bin/sh", ["-c", "echo hi"])
            print("empty rootfs exec:", r)
            assert r.status == "SE", r  # /bin/sh does not exist in the rootfs

    print("linux smoke: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
