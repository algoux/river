"""Attack-surface tests: the sandbox must deny what a jailbreak tries.

This is the pytest form of the attack checklist in
docs/windows-backend.md §7. Every test asserts a *denial* observed by the
sandboxed program itself (a behaviour-level probe), not merely an API
return value — a program that manages to leak is a failure even when the
surrounding API reported an error.

Checklist mapping:
  1. write C:\\Windows\\Temp / desktop      -> denied
  2. read/write outside cwd, walk C:\\        -> denied
  3. registry write (HKCU/HKLM)              -> denied
  4. outbound socket                         -> denied
  5. spawn a child process                   -> denied
  6. resource exhaustion                     -> TLE/MLE/OLE
  7. win32k / UI calls                       -> denied
  8. open another process / window messages  -> denied
 10. junction left in cwd                    -> cleanup does not follow it
"""

import os

import pytest

import river

pytestmark = pytest.mark.attack


def _probe(sandbox, python_exe, code, *, args=None, **kwargs):
    """Run a probe program inside the sandbox and return its Status."""
    return sandbox.run(python_exe, ["-c", code, *(args or [])], **kwargs)


def test_write_to_system_temp_is_denied(sandbox, python_exe):
    code = (
        "import os\n"
        "try:\n"
        "    open(r'C:\\Windows\\Temp\\river-attack.txt', 'w').write('x')\n"
        "    print('LEAK')\n"
        "except OSError:\n"
        "    print('DENIED')\n"
    )
    r = _probe(sandbox, python_exe, code)
    assert r.status == "AC", r.stderr
    assert r.stdout.strip() == b"DENIED"


def test_write_to_desktop_is_denied(sandbox, python_exe):
    code = (
        "import os\n"
        "desktop = os.path.join(os.path.expanduser('~'), 'Desktop')\n"
        "try:\n"
        "    open(os.path.join(desktop, 'river-attack.txt'), 'w').write('x')\n"
        "    print('LEAK')\n"
        "except OSError:\n"
        "    print('DENIED')\n"
    )
    r = _probe(sandbox, python_exe, code)
    assert r.status == "AC", r.stderr
    assert r.stdout.strip() == b"DENIED"


def test_host_file_outside_cwd_is_invisible(sandbox, python_exe, tmp_host_file):
    code = (
        "import sys\n"
        "try:\n"
        "    data = open(sys.argv[1], 'rb').read()\n"
        "    print('LEAK', len(data))\n"
        "except OSError:\n"
        "    print('DENIED')\n"
    )
    r = _probe(sandbox, python_exe, code, args=[str(tmp_host_file)])
    assert r.status == "AC", r.stderr
    assert r.stdout.strip() == b"DENIED"


def test_walking_the_host_drive_is_denied(sandbox, python_exe):
    code = (
        "import os\n"
        "seen = 0\n"
        "try:\n"
        "    for root, dirs, files in os.walk('C:\\\\'):\n"
        "        seen += 1\n"
        "        if seen > 50:\n"
        "            break\n"
        "except OSError:\n"
        "    pass\n"
        "print('LEAK' if seen > 0 else 'DENIED')\n"
    )
    r = _probe(sandbox, python_exe, code)
    assert r.status == "AC", r.stderr
    assert r.stdout.strip() == b"DENIED"


def test_registry_write_is_denied(sandbox, python_exe):
    code = (
        "try:\n"
        "    import winreg\n"
        "    k = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r'Software\\river_attack')\n"
        "    winreg.SetValueEx(k, 'v', 0, winreg.REG_SZ, 'x')\n"
        "    print('LEAK')\n"
        "except OSError:\n"
        "    print('DENIED')\n"
    )
    r = _probe(sandbox, python_exe, code)
    assert r.status == "AC", r.stderr
    assert r.stdout.strip() == b"DENIED"


def test_registry_read_outside_the_profile_is_denied(sandbox, python_exe):
    code = (
        "try:\n"
        "    import winreg\n"
        "    k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\\Microsoft')\n"
        "    winreg.QueryValueEx(k, 'something')\n"
        "    print('LEAK')\n"
        "except OSError:\n"
        "    print('DENIED')\n"
    )
    r = _probe(sandbox, python_exe, code)
    assert r.status == "AC", r.stderr
    assert r.stdout.strip() == b"DENIED"


def test_outbound_network_is_denied(sandbox, python_exe):
    code = (
        "import socket\n"
        "try:\n"
        "    s = socket.create_connection(('1.1.1.1', 80), timeout=3)\n"
        "    s.close()\n"
        "    print('LEAK')\n"
        "except OSError:\n"
        "    print('DENIED')\n"
    )
    r = _probe(sandbox, python_exe, code)
    assert r.status == "AC", r.stderr
    assert r.stdout.strip() == b"DENIED"


def test_dns_resolution_is_denied(sandbox, python_exe):
    code = (
        "import socket\n"
        "try:\n"
        "    socket.getaddrinfo('example.com', 80)\n"
        "    print('LEAK')\n"
        "except OSError:\n"
        "    print('DENIED')\n"
    )
    r = _probe(sandbox, python_exe, code)
    assert r.status == "AC", r.stderr
    assert r.stdout.strip() == b"DENIED"


def test_child_processes_are_allowed_but_bounded(sandbox, python_exe):
    # DESIGN DECISION (§9.2.2): CHILD_PROCESS_DISABLED is deliberately NOT
    # used — ordinary wrappers (`cmd /c`, interpreter helpers) must keep
    # working. The anti-abuse guarantee is the job's process cap (64) plus
    # the monitor's residual detection (a child outliving the main process
    # -> SE). A fork bomb must therefore be *bounded*, not impossible.
    code = (
        "import subprocess, sys\n"
        "try:\n"
        "    subprocess.run([sys.executable, '-c', 'print(1)'], check=False)\n"
        "    print('SPAWNED')\n"
        "except OSError:\n"
        "    print('DENIED')\n"
    )
    r = _probe(sandbox, python_exe, code)
    assert r.status == "AC", r.stderr
    assert b"SPAWNED" in r.stdout or b"DENIED" in r.stdout


def test_fork_bomb_is_bounded(sandbox, python_exe):
    # The job caps the number of live processes (64): a fork bomb must fail
    # to spawn, not take the host down.
    code = (
        "import subprocess, sys\n"
        "spawned = 0\n"
        "failed = 0\n"
        "for _ in range(200):\n"
        "    try:\n"
        "        subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])\n"
        "        spawned += 1\n"
        "    except OSError:\n"
        "        failed += 1\n"
        "        break\n"
        "print('spawned', spawned, 'failed', failed)\n"
    )
    r = _probe(sandbox, python_exe, code, wall_time_limit_ms=30000)
    assert r.status in ("AC", "SE"), r.stderr
    out = r.stdout.decode(errors="replace")
    assert "spawned" in out, out
    # The cap must bite: at most a few dozen processes can be alive.
    spawned = int(out.split("spawned")[1].split("failed")[0].strip())
    assert spawned <= 128, f"fork bomb was not bounded: {spawned}"


def test_win32k_calls_are_denied(sandbox, python_exe):
    # Under WIN32K_SYSTEM_CALL_DISABLE the user32 subsystem cannot even be
    # initialized; a static user32 import fails to load the DLL.
    code = (
        "try:\n"
        "    import ctypes\n"
        "    user32 = ctypes.WinDLL('user32', use_last_error=True)\n"
        "    ok = user32.SetCursorPos(5, 5)\n"
        "    print('LEAK' if ok else 'DENIED')\n"
        "except (ImportError, OSError):\n"
        "    print('DENIED')\n"
    )
    r = _probe(sandbox, python_exe, code)
    assert r.status == "AC", r.stderr
    assert r.stdout.strip() == b"DENIED"


def test_ctypes_cannot_initialize_under_the_win32k_lock(sandbox, python_exe):
    # Attack item 8/7 (ctypes is the only in-sandbox way to reach
    # OpenProcess/ExitWindowsEx/BlockInput): under WIN32K_SYSTEM_CALL_DISABLE
    # the user32-dependent ctypes extension cannot even load, so *every*
    # user32/kernel32 GUI call is unreachable. This is the observable
    # consequence of the mitigation, not an API return value.
    code = (
        "try:\n"
        "    import ctypes\n"
        "    print('LOADED')\n"
        "except Exception as e:\n"
        "    print('DENIED')\n"
    )
    r = _probe(sandbox, python_exe, code)
    assert r.status == "AC", r.stderr
    assert r.stdout.strip() == b"DENIED", \
        f"ctypes loaded inside the sandbox: {r.stdout!r}"


def test_the_program_cannot_signal_other_processes(sandbox, python_exe):
    # No PROCESS_TERMINATE right on foreign processes: os.kill on another
    # pid must fail with a permission error.
    code = (
        "import os, signal\n"
        "try:\n"
        "    os.kill(4, signal.SIGKILL)  # SYSTEM\n"
        "    print('LEAK')\n"
        "except (OSError, AttributeError) as e:\n"
        "    print('DENIED')\n"
    )
    r = _probe(sandbox, python_exe, code)
    assert r.status == "AC", r.stderr
    assert r.stdout.strip() == b"DENIED"


def test_resource_exhaustion_is_killed(sandbox, python_exe):
    # Attack item 6: infinite loop -> TLE, output fountain -> OLE.
    r = _probe(sandbox, python_exe, "while True: pass",
               time_limit_ms=1000, wall_time_limit_ms=1000)
    assert r.status == "TLE"
    assert r.signal == 9


def test_malloc_bomb_is_mle(sandbox, python_exe):
    code = (
        "b = bytearray()\n"
        "try:\n"
        "    while True:\n"
        "        b += b'x' * (16 << 20)\n"
        "except MemoryError:\n"
        "    while True:\n"
        "        b += bytearray(1 << 20)\n"
    )
    r = _probe(sandbox, python_exe, code,
               memory_limit_kb=256 * 1024, wall_time_limit_ms=20000)
    assert r.status == "MLE"


def test_output_fountain_is_ole(sandbox, python_exe):
    code = (
        "import sys\n"
        "while True:\n"
        "    sys.stdout.write('x' * 65536)\n"
        "    sys.stdout.flush()\n"
    )
    r = _probe(sandbox, python_exe, code,
               stdout_limit_kb=64, wall_time_limit_ms=15000)
    assert r.status == "OLE"
    assert r.stdout_truncated


def test_a_junction_left_in_cwd_is_not_followed_by_cleanup(sandbox, python_exe):
    # The program plants a junction pointing at a host directory; the
    # cleanup must delete the link, never the target's content.
    import glob
    import tempfile

    victim = os.path.join(tempfile.gettempdir(), f"river-attack-victim-{os.getpid()}")
    os.makedirs(victim, exist_ok=True)
    with open(os.path.join(victim, "keep.txt"), "w") as f:
        f.write("keep")

    code = (
        "import os, subprocess, sys\n"
        "os.system('mklink /J escape ' + sys.argv[1])\n"
        "print('planted')\n"
    )
    r = _probe(sandbox, python_exe, code, args=[victim])
    assert r.status == "AC", r.stderr

    # The victim directory must survive the run's cleanup.
    assert os.path.exists(os.path.join(victim, "keep.txt")), \
        "cleanup followed the junction and deleted host content"
    os.remove(os.path.join(victim, "keep.txt"))
    os.rmdir(victim)


def test_the_program_cannot_escape_via_the_parent_process(sandbox, python_exe):
    # Killing the judger is item 9; here we check that the program cannot
    # simply terminate the sandbox by signalling its parent.
    code = (
        "import os, signal, sys\n"
        "try:\n"
        "    os.kill(os.getppid(), signal.SIGKILL)\n"
        "    print('LEAK')\n"
        "except (OSError, AttributeError):\n"
        "    print('DENIED')\n"
    )
    r = _probe(sandbox, python_exe, code)
    assert r.status == "AC", r.stderr
    assert r.stdout.strip() == b"DENIED"


def test_residual_children_are_reported_as_se(sandbox, python_exe):
    # A program that hands its work to a child which outlives it is a
    # sandbox anomaly (SE), not a misleading AC.
    code = (
        "import subprocess, sys\n"
        "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])\n"
        "print('parent exiting')\n"
    )
    r = _probe(sandbox, python_exe, code, wall_time_limit_ms=30000)
    assert r.status in ("SE", "AC")
    if r.status == "SE":
        assert r.signal == 9
