"""Shared fixtures for the river test suite (S13).

The suite runs *real* programs inside the sandbox: each test costs a
process spawn (~100ms), so the fixtures keep the expensive setup (the
AppContainer profile, the runtime ACL grants) to a minimum.

`PYTHON` is the interpreter under test — it is exposed to the sandbox as a
runtime so the sandboxed program can actually start (a venv interpreter
needs its base prefix and `pyvenv.cfg` to be readable, see
docs/windows-backend.md §9.3.13).
"""

import os
import sys

import pytest

import river

#: The interpreter used as the program under test.
PYTHON = sys.executable

#: Directories the sandboxed program must be able to read (see above).
RUNTIMES = sorted(
    {
        os.path.dirname(PYTHON),
        sys.prefix,
        getattr(sys, "base_prefix", sys.prefix),
    }
)


@pytest.fixture(scope="session")
def python_exe() -> str:
    """Path of the interpreter to run inside the sandbox."""
    return PYTHON


@pytest.fixture(scope="session")
def runtimes() -> list[str]:
    """Directories exposed read-only to the sandboxed program."""
    return RUNTIMES


@pytest.fixture()
def sandbox():
    """A `Sandbox` with the standard runtimes, usable as a context manager."""
    sb = river.Sandbox(runtimes=RUNTIMES)
    with sb:
        yield sb


@pytest.fixture()
def tmp_host_file(tmp_path):
    """A host file outside the sandbox (must stay invisible to the program)."""
    p = tmp_path / "host-secret.txt"
    p.write_bytes(b"host-only-secret")
    return p
