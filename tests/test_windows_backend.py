"""End-to-end tests for the Windows backend.

Run with::

    uv run maturin develop
    uv run pytest tests/test_windows_backend.py
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

import river

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows backend tests")

COMSPEC = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "cmd.exe"
BUSY_LOOP = ["/c", "for /L %i in (1,1,400000000) do @rem x"]


def acl(path: Path) -> str:
    """The `icacls` view of `path`, used to prove grants are revoked."""
    result = subprocess.run(
        ["icacls", str(path)], check=False, capture_output=True, text=True
    )
    if result.returncode != 0:
        pytest.skip(f"icacls failed: {result.stderr.strip()}")
    return result.stdout


def acl_entries(text: str) -> list[str]:
    """The ACEs of an `icacls` listing, normalized for comparison.

    Writing a DACL makes Windows re-materialize an object's inherited ACEs as
    explicit ones, so the raw listing changes across a grant cycle even though
    the effective access does not. The inherited marker is dropped here: only
    the trustees and their rights are compared, so a leftover package SID or
    a changed right still fails the check.
    """
    return sorted(
        line.replace("(I)", "", 1)
        for line in text.splitlines()
        if line.strip() and not line.startswith("Successfully processed")
    )


def runtime_dir(tmp_path: Path) -> tuple[Path, Path]:
    directory = tmp_path / "runtime"
    directory.mkdir()
    target = directory / "data.txt"
    target.write_text("original", encoding="utf-8")
    return directory, target


def test_public_surface():
    assert set(river.__all__) == {"Sandbox", "Status"}


def test_rootfs_is_rejected():
    with pytest.raises(ValueError, match="rootfs"):
        river.Sandbox(rootfs=str(Path(os.environ["SystemRoot"])))


def test_exec_with_runtimes_requires_a_session(tmp_path: Path):
    directory, _ = runtime_dir(tmp_path)
    with pytest.raises(RuntimeError, match="AppContainer sandbox is not active"):
        river.Sandbox(runtimes=[str(directory)]).exec(str(COMSPEC), ["/c", "echo", "x"])


def test_profile_lifecycle_is_bound_to_enter_and_exit(tmp_path: Path):
    directory, target = runtime_dir(tmp_path)
    before = acl(directory)
    box = river.Sandbox(runtimes=[str(directory)])

    for _ in range(2):
        with box:
            during = acl(directory)
            assert during != before
            assert "S-1-15-2-" in during
            assert box.workdir is not None
            assert box.exec(str(COMSPEC), ["/c", "type", str(target)]).status == "AC"
        assert acl_entries(acl(directory)) == acl_entries(before)

    with pytest.raises(RuntimeError, match="AppContainer sandbox is not active"):
        box.exec(str(COMSPEC), ["/c", "echo", "x"])


def test_missing_runtime_fails_at_enter_without_touching_acls(tmp_path: Path):
    directory, _ = runtime_dir(tmp_path)
    before = acl(directory)
    with (
        pytest.raises(OSError, match="does not exist"),
        river.Sandbox(runtimes=[str(directory), str(tmp_path / "missing")]),
    ):
        pass
    assert acl(directory) == before


def test_clean_run_is_ac_and_reports_stats():
    status = river.Sandbox().exec(str(COMSPEC), ["/c", "echo", "hello"])
    assert status.status == "AC"
    assert status.exit_code == 0
    assert status.signal == 0
    assert status.cpu_time_used_ms >= 0
    assert status.wall_time_used_ms >= 0
    assert status.memory_used_bytes > 0


def test_nonzero_exit_is_re():
    status = river.Sandbox().exec(str(COMSPEC), ["/c", "exit", "3"])
    assert status.status == "RE"
    assert status.exit_code == 3
    assert status.signal == 0


def test_wall_time_limit_is_tle():
    status = river.Sandbox().exec(str(COMSPEC), BUSY_LOOP, wall_time_limit_ms=800)
    assert status.status == "TLE"
    assert status.signal == 9
    assert status.wall_time_used_ms >= 700


@pytest.mark.slow
def test_cpu_time_limit_is_tle():
    status = river.Sandbox().exec(
        sys.executable,
        ["-c", "while True: pass"],
        cpu_time_limit_ms=300,
        wall_time_limit_ms=20_000,
    )
    assert status.status == "TLE"
    assert status.signal == 9
    assert status.cpu_time_used_ms >= 300
    # The native job-time limit terminates with one of these two codes.
    assert status.exit_code in {1816, 0xC0000044}


def test_memory_limit_is_mle():
    status = river.Sandbox().exec(
        sys.executable,
        ["-c", "bytearray(200 * 1024 * 1024)"],
        memory_limit_bytes=100 * 1024 * 1024,
    )
    assert status.status == "MLE"
    assert status.signal == 9
    assert status.memory_used_bytes >= 100 * 1024 * 1024


def test_memory_usage_is_measured():
    status = river.Sandbox().exec(sys.executable, ["-c", "bytearray(20 * 1024 * 1024)"])
    assert status.status == "AC"
    assert status.memory_used_bytes >= 20 * 1024 * 1024


def test_cpu_time_is_measured():
    status = river.Sandbox().exec(sys.executable, ["-c", "sum(range(20_000_000))"])
    assert status.status == "AC"
    assert status.cpu_time_used_ms > 0


def test_runtime_directory_is_read_only(tmp_path: Path):
    directory, target = runtime_dir(tmp_path)
    nested = directory / "nested"
    nested.mkdir()
    (nested / "inner.txt").write_text("inner", encoding="utf-8")
    before = acl(directory)

    with river.Sandbox(runtimes=[str(directory)]) as box:
        assert box.exec(str(COMSPEC), ["/c", "type", str(target)]).status == "AC"
        assert (
            box.exec(str(COMSPEC), ["/c", "type", str(nested / "inner.txt")]).status
            == "AC"
        )

        write = box.exec(str(COMSPEC), ["/c", "echo", "hacked", ">", str(target)])
        assert write.status == "RE"
        assert target.read_text(encoding="utf-8") == "original"

        create = box.exec(
            str(COMSPEC),
            ["/c", "echo", "new", ">", str(directory / "new.txt")],
        )
        assert create.status == "RE"
        assert not (directory / "new.txt").exists()

    assert acl_entries(acl(directory)) == acl_entries(before)


def test_file_runtime_is_scoped(tmp_path: Path):
    directory, target = runtime_dir(tmp_path)
    sibling = directory / "sibling.txt"
    sibling.write_text("sibling", encoding="utf-8")
    before_file = acl(target)
    before_directory = acl(directory)

    with river.Sandbox(runtimes=[str(target)]) as box:
        assert box.exec(str(COMSPEC), ["/c", "type", str(target)]).status == "AC"
        assert box.exec(str(COMSPEC), ["/c", "type", str(sibling)]).status == "RE"
        assert (
            box.exec(str(COMSPEC), ["/c", "echo", "x", ">", str(target)]).status == "RE"
        )

    assert acl_entries(acl(target)) == acl_entries(before_file)
    assert acl_entries(acl(directory)) == acl_entries(before_directory)


def test_workdir_relative_cwd_is_writable(tmp_path: Path):
    directory, _ = runtime_dir(tmp_path)
    with river.Sandbox(runtimes=[str(directory)]) as box:
        workdir = Path(box.workdir)
        (workdir / "sub").mkdir()
        status = box.exec(
            str(COMSPEC),
            ["/c", "echo", "scratch", ">", "out.txt"],
            cwd="sub",
        )
        assert status.status == "AC"
        assert (workdir / "sub" / "out.txt").read_text().startswith("scratch")


@pytest.mark.parametrize("cwd", [".", "..", r"C:\Windows", "a:b"])
def test_invalid_cwd_is_rejected(cwd: str):
    with pytest.raises(ValueError, match="cwd"):
        river.Sandbox().exec(str(COMSPEC), ["/c", "echo", "x"], cwd=cwd)


def test_session_exec_defaults_to_the_workdir(tmp_path: Path):
    stdout = tmp_path / "cd.txt"
    with river.Sandbox() as box:
        status = box.exec(str(COMSPEC), ["/c", "cd"], stdout_file=str(stdout))
        assert status.status == "AC"
        assert Path(stdout.read_text().strip()) == Path(box.workdir)


def test_copy_in_file_is_readable(tmp_path: Path):
    source = tmp_path / "input.txt"
    source.write_text("copied-content", encoding="utf-8")
    stdout = tmp_path / "out.txt"
    with river.Sandbox() as box:
        status = box.exec(
            str(COMSPEC),
            ["/c", "type", "input.txt"],
            copy_in={str(source): "input.txt"},
            stdout_file=str(stdout),
        )
    assert status.status == "AC"
    assert stdout.read_text(encoding="utf-8").strip() == "copied-content"


def test_copy_in_nested_destination_is_created(tmp_path: Path):
    source = tmp_path / "input.txt"
    source.write_text("nested", encoding="utf-8")
    stdout = tmp_path / "out.txt"
    with river.Sandbox() as box:
        status = box.exec(
            str(COMSPEC),
            ["/c", "type", r"a\b\c.txt"],
            copy_in={str(source): r"a\b\c.txt"},
            stdout_file=str(stdout),
        )
    assert status.status == "AC"
    assert stdout.read_text(encoding="utf-8").strip() == "nested"


def test_copy_in_can_create_the_cwd(tmp_path: Path):
    source = tmp_path / "project"
    source.mkdir()
    (source / "data.txt").write_text("from-project", encoding="utf-8")
    stdout = tmp_path / "out.txt"
    with river.Sandbox() as box:
        status = box.exec(
            str(COMSPEC),
            ["/c", "type", "data.txt"],
            cwd="project",
            copy_in={str(source): "project"},
            stdout_file=str(stdout),
        )
    assert status.status == "AC"
    assert stdout.read_text(encoding="utf-8").strip() == "from-project"


def test_copy_in_file_is_read_only_in_a_session(tmp_path: Path):
    directory, _ = runtime_dir(tmp_path)
    source = tmp_path / "input.txt"
    source.write_text("original", encoding="utf-8")
    with river.Sandbox(runtimes=[str(directory)]) as box:
        workdir = Path(box.workdir)
        status = box.exec(
            str(COMSPEC),
            ["/c", "type", "input.txt"],
            copy_in={str(source): "input.txt"},
            stdout_file=str(tmp_path / "read.txt"),
        )
        assert status.status == "AC"

        status = box.exec(
            str(COMSPEC),
            ["/c", "echo", "hacked", ">", "input.txt"],
            copy_in={str(source): "input.txt"},
            stderr_file=str(tmp_path / "write.err"),
        )
        assert status.status == "RE"
        assert (workdir / "input.txt").read_text(encoding="utf-8") == "original"


def test_copy_in_directory_is_recursive_and_read_only(tmp_path: Path):
    directory, _ = runtime_dir(tmp_path)
    source = tmp_path / "inputdir"
    (source / "sub").mkdir(parents=True)
    (source / "sub" / "data.txt").write_text("immutable", encoding="utf-8")
    stdout = tmp_path / "out.txt"
    box = river.Sandbox(runtimes=[str(directory)])
    with box:
        workdir = Path(box.workdir)
        status = box.exec(
            str(COMSPEC),
            ["/c", "type", r"inputdir\sub\data.txt"],
            copy_in={str(source): "inputdir"},
            stdout_file=str(stdout),
        )
        assert status.status == "AC"
        assert stdout.read_text(encoding="utf-8").strip() == "immutable"

        status = box.exec(
            str(COMSPEC),
            ["/c", "echo", "hacked", ">", r"inputdir\sub\data.txt"],
            copy_in={str(source): "inputdir"},
            stderr_file=str(tmp_path / "write.err"),
        )
        assert status.status == "RE"
        assert (workdir / "inputdir" / "sub" / "data.txt").read_text(
            encoding="utf-8"
        ) == "immutable"
    assert not workdir.exists()


def test_copy_in_is_repeatable_inside_a_session(tmp_path: Path):
    directory, _ = runtime_dir(tmp_path)
    source = tmp_path / "input.txt"
    stdout = tmp_path / "out.txt"
    with river.Sandbox(runtimes=[str(directory)]) as box:
        for content in ("first", "second"):
            source.write_text(content, encoding="utf-8")
            status = box.exec(
                str(COMSPEC),
                ["/c", "type", "input.txt"],
                copy_in={str(source): "input.txt"},
                stdout_file=str(stdout),
            )
            assert status.status == "AC"
            assert stdout.read_text(encoding="utf-8").strip() == content


@pytest.mark.parametrize("destination", ["../escape", r"C:\abs", "/abs", ".", "a:b"])
def test_invalid_copy_in_destination_is_rejected(tmp_path: Path, destination: str):
    source = tmp_path / "input.txt"
    source.write_text("x", encoding="utf-8")
    with pytest.raises(ValueError, match="copy_in"):
        river.Sandbox().exec(
            str(COMSPEC),
            ["/c", "echo", "x"],
            copy_in={str(source): destination},
        )


def test_copy_in_duplicate_destinations_are_rejected(tmp_path: Path):
    first = tmp_path / "first.txt"
    first.write_text("first", encoding="utf-8")
    second = tmp_path / "second.txt"
    second.write_text("second", encoding="utf-8")
    with pytest.raises(ValueError, match="copy_in"):
        river.Sandbox().exec(
            str(COMSPEC),
            ["/c", "echo", "x"],
            copy_in={str(first): "input.txt", str(second): "input.txt"},
        )


def test_copy_in_overlapping_destinations_are_rejected(tmp_path: Path):
    first = tmp_path / "first.txt"
    first.write_text("first", encoding="utf-8")
    second = tmp_path / "second.txt"
    second.write_text("second", encoding="utf-8")
    with pytest.raises(ValueError, match="overlap"):
        river.Sandbox().exec(
            str(COMSPEC),
            ["/c", "echo", "x"],
            copy_in={str(first): "tree", str(second): r"tree\input.txt"},
        )


def test_copy_in_requires_a_session(tmp_path: Path):
    source = tmp_path / "input.txt"
    source.write_text("x", encoding="utf-8")
    with pytest.raises(
        RuntimeError, match="copy_in requires an active sandbox session"
    ):
        river.Sandbox().exec(
            str(COMSPEC),
            ["/c", "echo", "x"],
            copy_in={str(source): "input.txt"},
        )


def test_copy_in_missing_source_is_an_oserror(tmp_path: Path):
    with river.Sandbox() as box, pytest.raises(OSError, match="copy_in"):
        box.exec(
            str(COMSPEC),
            ["/c", "echo", "x"],
            copy_in={str(tmp_path / "missing.txt"): "input.txt"},
        )


# ---------------------------------------------------------------------------
# copy_out: product recovery (only after an AC run, never via links)
# ---------------------------------------------------------------------------


def test_copy_out_recovers_files_and_directories(tmp_path: Path):
    destination_file = tmp_path / "out" / "answer.txt"
    destination_dir = tmp_path / "out" / "tree"
    script = (
        "from pathlib import Path\n"
        "Path('answer.txt').write_text('hello-product')\n"
        "Path('tree/nested').mkdir(parents=True)\n"
        "Path('tree/nested/x.bin').write_bytes(bytes([1, 2]))\n"
    )
    with river.Sandbox() as box:
        status = box.exec(
            sys.executable,
            ["-c", script],
            copy_out={
                "answer.txt": str(destination_file),
                "tree": str(destination_dir),
            },
        )
    assert status.status == "AC"
    assert destination_file.read_text(encoding="utf-8") == "hello-product"
    assert (destination_dir / "nested" / "x.bin").read_bytes() == b"\x01\x02"


def test_copy_out_missing_source_is_skipped(tmp_path: Path):
    destination = tmp_path / "optional.txt"
    with river.Sandbox() as box:
        status = box.exec(
            str(COMSPEC),
            ["/c", "echo", "x"],
            copy_out={"never-written.txt": str(destination)},
        )
    assert status.status == "AC"
    assert not destination.exists()


def test_copy_out_limit_without_copy_out_is_ignored():
    status = river.Sandbox().exec(
        str(COMSPEC), ["/c", "echo", "x"], copy_out_limit_bytes=1
    )
    assert status.status == "AC"


def test_copy_out_quota_breach_is_ole_and_writes_nothing(tmp_path: Path):
    destination = tmp_path / "dump.bin"
    with river.Sandbox() as box:
        status = box.exec(
            sys.executable,
            ["-c", "open('dump.bin', 'wb').write(b'x' * 4096)"],
            copy_out={"dump.bin": str(destination)},
            copy_out_limit_bytes=1024,
        )
    assert status.status == "OLE"
    assert status.signal == 9
    assert not destination.exists()


def test_copy_out_exactly_at_the_limit_is_ac(tmp_path: Path):
    destination = tmp_path / "exact.bin"
    with river.Sandbox() as box:
        status = box.exec(
            sys.executable,
            ["-c", "open('exact.bin', 'wb').write(b'x' * 1024)"],
            copy_out={"exact.bin": str(destination)},
            copy_out_limit_bytes=1024,
        )
    assert status.status == "AC"
    assert destination.read_bytes() == b"x" * 1024


def test_copy_out_limit_is_a_total(tmp_path: Path):
    output = tmp_path / "out"
    with river.Sandbox() as box:
        status = box.exec(
            sys.executable,
            [
                "-c",
                (
                    "from pathlib import Path\n"
                    "Path('a.bin').write_bytes(b'a' * 600)\n"
                    "Path('b.bin').write_bytes(b'b' * 600)\n"
                ),
            ],
            copy_out={
                "a.bin": str(output / "a.bin"),
                "b.bin": str(output / "b.bin"),
            },
            copy_out_limit_bytes=1000,
        )
    assert status.status == "OLE"
    assert status.signal == 9
    collected = list(output.iterdir())
    assert len(collected) == 1
    assert collected[0].stat().st_size == 600


@pytest.mark.parametrize("source", ["../escape", r"C:\abs", "/abs", ".", "a:b"])
def test_invalid_copy_out_source_is_rejected(tmp_path: Path, source: str):
    with pytest.raises(ValueError, match="copy_out"):
        river.Sandbox().exec(
            str(COMSPEC),
            ["/c", "echo", "x"],
            copy_out={source: str(tmp_path / "out.txt")},
        )


def test_copy_out_requires_a_session(tmp_path: Path):
    with pytest.raises(
        RuntimeError, match="copy_out requires an active sandbox session"
    ):
        river.Sandbox().exec(
            str(COMSPEC),
            ["/c", "echo", "x"],
            copy_out={"out.txt": str(tmp_path / "out.txt")},
        )


def test_copy_out_is_skipped_when_the_run_is_not_ac(tmp_path: Path):
    destination = tmp_path / "product.txt"
    with river.Sandbox() as box:
        status = box.exec(
            sys.executable,
            ["-c", "open('product.txt', 'w').write('x'); raise SystemExit(3)"],
            copy_out={"product.txt": str(destination)},
        )
    assert status.status == "RE"
    assert not destination.exists()


def test_copy_out_recovers_products_from_an_appcontainer_session(tmp_path: Path):
    directory, _ = runtime_dir(tmp_path)
    destination = tmp_path / "product.txt"
    with river.Sandbox(runtimes=[str(directory)]) as box:
        status = box.exec(
            str(COMSPEC),
            ["/c", "echo", "product", ">", "out.txt"],
            copy_out={"out.txt": str(destination)},
        )
    assert status.status == "AC"
    assert destination.read_text(encoding="utf-8").strip() == "product"


def test_copy_out_never_follows_junctions(tmp_path: Path):
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "secret.txt").write_text("host-secret", encoding="utf-8")

    with river.Sandbox() as box:
        workdir = Path(box.workdir)

        leak = workdir / "leak"
        created = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(leak), str(victim)],
            capture_output=True,
            check=False,
            text=True,
        )
        if created.returncode != 0:
            pytest.skip(f"mklink /J failed: {created.stderr.strip()}")

        status = box.exec(
            str(COMSPEC),
            ["/c", "echo", "x"],
            copy_out={"leak": str(tmp_path / "leak")},
        )
        assert status.status == "AC"
        assert not (tmp_path / "leak").exists()

        tree = workdir / "tree"
        tree.mkdir()
        (tree / "ok.txt").write_text("data", encoding="utf-8")
        created = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(tree / "leak"), str(victim)],
            capture_output=True,
            check=False,
            text=True,
        )
        if created.returncode != 0:
            pytest.skip(f"mklink /J failed: {created.stderr.strip()}")

        tree_destination = tmp_path / "tree"
        status = box.exec(
            str(COMSPEC),
            ["/c", "echo", "x"],
            copy_out={"tree": str(tree_destination)},
        )
        assert status.status == "AC"
        assert (tree_destination / "ok.txt").read_text(encoding="utf-8") == "data"
        assert not (tree_destination / "leak").exists()

    # The session cleanup must remove the junctions, not their target.
    assert (victim / "secret.txt").exists()


def test_stdin_file_is_fed(tmp_path: Path):
    source = tmp_path / "input.bin"
    source.write_bytes(b"file-input")
    stdout = tmp_path / "stdout.bin"
    status = river.Sandbox().exec(
        sys.executable,
        ["-c", "import sys; sys.stdout.write(sys.stdin.read())"],
        stdin_file=str(source),
        stdout_file=str(stdout),
    )
    assert status.status == "AC"
    assert stdout.read_bytes() == b"file-input"


def test_stdin_file_is_fed_inside_an_appcontainer_session(tmp_path: Path):
    directory, _ = runtime_dir(tmp_path)
    source = tmp_path / "input.txt"
    source.write_bytes(b"hello\r\n")
    stdout = tmp_path / "out.txt"
    with river.Sandbox(runtimes=[str(directory)]) as box:
        (Path(box.workdir) / "sub").mkdir()
        status = box.exec(
            str(COMSPEC),
            ["/c", "findstr", "hello"],
            cwd="sub",
            stdin_file=str(source),
            stdout_file=str(stdout),
        )
    assert status.status == "AC"
    assert stdout.read_bytes() == b"hello\r\n"


def test_stdout_and_stderr_files_capture_separately(tmp_path: Path):
    stdout = tmp_path / "stdout.bin"
    stderr = tmp_path / "stderr.bin"
    status = river.Sandbox().exec(
        sys.executable,
        ["-c", "import sys; sys.stdout.write('out'); sys.stderr.write('err')"],
        stdout_file=str(stdout),
        stderr_file=str(stderr),
    )
    assert status.status == "AC"
    assert stdout.read_bytes() == b"out"
    assert stderr.read_bytes() == b"err"


def test_stdout_file_is_created_when_output_is_empty(tmp_path: Path):
    stdout = tmp_path / "empty.bin"
    status = river.Sandbox().exec(
        sys.executable, ["-c", "pass"], stdout_file=str(stdout)
    )
    assert status.status == "AC"
    assert stdout.read_bytes() == b""


def test_stdout_file_works_inside_an_appcontainer_session(tmp_path: Path):
    directory, _ = runtime_dir(tmp_path)
    stdout = tmp_path / "appcontainer.bin"
    stderr = tmp_path / "appcontainer.err"
    with river.Sandbox(runtimes=[str(directory)]) as box:
        status = box.exec(
            str(COMSPEC),
            ["/c", "echo", "captured"],
            stdout_file=str(stdout),
            stderr_file=str(stderr),
        )
    assert status.status == "AC"
    assert stdout.read_bytes().strip() == b"captured"
    assert stderr.read_bytes() == b""


def test_stdout_limit_kills_with_ole_and_keeps_the_archive(tmp_path: Path):
    stdout = tmp_path / "full.bin"
    status = river.Sandbox().exec(
        sys.executable,
        ["-c", "import sys; sys.stdout.write('z' * 4096); sys.stdout.flush()"],
        stdout_limit_bytes=1024,
        stdout_file=str(stdout),
    )
    assert status.status == "OLE"
    assert status.signal == 9
    assert stdout.stat().st_size >= 1024


def test_stdout_limit_without_a_file_is_ole():
    status = river.Sandbox().exec(
        sys.executable,
        ["-c", "import sys; sys.stdout.write('z' * 4096); sys.stdout.flush()"],
        stdout_limit_bytes=1024,
    )
    assert status.status == "OLE"
    assert status.signal == 9


def test_stdout_limit_kills_a_flood_before_the_wall_limit(tmp_path: Path):
    status = river.Sandbox().exec(
        sys.executable,
        [
            "-c",
            (
                "import sys\n"
                "while True:\n"
                "    sys.stdout.write('x' * 65536)\n"
                "    sys.stdout.flush()"
            ),
        ],
        stdout_limit_bytes=64 * 1024,
        wall_time_limit_ms=15_000,
    )
    assert status.status == "OLE"
    assert status.signal == 9
    assert status.wall_time_used_ms < 15_000


def test_exactly_at_the_stdout_limit_is_ac():
    status = river.Sandbox().exec(
        sys.executable,
        ["-c", "import sys; sys.stdout.write('z' * 1024); sys.stdout.flush()"],
        stdout_limit_bytes=1024,
    )
    assert status.status == "AC"
    assert status.signal == 0


def test_stderr_limit_is_independent(tmp_path: Path):
    stdout = tmp_path / "stdout.bin"
    status = river.Sandbox().exec(
        sys.executable,
        ["-c", "import sys; sys.stderr.write('e' * 4096); sys.stderr.flush()"],
        stderr_limit_bytes=1024,
        stdout_file=str(stdout),
    )
    assert status.status == "OLE"
    assert status.signal == 9
    assert stdout.read_bytes() == b""


def test_without_runtimes_is_a_plain_process(tmp_path: Path):
    target = tmp_path / "plain.txt"
    status = river.Sandbox().exec(
        str(COMSPEC), ["/c", "echo", "plain", ">", str(target)]
    )
    assert status.status == "AC"
    assert target.read_text(encoding="utf-8").strip() == "plain"


def test_plain_run_env_is_whitelisted(monkeypatch, tmp_path: Path):
    """A plain run (no runtimes) also drops the host environment, matching
    the Linux backend's `ENV_BASE` semantics; only whitelisted machine
    facts pass through and PATH is the fixed system PATH."""
    monkeypatch.setenv("RIVER_TEST_MARKER", "secret")
    stdout = tmp_path / "env.txt"
    status = river.Sandbox().exec(
        sys.executable,
        ["-c", "import os, sys; w = sys.stdout.write; "
               "w(os.environ.get('RIVER_TEST_MARKER', '<absent>') + '\\n'); "
               "w(os.environ.get('PATH', '') + '\\n'); "
               "w(os.environ.get('SystemRoot', ''))"],
        stdout_file=str(stdout),
    )
    assert status.status == "AC"
    marker, path, system_root = stdout.read_text(encoding="utf-8").splitlines()
    assert marker == "<absent>"
    assert path == rf"{system_root}\system32;{system_root}"


def test_plain_run_envs_override_the_whitelist(tmp_path: Path):
    stdout = tmp_path / "env.txt"
    status = river.Sandbox().exec(
        sys.executable,
        ["-c", "import os, sys; sys.stdout.write(os.environ['RIVER_TEST_SET'])"],
        envs={"RIVER_TEST_SET": "passed-through"},
        stdout_file=str(stdout),
    )
    assert status.status == "AC"
    assert stdout.read_text(encoding="utf-8") == "passed-through"
