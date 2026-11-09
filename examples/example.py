from pathlib import Path

import river

PROJECT_ROOT = "./"

workdir = None
with river.Sandbox(
    runtimes=[
        PROJECT_ROOT + "/.venv/Scripts",
    ]
) as sandbox:
    workdir = sandbox.workdir
    if Path(workdir).exists():
        print("Workdir exists:", workdir)
    status = sandbox.exec(
        "python",
        args=["-c", "print('Hello, World!')"],
        envs={"PATH": PROJECT_ROOT + "/.venv/Scripts"},
        cpu_time_limit_ms=1000,
        wall_time_limit_ms=2000,
        memory_limit_bytes=256 * 1024,
        stdout_limit_bytes=64 * 1024,
        stderr_limit_bytes=64 * 1024,
        copy_in={
            PROJECT_ROOT + "/example/stdin.txt": "stdin.txt",
        },
        copy_out={
            "stdout.txt": PROJECT_ROOT + "/example/stdout.txt",
            "stderr.txt": PROJECT_ROOT + "/example/stderr.txt",
        },
        copy_out_limit_bytes=64 * 1024,
        stdin_file=PROJECT_ROOT + "/example/input.txt",
        stdout_file="stdout.txt",
        stderr_file="stderr.txt",
    )

    print("Status:", status.status)
    print("Exit Code:", status.exit_code)
    print("Signal:", status.signal)
    print("CPU Time Used (ms):", status.cpu_time_used_ms)
    print("Wall Time Used (ms):", status.wall_time_used_ms)
    print("Memory Used (bytes):", status.memory_used_bytes)

if workdir and Path(workdir).exists() is False:
    print("Workdir has been cleaned up:", workdir)
