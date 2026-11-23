from river import River

# 参数是一个 rootfs 目录，river 会以这个目录为根创建一个沙箱环境，这个目录内是一个完整的镜像
# 和 podman 一样 rootless
# 和 nsjail 一样低开销
# 和 go-judge 一样限制/读取资源占用
# 只支持最新的 Linux 内核，不考虑旧版本兼容，什么 user ns 的都上

with River("/rootfs/python") as river:
    r = river.exec(
        "python",
        args=["-c", "print('Hello, World!')"],
        cwd="/work",
        envs={
            "PATH": "/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        },
        cpu_time_limit_ms=1000,
        wall_time_limit_ms=2000,
        memory_limit_bytes=256 * 1024,
        stdout_limit_bytes=64 * 1024,
        stderr_limit_bytes=64 * 1024,
        copy_in={},
        copy_out={},
        copy_out_limit_bytes=64 * 1024,
        stdin_file="input.txt",
        stdout_file="stdout.txt",
        stderr_file="stderr.txt",
    )
    print("Status:", r.status)
    print("Exit Code:", r.exit_code)
    print("Signal:", r.signal)
    print("CPU Time Used (ms):", r.cpu_time_used_ms)
    print("Wall Time Used (ms):", r.wall_time_used_ms)
    print("Memory Used (bytes):", r.memory_used_bytes)
