import river

# 统一三平台的心智模型：
#   私有可写 cwd（每次 run 新建，块退出即销毁）
#   + runtimes（宿主机目录以只读方式并入沙箱：Windows 用 ACL 授权，
#     Linux/macOS 用只读 bind mount）
#   + copy_in（每 run 投放的私有文件）
#   + env
#
# rootfs 仅 Linux/macOS 支持（chroot/sandbox-exec）；Windows 上传入即报错
# —— Windows 进程永远从真实 System32 加载系统 DLL，rootfs 语义不成立，
# 运行时环境一律通过 runtimes 提供。
sandbox = river.Sandbox(
    rootfs=None,  # str | None，Linux/macOS 专属
    runtimes=[
        "E:/runtimes/python313",  # 只读
        "E:/runtimes/jdk21",  # 只读
    ],
)

with sandbox:
    # ── 场景 1：编译好的自包含 exe（典型 ACM 提交）────────────────────
    r = sandbox.run(
        "D:/oj/work/submissions/1001/main.exe",  # str，宿主机路径
        args=["arg1", "arg2"],  # list[str]，默认 []
        cwd=None,  # str | None，沙箱内相对路径，默认沙箱根（私有 cwd）
        env={
            "ENV_VAR1": "value1",
        },  # dict[str, str] | None，增量合并进白名单基底（SystemRoot/TEMP/TMP 恒存在）
        time_limit_ms=5000,  # ms | None，如果未设置，则默认为无限
        memory_limit_kb=1024 * 1024,  # kb | None，如果未设置，则默认为无限
        wall_time_limit_ms=10000,  # ms | None，如果未设置，则默认为 time_limit_ms * 2 + 1000
        stdin=b"1 2\n",  # bytes | None，与 stdin_file 互斥
        stdin_file=None,  # str | None，与 stdin 互斥，宿主机路径
        copy_in={
            # 沙箱相对路径 -> bytes 或宿主机路径，程序对这些文件默认只读
            # "input.txt": "D:/oj/data/P1001/1.in",  # file I/O 型题目
        },
        stdout_file=None,  # str | None，宿主机路径，完整输出留档（截至被杀为止）
        stdout_limit_kb=256 * 1024,  # kb | None，如果未设置，则默认为无限
        stderr_file=None,  # str | None，宿主机路径
        stderr_limit_kb=256 * 1024,  # kb | None，如果未设置，则默认为无限
    )
    print(r)
    print(r.time_used_ms, r.memory_used_kb, r.wall_time_used_ms)  # ms / kb / ms
    print(r.status, r.signal, r.exit_code, r.stdout_truncated, r.stderr_truncated)
    print(r.stdout, r.stderr)  # 截断后的 bytes

    # ── 场景 2：解释型语言 —— 可执行文件来自 runtimes，代码走 copy_in ──
    r2 = sandbox.run(
        "E:/runtimes/python313/python.exe",
        args=["main.py"],
        copy_in={
            "main.py": b"print(sum(map(int, input().split())))\n",
        },
        stdin=b"1 2\n",
        time_limit_ms=5000,
        memory_limit_kb=512 * 1024,  # 解释器有底噪，给宽些
    )
    assert r2.stdout == b"3\n"

    # ── 场景 3：Java —— 运行时目录 + env 组合 ──────────────────────
    r3 = sandbox.run(
        "E:/runtimes/jdk21/bin/java.exe",
        args=["-Djava.io.tmpdir=.", "Main"],
        env={"JAVA_HOME": "E:/runtimes/jdk21"},
        copy_in={"Main.class": "D:/oj/work/submissions/1002/Main.class"},
        stdin=b"1 2\n",
        time_limit_ms=10000,
    )

# with 块退出的协议保证：无残留进程、临时目录已删除、令牌/句柄已释放
