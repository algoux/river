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
#
# 注意（当前进度）：runtimes / env 增量合并尚未实现（S6/S7）；
# copy_in / cwd / 各项限制 / 三通道 IO 已可用。
sandbox = river.Sandbox(
    rootfs=None,  # str | None，Linux/macOS 专属
    runtimes=[],
)

import sys

PYTHON = sys.executable  # 演示用：以本机 Python 作为被测运行时

with sandbox:
    # ── 场景 1：运行一个程序并施加资源限制 ─────────────────────────
    r = sandbox.run(
        PYTHON,  # str，宿主机路径
        args=["-c", "print(sum(map(int, input().split())))"],
        cwd=None,  # str | None，沙箱内相对路径，默认沙箱根（私有 cwd）
        env=None,  # dict[str, str] | None，增量合并进白名单基底（S7 生效）
        time_limit_ms=5000,  # ms | None，如果未设置，则默认为无限
        memory_limit_kb=256 * 1024,  # kb | None，如果未设置，则默认为无限
        wall_time_limit_ms=10000,  # ms | None，默认为 time_limit_ms * 2 + 1000
        stdin=b"1 2\n",  # bytes | None，与 stdin_file 互斥
        stdin_file=None,  # str | None，宿主机路径
        copy_in={  # 沙箱相对路径 -> bytes 或宿主机路径，程序只读
        },
        stdout_file=None,  # str | None，宿主机路径，完整输出留档
        stdout_limit_kb=256 * 1024,  # kb | None，如果未设置，则默认为无限
        stderr_file=None,
        stderr_limit_kb=256 * 1024,
    )
    print(r)
    assert r.status == "AC"
    assert r.stdout.rstrip() == b"3"
    print(r.time_used_ms, r.memory_used_kb, r.wall_time_used_ms)  # ms / kb / ms
    print(r.status, r.signal, r.exit_code, r.stdout_truncated, r.stderr_truncated)

    # ── 场景 2：copy_in 投放数据文件（file I/O 型题目 / 解释型语言代码）──
    r2 = sandbox.run(
        PYTHON,
        args=["-c", "print(sum(map(int, open('nums.txt').read().split())))"],
        copy_in={
            "nums.txt": b"1 2 3 4 5\n",  # bytes 直接写入
            # "data.txt": "D:/oj/data/P1001/1.in",  # 或宿主机路径拷贝
        },
        time_limit_ms=5000,
        memory_limit_kb=512 * 1024,  # 解释器有底噪，给宽些
    )
    assert r2.status == "AC"
    assert r2.stdout.rstrip() == b"15"
    print("copy_in:", r2.status, r2.stdout)

    # ── 场景 3：TLE —— wall 看门狗强杀 ────────────────────────────
    r3 = sandbox.run(
        PYTHON,
        args=["-c", "import time; time.sleep(30)"],
        time_limit_ms=5000,
        wall_time_limit_ms=500,  # 500ms 后由沙箱强杀
    )
    assert r3.status == "TLE" and r3.signal == 9
    print("watchdog:", r3.status, r3.signal, f"wall={r3.wall_time_used_ms}ms")

# with 块退出的协议保证：无残留进程、临时目录已删除、令牌/句柄已释放
print("example OK")
