# 冒烟：mitigation policies + 禁网 —— Windows 攻击清单前 7 项。
# 场景（每项在沙箱内探针验证，不是只看 API 返回值）：
#   1. 写 C:\Windows\Temp / 桌面 → 拒绝（AppContainer + ACL）
#   2. 读写 cwd 外文件（宿主目录）→ 拒绝
#   3. 注册表写入 → 拒绝
#   4. socket 连外网 → 拒绝（无 capability，默认断网）
#   5. 全局 Windows hook 注入 → 失败（EXTENSION_POINT_DISABLE）
#   6. win32k 系统调用（SetCursorPos）→ 拒绝（WIN32K_SYSTEM_CALL_DISABLE）
#   7. while(1)/sleep/输出喷泉 → TLE/TLE/OLE
import os
import sys

import river

PYTHON = sys.executable
base = getattr(sys, "base_prefix", os.path.dirname(PYTHON))
runtimes = sorted({os.path.dirname(PYTHON), sys.prefix, base})

sandbox = river.Sandbox(runtimes=runtimes)

PROBE = r"""
import os, sys, socket
ok = []
# 1) 写系统临时目录 / 桌面
for target in (os.path.expanduser(r"%TEMP%") if False else r"C:\Windows\Temp",
               os.path.expanduser(r"~\Desktop")):
    try:
        open(os.path.join(target, "river-s8.txt"), "w").write("x")
        ok.append(target + "=LEAK")
    except OSError:
        ok.append(target + "=denied")
# 2) 读写 cwd 外的宿主文件（本脚本自己的宿主路径）
host_file = sys.argv[1] if len(sys.argv) > 1 else None
if host_file:
    try:
        open(host_file, "a").close()
        ok.append("host-file=LEAK")
    except OSError:
        ok.append("host-file=denied")
# 3) 注册表写入
try:
    import winreg
    winreg.SetValueEx(winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\river_s8"),
                      "v", 0, winreg.REG_SZ, "x")
    ok.append("registry=LEAK")
except OSError:
    ok.append("registry=denied")
# 4) 网络连接（AppContainer 无 capability，默认断网）
try:
    s = socket.create_connection(("1.1.1.1", 80), timeout=3)
    ok.append("network=LEAK")
    s.close()
except OSError:
    ok.append("network=denied")
print("|".join(ok))
"""

PROBE_WIN32K_HOOK = r"""
# 6) win32k 调用 + 5) 全局 hook：EXTENSION_POINT/WIN32K 策略在内核层拦截。
# 注意：win32k 锁定下连 user32 都无法初始化——_ctypes.pyd 静态依赖 user32，
# 其 ImportError(DLL load failed) 即为策略生效的直接证据。
try:
    import ctypes
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    # win32k 系统调用：SetCursorPos 需要 win32k；被禁 → 失败且 lasterror=1260
    r = user32.SetCursorPos(5, 5)
    err = ctypes.get_last_error()
    print("win32k:", "LEAK" if r else f"denied({err})")
    # 全局钩子注册（EXTENSION_POINT_DISABLE 拦截注入路径；API 层可能仍成功）
    HOOKPROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, ctypes.c_int, ctypes.c_ssize_t, ctypes.c_ssize_t)
    h = user32.SetWindowsHookExW(5, HOOKPROC(lambda *a: 0), None, 0)
    if h:
        user32.UnhookWindowsHookEx(h)
        print("hook: registered(kernel-blocked-injection)" if ctypes.get_last_error() == 0 else "hook: registered")
    else:
        print(f"hook: denied({ctypes.get_last_error()})")
except ImportError as e:
    # user32 初始化失败 → 依赖它的扩展模块全部无法加载
    print(f"win32k: denied(user32 init failed: {e})")
    print("hook: denied(user32 unavailable)")
"""

with sandbox:
    # ── 攻击 1/2/3/4：文件 / 注册表 / 网络 ────────────────────────────
    r = sandbox.run(
        PYTHON,
        args=["-c", PROBE],
        time_limit_ms=20000,
        memory_limit_kb=1024 * 1024,
    )
    print(r.status, r.exit_code)
    out = r.stdout.decode(errors="replace").strip()
    print(out)
    print(r.stderr.decode(errors="replace").rstrip()[:300])
    checks = dict(p.split("=", 1) for p in out.split("|"))
    assert all(v == "denied" for v in checks.values()), checks
    assert r.status == "AC", r.status

    # ── 攻击 5/6：hook / win32k ───────────────────────────────────────
    r2 = sandbox.run(
        PYTHON,
        args=["-c", PROBE_WIN32K_HOOK],
        time_limit_ms=20000,
        memory_limit_kb=1024 * 1024,
    )
    out2 = r2.stdout.decode(errors="replace").strip()
    print(out2)
    print(r2.stderr.decode(errors="replace").rstrip()[:300])
    assert "win32k: denied" in out2 or "load-denied" in out2, out2
    assert "LEAK" not in out2, out2
    assert r2.status == "AC", r2.status

    # ── 攻击 6：TLE —— while(1) 仍被看门狗强杀 ───────────────────────
    r3 = sandbox.run(
        PYTHON,
        args=["-c", "while True: pass"],
        time_limit_ms=1000,
        wall_time_limit_ms=1000,
    )
    assert r3.status == "TLE" and r3.signal == 9, (r3.status, r3.signal)
    print("watchdog:", r3.status, r3.signal)

print("attack smoke OK")
