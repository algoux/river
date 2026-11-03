# S7 冒烟：AppContainer + ACL 端到端验证。
# 场景：写 cwd 成功 / 写 C:\ 失败 / 读 runtimes 成功 / python via runtimes 跑通
import os
import sys

import river

PYTHON = sys.executable
base = getattr(sys, "base_prefix", os.path.dirname(PYTHON))
# venv shim 需要读 sys.prefix 下的 pyvenv.cfg 与 base 解释器目录
runtimes = sorted({os.path.dirname(PYTHON), sys.prefix, base})

sandbox = river.Sandbox(runtimes=runtimes)

PROBE = r"""
import os, sys
ok = []
# 1) 写 cwd 成功
open("out.txt", "w").write("hello")
ok.append("write-cwd:" + os.path.exists("out.txt").__str__())
# 2) 写 C:\ 失败
try:
    open(r"C:\river-smoke-denied.txt", "w").write("x")
    ok.append("write-root:LEAK")
except OSError:
    ok.append("write-root:denied")
# 3) 读 runtimes（宿主目录只读）
exe_dir = os.path.dirname(sys.executable)
try:
    names = os.listdir(exe_dir)
    ok.append("read-runtimes:ok(%d)" % len(names))
    try:
        open(os.path.join(exe_dir, names[0]), "a").close()
        ok.append("write-runtimes:LEAK")
    except OSError:
        ok.append("write-runtimes:denied")
except OSError as e:
    ok.append("read-runtimes:FAIL %s" % e)
print("|".join(ok))
"""

with sandbox:
    r = sandbox.run(
        PYTHON,
        args=["-c", PROBE],
        time_limit_ms=10000,
        memory_limit_kb=1024 * 1024,
    )
    print(r.status, r.signal, r.exit_code)
    print(r.stdout.decode(errors="replace").rstrip())
    print(r.stderr.decode(errors="replace").rstrip()[:500])
    out = r.stdout.decode(errors="replace").strip()
    checks = dict(p.split(":", 1) for p in out.split("|"))
    assert checks["write-cwd"] == "True", checks
    assert checks["write-root"] == "denied", checks
    assert checks["read-runtimes"].startswith("ok"), checks
    assert checks["write-runtimes"] == "denied", checks
    print("S7 smoke OK")

# 清理误留文件（若隔离失效会存在）
try:
    os.remove(r"C:\river-smoke-denied.txt")
    print("!! isolation leak file removed")
except OSError:
    pass
