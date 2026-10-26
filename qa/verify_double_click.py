# -*- coding: utf-8 -*-
"""缺陷定位：为什么「双击第二次」没有提示「已有本服务在运行」？

launcher.resolve_port 的判断顺序是：
    1. port_is_free(port, host)  -> True 就直接返回「端口可用」
    2. health_ok(port)            -> 只有第 1 步为 False 才会走到这里

而 port_is_free 在 Windows 上只 bind `host`（默认 127.0.0.1）：
  - 占用者绑 127.0.0.1:P  -> 探测 bind 失败 -> BUSY  （能发现）
  - 占用者绑 0.0.0.0:P    -> 探测 bind 成功 -> FREE  （发现不了！）

`streamlit run main.py`（运行说明.md 方式二）的默认绑定地址是 0.0.0.0，
所以「按文档手动起过一次，再双击 bat」就会踩中这个盲区。

本脚本做对照实验，证明：
  情况 X：第 1 次用 start.py 起的（绑 127.0.0.1）-> 第 2 次能正确识别
  情况 Y：第 1 次用 streamlit run 起的（绑 0.0.0.0）-> 第 2 次识别不到
"""
import os
import re
import subprocess
import sys
import time
import urllib.request

PROJ = r"D:\DeskApp\python_xiangmu\python-sbom-security-tool"
PY_EXE = os.path.join(PROJ, ".venv", "Scripts", "python.exe")
LOCAL = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def health(port):
    try:
        with LOCAL.open(f"http://127.0.0.1:{port}/_stcore/health", timeout=3) as r:
            return r.status == 200 and r.read(64).decode().strip().lower() == "ok"
    except Exception:
        return False


def listeners(port):
    r = subprocess.run(["netstat", "-ano", "-p", "TCP"], capture_output=True)
    out = r.stdout.decode("gbk", errors="replace")
    return [l.strip() for l in out.splitlines()
            if f":{port}" in l and "LISTENING" in l]


def probe(port):
    code = (
        "import sys; sys.path.insert(0, %r)\n"
        "import launcher as L\n"
        "print('port_is_free(127.0.0.1) =', L.port_is_free(%d, '127.0.0.1'))\n"
        "print('port_is_free(0.0.0.0)  =', L.port_is_free(%d, '0.0.0.0'))\n"
        "print('health_ok            =', L.health_ok(%d))\n" % (PROJ, port, port, port)
    )
    r = subprocess.run([PY_EXE, "-c", code], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    return (r.stdout or "").strip()


def run_second_start(port):
    """第二次点 bat：start.py 会怎么表现。"""
    env = dict(os.environ)
    env["BROWSER"] = "echo"
    env["NO_PROXY"] = "127.0.0.1,localhost"
    env["no_proxy"] = env["NO_PROXY"]
    p = subprocess.Popen([PY_EXE, "start.py", "--port", str(port),
                          "--no-browser", "--timeout", "45"],
                         cwd=PROJ, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, encoding="utf-8", errors="replace", env=env)
    buf = ""
    t0 = time.time()
    while time.time() - t0 < 45:
        line = p.stdout.readline()
        if not line:
            break
        buf += line
        if "访问地址" in buf or "直接访问" in buf:
            break
    time.sleep(1)
    return p, buf


def scenario(label, port, first_cmd):
    print("=" * 72)
    print(label)
    print("=" * 72)
    first = subprocess.Popen(first_cmd, cwd=PROJ, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
    second = None
    try:
        t0 = time.time()
        while time.time() - t0 < 90 and not health(port):
            time.sleep(1.5)
        print(f"[1] 第 1 个实例已就绪: health={health(port)}")
        print(f"    监听行: {listeners(port)}")
        print(f"[2] launcher 的探测结果:")
        for line in probe(port).splitlines():
            print(f"    {line}")
        second, buf = run_second_start(port)
        print(f"[3] 第 2 次启动 start.py 的关键输出:")
        for l in buf.splitlines():
            if any(k in l for k in ("端口", "访问地址", "直接访问", "占用")):
                print(f"    {l.strip()}")
        detected = ("已有本服务" in buf) or ("不用重复" in buf)
        n_listen = len(listeners(port))
        print(f"[4] 判定：")
        print(f"    - 识别出「已有本服务在运行」? {detected}")
        print(f"    - 当前该端口的监听进程数 = {n_listen} "
              f"({'只有一个，没重复起' if n_listen <= 1 else '重复起了！'})")
    finally:
        if second:
            second.kill(); second.wait()
        first.kill(); first.wait()
        time.sleep(1.0)


if __name__ == "__main__":
    scenario("情况 X：第 1 次用 start.py 起的（绑 127.0.0.1）", 8851,
             [PY_EXE, "start.py", "--port", "8851", "--no-browser", "--timeout", "60"])
    print()
    scenario("情况 Y：第 1 次用 streamlit run 起的（绑 0.0.0.0，运行说明.md 方式二）",
             8852,
             [PY_EXE, "-m", "streamlit", "run", "main.py",
              "--server.port", "8852", "--server.headless", "true"])
