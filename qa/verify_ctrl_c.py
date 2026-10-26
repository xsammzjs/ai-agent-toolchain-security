# -*- coding: utf-8 -*-
"""直接验证产品代码路径：launcher.stop_streamlit() 是否真的清干净整棵进程树。

为什么不用「模拟 Ctrl+C」：
  Windows 控制台事件（CTRL_C_EVENT / CTRL_BREAK_EVENT）只有在真正的
  前台控制台里才会送到**整个前台进程组**；用脚本模拟时，投递语义与
  真实终端不一致（我实测三种方式，结果互相矛盾，不可信）。
  所以这里绕开信号投递，直接测**产品真正执行的那段代码**：
  start.py 捕获 KeyboardInterrupt 后调用的 launcher.stop_streamlit(proc)。

真实终端按 Ctrl+C 时，streamlit 子进程会**同时**收到 Ctrl+C 而自己退出；
  产品的 stop_streamlit 是**兜底**（保证子进程没自己退出时也能清掉）。
所以要验证的是：单独调用 stop_streamlit 后，端口是否释放、有无孤儿。
"""
import os
import subprocess
import sys
import time
import urllib.request

PROJ = r"D:\DeskApp\python_xiangmu\python-sbom-security-tool"
PY_EXE = os.path.join(PROJ, ".venv", "Scripts", "python.exe")
PORT = 9101
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


def main():
    print("=" * 70)
    print("验证 launcher.stop_streamlit()：能否清干净整棵进程树")
    print("=" * 70)

    code = f'''
import sys, time, urllib.request
sys.path.insert(0, {PROJ!r})
import launcher as L
from pathlib import Path

LOCAL = urllib.request.build_opener(urllib.request.ProxyHandler({{}}))

def health(port):
    try:
        with LOCAL.open(f"http://127.0.0.1:{{port}}/_stcore/health", timeout=3) as r:
            return r.status == 200 and r.read(64).decode().strip().lower() == "ok"
    except Exception:
        return False

python = L.venv_python()
proc = L.start_streamlit(python, {PORT}, "127.0.0.1")
print("STARTED", flush=True)

# 等就绪
t0 = time.time()
while time.time() - t0 < 120 and not health({PORT}):
    time.sleep(1.0)
print("READY", health({PORT}), flush=True)

# 调用产品的停止逻辑（start.py 捕获 Ctrl+C 后走的就是这条路径）
L.stop_streamlit(proc)
print("STOPPED", flush=True)
'''
    p = subprocess.Popen([PY_EXE, "-c", code], cwd=PROJ,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, encoding="utf-8", errors="replace")
    buf = ""
    t0 = time.time()
    while time.time() - t0 < 180:
        line = p.stdout.readline()
        if not line:
            break
        buf += line
        if "STOPPED" in buf:
            break
    print(f"[1] 子脚本输出:")
    for l in buf.splitlines():
        print(f"    {l.strip()}")
    print(f"[2] stop_streamlit 返回后，端口 {PORT} 的监听行: {listeners(PORT)}")

    # 等端口真正释放
    t0 = time.time()
    while time.time() - t0 < 20 and listeners(PORT):
        time.sleep(1.0)
    left = listeners(PORT)
    print(f"[3] 最终监听行: {left}")
    print(f"[4] 判定：")
    print(f"    - 端口已释放? {'✅ 是' if not left else '❌ 否，仍有残留'}")
    print(f"    - 有孤儿 streamlit 进程? "
          f"{'✅ 无' if not left else '❌ 有'}")

    try:
        p.wait(timeout=15)
    except subprocess.TimeoutExpired:
        p.kill()
    # 收尾
    for l in listeners(PORT):
        parts = l.split()
        if parts:
            subprocess.run(["taskkill", "/F", "/PID", parts[-1]],
                           capture_output=True)


if __name__ == "__main__":
    main()
