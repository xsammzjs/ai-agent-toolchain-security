# -*- coding: utf-8 -*-
"""独立复核脚本：端口冲突的两种真实场景。

场景 1：占用者是**本服务自己**（用户双击了两次）
        -> 期望：不重复起服务，提示「已有本服务在运行」并直接给出访问地址
场景 2：占用者是**别的程序**（不是本服务）
        -> 期望：自动避让到下一个端口，且提示端口 == 实际端口

用文件写而不是 heredoc，避免 Windows 控制台编码把中文关键字搞乱。
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


def wait_health(port, timeout=90):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if health(port):
            return True
        time.sleep(1.5)
    return False


def run_start(port, extra=None, timeout=150):
    """跑 start.py，返回 (输出文本, 访问端口)。"""
    env = dict(os.environ)
    env["BROWSER"] = "echo"
    env["NO_PROXY"] = "127.0.0.1,localhost"
    env["no_proxy"] = env["NO_PROXY"]
    cmd = [PY_EXE, "start.py", "--port", str(port), "--timeout", "120"]
    if extra:
        cmd += extra
    p = subprocess.Popen(cmd, cwd=PROJ, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True,
                         encoding="utf-8", errors="replace", env=env)
    buf = ""
    t0 = time.time()
    while time.time() - t0 < timeout:
        line = p.stdout.readline()
        if not line:
            break
        buf += line
        if "访问地址" in buf or "直接访问" in buf:
            break
    m = re.search(r"https?://localhost:(\d+)", buf)
    return p, buf, (int(m.group(1)) if m else None)


def scenario_1_same_service():
    print("=" * 70)
    print("场景 1：占用者是本服务自己（用户双击了两次）")
    print("=" * 70)
    port = 8811
    p1 = subprocess.Popen([PY_EXE, "-m", "streamlit", "run", "main.py",
                           "--server.port", str(port),
                           "--server.address", "127.0.0.1",
                           "--server.headless", "true"], cwd=PROJ,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        ok = wait_health(port)
        print(f"[1] 本服务占住 {port}: health={ok}")
        p2, buf, shown = run_start(port)
        try:
            print(f"[2] start.py 提示端口 = {shown}")
            key = [l.strip() for l in buf.splitlines()
                   if "占用" in l or "访问地址" in l or "直接访问" in l
                   or "不用重复" in l]
            for l in key:
                print(f"    {l}")
            print(f"[3] 判定：")
            print(f"    - 提示端口 == 原端口 {port} ? {shown == port}")
            print(f"    - 原实例仍健康 ? {health(port)}")
            print(f"    - 未重复启动第二个实例 ? "
                  f"{'已有本服务在运行' in buf or '不用重复' in buf}")
        finally:
            p2.kill(); p2.wait()
    finally:
        p1.kill(); p1.wait()


def scenario_2_other_program():
    print()
    print("=" * 70)
    print("场景 2：占用者是别的程序（非本服务）")
    print("=" * 70)
    port = 8821
    # 用一个返回固定内容的普通 HTTP 服务占端口
    code = (
        "import http.server, socketserver\n"
        "class H(http.server.BaseHTTPRequestHandler):\n"
        "    protocol_version = 'HTTP/1.0'\n"
        "    def do_GET(self):\n"
        "        b = b'OTHER-APP'\n"
        "        self.send_response(200)\n"
        "        self.send_header('Content-Length', str(len(b)))\n"
        "        self.end_headers()\n"
        "        self.wfile.write(b)\n"
        "    def log_message(self, *a): pass\n"
        "class S(socketserver.TCPServer):\n"
        "    allow_reuse_address = False\n"
        "S(('0.0.0.0', %d), H).serve_forever()\n" % port
    )
    holder = subprocess.Popen([PY_EXE, "-c", code],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(1.5)
        p2, buf, shown = run_start(port)
        try:
            print(f"[1] 别的程序占住 {port}")
            key = [l.strip() for l in buf.splitlines()
                   if "占用" in l or "访问地址" in l]
            for l in key:
                print(f"    {l}")
            print(f"[2] start.py 提示端口 = {shown}")
            print(f"[3] 判定：")
            print(f"    - 已避让（提示端口 != {port}）? {shown != port and shown is not None}")
            if shown:
                ready = wait_health(shown, timeout=90)
                print(f"    - 新端口 {shown} 服务可用 ? {ready}")
                print(f"    - 旧端口 {port} 仍归原程序 ? "
                      f"{not health(port)}")
        finally:
            p2.kill(); p2.wait()
    finally:
        holder.kill(); holder.wait()


if __name__ == "__main__":
    scenario_1_same_service()
    scenario_2_other_program()
