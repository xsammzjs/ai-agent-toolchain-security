# -*- coding: utf-8 -*-
"""精确定位：端口探测在「占用者绑定通配地址 0.0.0.0」时的行为。

Windows 的 socket 语义（与 Linux 不同）：
  - 绑定 0.0.0.0:P 的 socket 会占住**所有**本机地址的 P 端口；
  - 但另一个进程**仍然可以**绑定 127.0.0.1:P（更具体的地址优先），
    于是出现「两个进程同时监听 P」的怪现象，连到 127.0.0.1 的流量
    会被更具体的那个截走。

本脚本验证：
  A) 占用者绑 127.0.0.1:P  -> port_is_free(P,'127.0.0.1') 应为 BUSY（能发现）
  B) 占用者绑 0.0.0.0:P    -> port_is_free(P,'127.0.0.1') 实际是什么？
  C) 同上，start.py 会不会自动避让？
"""
import os
import socket
import subprocess
import sys
import time
import urllib.request

PROJ = r"D:\DeskApp\python_xiangmu\python-sbom-security-tool"
PY_EXE = os.path.join(PROJ, ".venv", "Scripts", "python.exe")
LOCAL = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def start_holder(port, addr):
    code = (
        "import socket, time\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "s.bind(('%s', %d))\n"
        "s.listen(5)\n"
        "print('HELD', flush=True)\n"
        "time.sleep(60)\n" % (addr, port)
    )
    p = subprocess.Popen([PY_EXE, "-c", code], stdout=subprocess.PIPE, text=True)
    line = p.stdout.readline()
    if "HELD" not in (line or ""):
        raise RuntimeError(f"占用者没能绑住 {addr}:{port}")
    time.sleep(0.4)
    return p


def check_free(port, host="127.0.0.1"):
    code = (
        "import sys; sys.path.insert(0, %r)\n"
        "import start\n"
        "print('FREE' if start.port_is_free(%d, %r) else 'BUSY')\n"
        % (PROJ, port, host)
    )
    r = subprocess.run([PY_EXE, "-c", code], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    return (r.stdout or "").strip().splitlines()[-1] if r.stdout.strip() else "(无输出)"


def netstat_rows(port):
    r = subprocess.run(["netstat", "-ano", "-p", "TCP"], capture_output=True)
    out = r.stdout.decode("gbk", errors="replace")
    return [l.strip() for l in out.splitlines()
            if f":{port}" in l and "LISTENING" in l]


def case(label, port, addr):
    print(f"\n--- {label}（占用者绑 {addr}:{port}）---")
    holder = start_holder(port, addr)
    try:
        print(f"  监听行: {netstat_rows(port)}")
        verdict = check_free(port)
        print(f"  port_is_free({port},'127.0.0.1') = {verdict}")
        # 对照：按通配地址探测
        verdict_any = check_free(port, "0.0.0.0")
        print(f"  port_is_free({port},'0.0.0.0')  = {verdict_any}")
    finally:
        holder.kill(); holder.wait()
        time.sleep(0.6)


if __name__ == "__main__":
    print("=" * 68)
    print("端口探测在不同占用者绑定方式下的行为")
    print("=" * 68)
    case("情形 A", 8831, "127.0.0.1")
    case("情形 B", 8832, "0.0.0.0")
