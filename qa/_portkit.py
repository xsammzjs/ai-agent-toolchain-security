# -*- coding: utf-8 -*-
"""端口与进程工具（QA 内部模块）

=====================================================
职责
=====================================================
只放「跟端口/进程打交道」的低层工具：
  - 测试端口的挑选与加锁（并发跑时互不干扰）
  - 哑巴占用者（占住端口模拟冲突）的启动与**保证清理**
  - netstat 监听查询、端口空闲探测

被 cases_*.py 用例模块调用；不要在这里写断言逻辑。
"""

from __future__ import annotations

import os
import socket
import subprocess
import time
from pathlib import Path
from typing import List

ROOT = Path(__file__).resolve().parent.parent
VENV_PY = ROOT / ".venv" / "Scripts" / "python.exe"

# 测端口用的哑巴占用者端口（避开 8501）
#
# 🔴 端口必须**每个进程实例唯一**，否则并发跑的验收脚本会互相
#    kill_port_listeners → 双方结果都不可信，还可能误杀对方的服务。
#
#    ⚠️ 不要只用 `pid % N` 派生 —— PID 会回收复用，两个并发实例完全
#    可能撞到同一个余数（实测踩过：症状是「服务莫名消失、退出码
#    4294967295 = taskkill /F 的特征」）。所以这里用
#    **随机起点 + 逐个试占用**，并在候选端口上放一个带 PID 的锁文件，
#    做到「逻辑独占」而不只是「碰巧不撞」。






def netstat_listening(port: int) -> List[str]:
    """返回该端口 LISTENING 的 netstat 行（GBK 解码）。

    ⚠️ 端口必须**精确匹配**：``":8765" in line`` 会把 ``":87650"`` 也算进来
    （实测确认），导致「以为端口被占」或「以为端口已释放」的误判。
    netstat 的本地地址列格式是 ``127.0.0.1:8765`` + 空格，
    所以用 ``":<port> "``（带尾随空格）就能精确命中。
    """
    proc = subprocess.run(["netstat", "-ano", "-p", "TCP"], capture_output=True)
    out = proc.stdout.decode("gbk", errors="replace")
    needle = f":{port} "
    return [l.strip() for l in out.splitlines()
            if needle in l and "LISTENING" in l]



def port_is_free(port: int, host: str = "127.0.0.1") -> bool:
    """端口是否空闲 —— **不能**设 SO_REUSEADDR（Windows 上会误判）。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if os.name != "nt":
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()



def start_port_holder(port: int, reuse: bool = False, addr: str = "127.0.0.1"):
    """启动一个占用端口的哑巴进程，返回 Popen。

    🔴 两个必须做对的地方（都踩过坑）：

    1. **启动失败必须能被发现**：端口被占时 bind 抛异常、进程直接退出，
       stdout 关闭、readline() 返回空串。若把空串当成功，
       「占用者其实没起来」会被当成「占用成功」，把后面所有断言带偏。
       所以这里要求读到 "HELD" 且进程还活着，否则抛 RuntimeError。

    2. **bind 失败要重试**：端口可能还在 TIME_WAIT，
       刚 kill 掉上一个占用者立刻重绑会失败。带退避重试几次。

    调用方**必须**用 try/finally 保证 holder 被 kill —— 见 kill_holder()。
    """
    code = f'''
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
if {reuse}:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("{addr}", {port}))
s.listen(5)
print("HELD", flush=True)
time.sleep(120)
'''
    last_err = ""
    for attempt in range(4):
        proc = subprocess.Popen([str(VENV_PY), "-c", code],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True)
        line = proc.stdout.readline()
        if "HELD" in (line or "") and proc.poll() is None:
            time.sleep(0.3)
            return proc
        # 启动失败：把错误信息收回来，并确认进程真的退出了
        # （stderr 单独收，避免 traceback 刷屏 —— X2 用例会故意触发失败）
        try:
            err = proc.stderr.read() if proc.stderr else ""
        except Exception:                      # noqa: BLE001
            err = ""
        last_err = (err or line or "").strip()
        proc.kill()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        try:
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()
        except Exception:                      # noqa: BLE001
            pass
        time.sleep(1.0 + attempt)             # 退避，等 TIME_WAIT 释放
    raise RuntimeError(
        f"哑巴占用者没能占用 {addr}:{port}（重试 4 次均失败）：{last_err}")



def kill_holder(proc) -> None:
    """**保证**占位进程被清理干净（异常路径也必须走到这里）。"""
    if proc is None:
        return
    try:
        if proc.poll() is None:
            proc.kill()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    except Exception:                          # noqa: BLE001
        pass
    finally:
        # 兜底：万一 kill 没生效，用端口反查再杀一次
        try:
            for line in netstat_listening(_holder_port_of(proc)):
                parts = line.split()
                if parts:
                    kill_pid(int(parts[-1]))
        except Exception:                      # noqa: BLE001
            pass



def _holder_port_of(proc) -> int:
    """从占位进程的命令行里取回端口号（兜底清理用）。"""
    try:
        cmd = " ".join(proc.args)
        m = re.search(r"\((\"?'?\d+\.?'?),\s*(\d+)\)", cmd)
        if m:
            return int(m.group(2))
        m = re.search(r"bind\(\(.*?,\s*(\d+)\)", cmd)
        if m:
            return int(m.group(1))
    except Exception:                          # noqa: BLE001
        pass
    return TEST_PORT



def kill_pid(pid: int) -> None:
    subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                   capture_output=True)



def kill_port_listeners(port: int) -> None:
    """杀掉监听指定端口的所有进程。

    ⚠️ 只应用于**本进程实例专属**的测试端口（TEST_PORT 按 PID 派生），
    绝不能拿去扫 8501 等公共端口 —— 那会杀掉别人的服务。
    """
    for line in netstat_listening(port):
        parts = line.split()
        if parts:
            kill_pid(int(parts[-1]))
    # 等端口真正释放（taskkill 是异步的）
    deadline = time.time() + 5
    while time.time() < deadline:
        if not netstat_listening(port):
            break
        time.sleep(0.3)


# 本进程实例专属的测试端口（在 _portlock 里挑，这里转出去给用例用）
from _portlock import TEST_PORT                          # noqa: E402,F401
