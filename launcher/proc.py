# -*- coding: utf-8 -*-
"""launcher/proc.py —— streamlit 子进程的拉起、就绪等待与干净停止

Windows 上有两个坑，这里都处理了：
  * Ctrl+C 会同时打到子进程（uvicorn 走优雅关闭，端口好一会儿还占着）→
    子进程放进独立进程组，改由父进程显式收尾；
  * ``terminate()`` 不会连带结束子孙进程 → 用 ``taskkill /T`` 杀整棵树。
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

from launcher.const import LauncherError, LAUNCHER_ROOT
from launcher.net import health_ok

__all__ = ["start_streamlit", "wait_until_ready", "stop_streamlit"]


def start_streamlit(python: Path, port: int, host: str) -> subprocess.Popen:
    """拉起 streamlit 子进程。

    Windows 上用 ``CREATE_NEW_PROCESS_GROUP`` 把子进程放进**独立进程组**：
    这样 Ctrl+C 只送到 start.py 自己，子进程不会跟着一起被 Ctrl+C 打断
    （uvicorn 收到 Ctrl+C 后会走优雅关闭，可能要好几秒，这期间端口还被占着，
    看起来就像「停了服务但端口没释放」的孤儿进程）。

    改成由父进程显式 terminate + wait 子进程，端口一定能干净释放。
    """
    cmd = [
        str(python), "-m", "streamlit", "run", "main.py",
        "--server.port", str(port),
        "--server.address", host,
        "--server.headless", "true",
    ]
    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("STREAMLIT_BROWSER_GATHER_USAGE_STATS", "false")
    # 本机回环地址不经过代理，避免代理导致浏览器连不上本地服务
    no_proxy = env.get("NO_PROXY") or env.get("no_proxy") or ""
    for name in ("localhost", "127.0.0.1"):
        if name not in no_proxy:
            no_proxy = f"{no_proxy},{name}" if no_proxy else name
    env["NO_PROXY"] = no_proxy
    env["no_proxy"] = no_proxy
    # Windows：让子进程独立成进程组，便于整组结束
    creationflags = 0
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    try:
        return subprocess.Popen(cmd, cwd=str(LAUNCHER_ROOT), env=env,
                                creationflags=creationflags)
    except OSError as exc:
        raise LauncherError(f"启动 streamlit 失败：{exc}") from exc


def wait_until_ready(proc: subprocess.Popen, port: int, timeout: int) -> bool:
    """轮询健康检查接口，等待服务真正可用。"""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        if health_ok(port):
            return True
        time.sleep(0.5)
    return False


def stop_streamlit(proc: subprocess.Popen) -> None:
    """结束 streamlit 及其子进程。

    🔴 Windows 上 terminate() 不会连带结束子孙进程，
       streamlit 会再派生子进程 —— 只 terminate 会留下孤儿进程占着端口
       （下次启动就报「端口被占用」）。所以优先用 taskkill /T 杀整棵树。
    """
    if proc.poll() is not None:
        return
    if os.name == "nt":
        try:
            subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                           capture_output=True, timeout=15)
            proc.wait(timeout=10)
            return
        except (subprocess.TimeoutExpired, OSError):
            pass                      # 回退到下面的 terminate/kill
    try:
        proc.terminate()
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    except OSError:
        pass
