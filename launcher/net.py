# -*- coding: utf-8 -*-
"""launcher/net.py —— 端口探测、健康检查、浏览器、局域网地址

端口探测是这里最要紧的一段，踩过的坑都写在函数 docstring 里：
Windows 上 bind 试探不可靠，必须用 netstat 核对「有没有进程在 LISTEN」。
"""

from __future__ import annotations

import os
import socket
import subprocess
import threading
import urllib.error
import urllib.request
import webbrowser
from typing import List, Optional

from launcher.const import (
    HEALTH_PATH,
    LauncherError,
    PORT_SCAN_COUNT,
)

__all__ = [
    "port_is_free",
    "find_free_port",
    "health_ok",
    "kill_port_owner",
    "open_browser",
    "is_private_ip",
    "default_route_ip",
    "iter_local_ips",
    "lan_ip",
]

# 本机请求专用 opener：显式清空代理，避免 http_proxy 环境变量把
# 127.0.0.1 的健康检查请求转发到代理服务器上。
_LOCAL_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


# ==========================================================
# 端口
# ==========================================================
def _bind_succeeds(port: int, host: str) -> bool:
    """尝试绑定端口；成功说明「至少没有独占型占用者」。"""
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


def _listening_ports_windows() -> set:
    """Windows：列出所有处于 LISTENING 状态的 TCP 端口。

    为什么需要它：Windows 上**绑在 0.0.0.0 的服务不阻止别的进程
    bind 127.0.0.1**（只 bind 一次会误判「端口可用」→ 静默拉起
    第二个实例，旧实例变僵尸）。而 ``streamlit run main.py`` 默认
    绑的就是 0.0.0.0 —— 这是真实会踩到的场景。

    所以 Windows 上必须用「有没有进程在 LISTEN 这个端口」来判定，
    不能只靠 bind 试探。netstat 输出是 GBK 编码，要按 gbk 解码。
    """
    try:
        proc = subprocess.run(
            ["cmd", "/c", "netstat", "-ano", "-p", "TCP"],
            capture_output=True, text=True, encoding="gbk", errors="replace",
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return set()
    ports = set()
    for line in proc.stdout.splitlines():
        if "LISTENING" not in line:
            continue
        parts = line.split()
        if len(parts) < 2 or ":" not in parts[1]:
            continue
        try:
            ports.add(int(parts[1].rsplit(":", 1)[1]))
        except ValueError:
            continue
    return ports


def port_is_free(port: int, host: str = "127.0.0.1") -> bool:
    """端口是否真的空闲（可以被本服务使用）。

    Windows 上不能只靠 bind 试探：
      * 设了 SO_REUSEADDR 的占用者，别的进程照样能 bind 成功；
      * 绑在 0.0.0.0 的占用者，不阻止别人 bind 127.0.0.1。
    因此 Windows 上额外用 netstat 核对「有没有进程在 LISTEN 这个端口」。
    """
    if not _bind_succeeds(port, host):
        return False
    if os.name == "nt" and port in _listening_ports_windows():
        return False
    return True


def find_free_port(preferred: int, host: str = "127.0.0.1") -> int:
    """从 preferred 开始往后找第一个空闲端口。"""
    listening = _listening_ports_windows() if os.name == "nt" else set()
    for offset in range(PORT_SCAN_COUNT):
        candidate = preferred + offset
        if not _bind_succeeds(candidate, host):
            continue
        if os.name == "nt" and candidate in listening:
            continue
        return candidate
    raise LauncherError(
        f"{preferred} 到 {preferred + PORT_SCAN_COUNT - 1} 端口都被占用了，"
        "请先关掉一些程序后重试。"
    )


def health_ok(port: int, timeout: float = 3.0) -> bool:
    """检测某个端口上是否已经跑着本服务（Streamlit 健康检查）。

    注意：健康检查必须**绕过系统代理**。很多机器上设了
    ``http_proxy`` 环境变量，一旦走代理，本机请求会被转发到
    代理服务器上，直接变成连接失败。
    """
    url = f"http://127.0.0.1:{port}{HEALTH_PATH}"
    try:
        with _LOCAL_OPENER.open(url, timeout=timeout) as resp:
            body = resp.read(64).decode("utf-8", "replace").strip().lower()
            return resp.status == 200 and body == "ok"
    except (urllib.error.URLError, OSError, ValueError):
        return False


def kill_port_owner(port: int) -> bool:
    """结束占用端口的进程（Windows 用 taskkill）。返回是否成功。"""
    if os.name != "nt":
        return False
    try:
        proc = subprocess.run(
            ["cmd", "/c", "netstat", "-ano", "-p", "TCP"],
            capture_output=True, text=True, encoding="gbk", errors="replace",
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    for line in proc.stdout.splitlines():
        if "LISTENING" not in line:
            continue
        parts = line.split()
        # netstat -ano 的列：Proto / Local Address / Foreign / State / PID
        if len(parts) >= 5 and parts[1].endswith(f":{port}"):
            subprocess.run(["taskkill", "/PID", parts[4], "/F"],
                           capture_output=True)
            return True
    return False


# ==========================================================
# 浏览器
# ==========================================================
def open_browser(url: str, timeout: float = 3.0) -> bool:
    """打开默认浏览器；失败不影响服务本身。

    必须在守护线程里调用：Python 的 ``webbrowser`` 对
    ``GenericBrowser`` 会执行 ``p.wait()`` —— 也就是**等浏览器进程退出**。
    用真实浏览器（Edge/Chrome）时那可能是几分钟，启动流程会被卡住；
    在管道重定向的环境下还可能拖住整个进程组。

    所以这里只等一小会儿（默认 3 秒），拿不到结果也不影响服务启动。
    """
    result = {"ok": False}

    def _worker() -> None:
        try:
            result["ok"] = bool(webbrowser.open(url))
        except Exception:          # noqa: BLE001 - 浏览器异常一律忽略
            result["ok"] = False

    worker = threading.Thread(target=_worker, daemon=True)
    worker.start()
    worker.join(timeout)
    return result["ok"]


# ==========================================================
# 局域网地址
# ==========================================================
def is_private_ip(ip: str) -> bool:
    """判断是否 RFC1918 私有地址段（10/8、172.16/12、192.168/16）。"""
    try:
        first, second = int(ip.split(".")[0]), int(ip.split(".")[1])
    except (ValueError, IndexError):
        return False
    if first == 10:
        return True
    if first == 172 and 16 <= second <= 31:
        return True
    if first == 192 and second == 168:
        return True
    return False


def default_route_ip() -> Optional[str]:
    """默认路由用的源地址 —— 也就是「同一 WiFi 下的手机能访问到」的那个。

    多网卡机器上装了 VMware / VirtualBox / WSL 时，会多出一堆
    192.168.x.x 的虚拟网卡地址，只有默认路由这个才是真网卡。
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("10.255.255.255", 1))   # UDP connect 不会真的发包
        ip = sock.getsockname()[0]
        return ip if not ip.startswith("127.") else None
    except OSError:
        return None
    finally:
        sock.close()


def iter_local_ips() -> List[str]:
    """枚举本机所有 IPv4 地址（去重、排序）。"""
    found = set()
    default = default_route_ip()
    if default:
        found.add(default)
    try:
        import socket as _socket
        for info in _socket.getaddrinfo(_socket.gethostname(), None,
                                        _socket.AF_INET):
            found.add(info[4][0])
    except OSError:
        pass
    return sorted(found)


def lan_ip() -> Optional[str]:
    """取本机在局域网里的 IPv4 地址（用于 --host 0.0.0.0 时提示手机访问）。

    选取优先级：
      1. 默认路由网卡且落在私有地址段（10/8、172.16/12、192.168/16）
      2. 其它私有地址段里的地址
      3. 默认路由网卡（公网段也认）
      4. 任意非回环地址

    很多公司网络同时挂着私有段和公网段，私有段才是同一 WiFi 下
    手机能访问到的那个，所以**优先选私有段**。
    """
    candidates = [
        ip for ip in iter_local_ips()
        if not ip.startswith("127.") and not ip.startswith("169.254.")
    ]
    if not candidates:
        return None

    default = default_route_ip()
    if default and default in candidates and is_private_ip(default):
        return default
    private = [ip for ip in candidates if is_private_ip(ip)]
    if private:
        return private[0]
    if default and default in candidates:
        return default
    return candidates[0]
