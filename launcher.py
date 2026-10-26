# -*- coding: utf-8 -*-
"""launcher.py —— 启动器内核（AI 技能与依赖漏洞检测平台）

职责边界
--------
* ``launcher.py``（本文件）：所有**可复用**的启动机制
  —— 找虚拟环境、检依赖、探端口、开浏览器、拉起/停止 streamlit。
* ``start.py``：命令行外壳，负责解析参数、组织流程、打���人类可读的提示。

这样切分的理由：仓库的架构体检（``samples/check_architecture.py``）
要求单文件不超过 700 行，而且「启动逻辑只有一份」——
``快速运行.bat`` 与 ``python start.py`` 走的是同一条代码路径。

对外可直接使用的 API：
    ensure_venv() / ensure_dependencies() / port_is_free() /
    find_free_port() / health_ok() / open_browser() / lan_ip() /
    start_streamlit() / wait_until_ready() / stop_streamlit()
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path
from typing import List, Optional, Tuple

# ==========================================================
# 常量
# ==========================================================
APP_TITLE = "AI 技能与依赖漏洞检测平台"
ROOT = Path(__file__).resolve().parent
LAUNCHER_ROOT = ROOT          # 别名：start.py 里用起来更直观
VENV_DIR = ROOT / ".venv"
REQUIREMENTS = ROOT / "requirements.txt"
DEFAULT_PORT = 8501
PORT_SCAN_COUNT = 60          # 端口被占时，最多往后找 60 个
HEALTH_PATH = "/_stcore/health"
STARTUP_TIMEOUT = 90          # 等待服务就绪的最长秒数
TOTAL_STEPS = 5               # 界面上显示的步骤总数

# 运行时真正需要的模块（与 requirements.txt 对应）
REQUIRED_MODULES: Tuple[str, ...] = (
    "streamlit",   # Web 框架
    "pandas",      # 数据处理
    "requests",    # HTTP 请求
    "nvdlib",      # NVD 漏洞库
    "packaging",   # 版本号比较
    "docx",        # python-docx，DOCX 报告
    "reportlab",   # PDF 报告
    "dotenv",      # 读取 .env
    "rarfile",     # RAR 压缩包支持
)

# 检查依赖用的探测脚本（在子进程里跑，避免污染当前进程）
_CHECK_CODE = (
    "import importlib.util as u\n"
    "mods = %r\n"
    "print(' '.join(m for m in mods if u.find_spec(m) is None))\n" % (REQUIRED_MODULES,)
)

# 本机请求专用 opener：显式清空代理，避免 http_proxy 环境变量把
# 127.0.0.1 的健康检查请求转发到代理服务器上。
_LOCAL_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class LauncherError(Exception):
    """启动过程中的可预期错误 —— 会被转成友好提示交给用户。"""


# ==========================================================
# 输出工具
# ==========================================================
def _supports_color() -> bool:
    return sys.stdout.isatty() and os.name != "nt"


def enable_line_buffering() -> None:
    """让进度提示实时刷新 —— 否则输出重定向到文件时会被缓冲到退出才显示。"""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(line_buffering=True)      # type: ignore[union-attr]
        except (AttributeError, OSError, ValueError):
            pass


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _supports_color() else text


def ok(text: str) -> None:
    print(f"      {_c('OK', '32')}  {text}")


def warn(text: str) -> None:
    print(f"      {_c('!!', '33')}  {text}")


def fail(text: str) -> None:
    print(f"      {_c('XX', '31')}  {text}")


def step_line(index: int, total: int, message: str) -> None:
    """打印一步的结果，形如 `[1/5] 找到项目虚拟环境 .venv ...`。"""
    print(f"{_c(f'[{index}/{total}]', '36')} {message}")


def banner() -> None:
    """启动横幅。"""
    line = "=" * 46
    print(line)
    print(f"  {APP_TITLE}  一键启动")
    print(line)


# ==========================================================
# Python 解释器与虚拟环境
# ==========================================================
def venv_python() -> Path:
    """项目虚拟环境里的解释器路径（跨平台）。"""
    if os.name == "nt":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def python_version(exe: str) -> Optional[Tuple[int, int]]:
    """返回 (major, minor)；不可用时返回 None。"""
    try:
        proc = subprocess.run(
            [exe, "-c", "import sys; print('%d.%d' % sys.version_info[:2])"],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    try:
        major, minor = proc.stdout.strip().split(".")[:2]
        return int(major), int(minor)
    except (ValueError, IndexError):
        return None


def find_base_python() -> Optional[str]:
    """找一个可用的 Python 3.x，用来创建虚拟环境。"""
    candidates: List[str] = []
    own = getattr(sys, "executable", "") or ""
    if own and "python" in os.path.basename(own).lower():
        candidates.append(own)
    for name in ("python3", "python"):
        found = shutil.which(name)
        if found:
            candidates.append(found)
    for cand in candidates:
        version = python_version(cand)
        if version and version[0] >= 3:
            return cand
    return None


def ensure_venv() -> Path:
    """返回可用的虚拟环境解释器；没有就创建。"""
    python = venv_python()
    if python.exists():
        return python

    base = find_base_python()
    if base is None:
        raise LauncherError(
            "没有找到可用的 Python。\n"
            "        请安装 Python 3.11 或 3.13（https://www.python.org/downloads/），\n"
            "        安装时务必勾选 Add Python to PATH，装完重开终端再运行。"
        )

    print(f"      正在创建虚拟环境 .venv（基于 {base}）...")
    try:
        subprocess.run([base, "-m", "venv", str(VENV_DIR)], check=True)
    except subprocess.CalledProcessError as exc:
        raise LauncherError(
            f"创建虚拟环境失败（退出码 {exc.returncode}），请检查 Python 安装是否完整。"
        ) from exc
    except OSError as exc:
        raise LauncherError(f"创建虚拟环境失败：{exc}") from exc

    if not python.exists():
        raise LauncherError("创建虚拟环境失败：.venv 里的 python.exe 没有生成。")
    return python


# ==========================================================
# 依赖
# ==========================================================
def missing_modules(python: Path) -> List[str]:
    """返回缺失的第三方模块列表。"""
    try:
        proc = subprocess.run(
            [str(python), "-c", _CHECK_CODE],
            capture_output=True, text=True, timeout=120,
        )
    except (OSError, subprocess.SubprocessError):
        return list(REQUIRED_MODULES)
    if proc.returncode != 0:
        return list(REQUIRED_MODULES)
    return proc.stdout.split()


def ensure_dependencies(python: Path) -> None:
    """缺什么装什么；已齐全则完全不碰网络。"""
    missing = missing_modules(python)
    if not missing:
        step_line(2, TOTAL_STEPS, "依赖检查通过，组件都已就绪（不会重复安装）")
        return

    warn(f"缺少依赖：{'、'.join(missing)}")
    print("      正在安装（首次运行约需 2-5 分钟，请耐心等待）...")
    if not REQUIREMENTS.exists():
        raise LauncherError(f"依赖清单不存在：{REQUIREMENTS}")

    try:
        subprocess.run(
            [str(python), "-m", "pip", "install", "--upgrade", "pip", "-q"],
            check=True,
        )
        subprocess.run(
            [str(python), "-m", "pip", "install", "-r", str(REQUIREMENTS)],
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        raise LauncherError(
            f"依赖安装失败（退出码 {exc.returncode}），通常是网络问题。\n"
            "        可以换国内镜像源重试：\n"
            f'        "{python}" -m pip install -r "{REQUIREMENTS}" '
            "-i https://pypi.tuna.tsinghua.edu.cn/simple"
        ) from exc
    except OSError as exc:
        raise LauncherError(f"依赖安装失败：{exc}") from exc

    still_missing = missing_modules(python)
    if still_missing:
        raise LauncherError(
            f"依赖安装后仍然缺少：{'、'.join(still_missing)}，请检查网络后重试。"
        )
    ok("依赖安装完成")


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
        r = subprocess.run(
            ["cmd", "/c", "netstat", "-ano", "-p", "TCP"],
            capture_output=True, text=True, encoding="gbk", errors="replace",
        )
    except (OSError, subprocess.SubprocessError):
        return False
    for line in r.stdout.splitlines():
        if "LISTENING" not in line:
            continue
        parts = line.split()
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
        for info in socket.getaddrinfo(socket.gethostname(), None,
                                       socket.AF_INET):
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


# ==========================================================
# 启动 / 停止服务
# ==========================================================
def start_streamlit(python: Path, port: int, host: str) -> subprocess.Popen:
    """拉起 streamlit 子进程。"""
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
        return subprocess.Popen(cmd, cwd=str(ROOT), env=env,
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
