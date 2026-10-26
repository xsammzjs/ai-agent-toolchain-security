#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""start.py —— 一键启动器（AI 技能与依赖漏洞检测平台）

用法（在项目根目录执行）::

    python start.py

它会自动完成这些事，你不需要记任何命令：

1. 复用项目里的 ``.venv`` 虚拟环境；没有就自动创建；
2. 检测依赖，缺什么装什么，**已经装齐的绝不重复安装**；
3. 端口自动避让：8501 被占用就自动换到 8502、8503 ...
4. 打印真实访问地址，并自动打开浏览器；
5. 失败时给出人话提示，不甩裸 traceback。

常用参数::

    python start.py --port 8502     # 指定端口（被占用仍会自动往后找）
    python start.py --no-browser    # 不自动打开浏览器
    python start.py --host 0.0.0.0  # 允许同一局域网的其它设备访问
    python start.py --check         # 只做环境自检，不启动服务

停止服务：终端里按 ``Ctrl+C``，或直接关闭这个终端窗口。
"""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
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
VENV_DIR = ROOT / ".venv"
REQUIREMENTS = ROOT / "requirements.txt"
DEFAULT_PORT = 8501
PORT_SCAN_COUNT = 60          # 端口被占时，最多往后找 60 个
HEALTH_PATH = "/_stcore/health"
STARTUP_TIMEOUT = 90          # 等待服务就绪的最长秒数

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


def _enable_line_buffering() -> None:
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


def step(index: int, total: int, title: str) -> None:
    print(f"\n{_c(f'[{index}/{total}]', '36')} {title}")


def banner() -> None:
    line = "=" * 62
    print(line)
    print(f"  {APP_TITLE} · 一键启动")
    print(line)


def show_url(url: str) -> None:
    """醒目地打印访问地址 —— 这行是用户最需要的信息。"""
    print()
    print(f"  {_c('>>> 访问地址： ' + url, '1;32')}")
    print()


# ==========================================================
# Python 解释器与虚拟环境
# ==========================================================
def venv_python() -> Path:
    """项目虚拟环境里的解释器路径（跨平台）。"""
    if os.name == "nt":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def _python_version(exe: str) -> Optional[Tuple[int, int]]:
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
        version = _python_version(cand)
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
        ok("依赖齐全，无需重复安装")
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
def port_is_free(port: int, host: str = "127.0.0.1") -> bool:
    """端口是否可以被绑定。

    Windows 上 **不能** 设置 SO_REUSEADDR —— 那会让本机出现
    "两个进程绑同一个端口" 的怪现象，导致误判端口空闲。
    """
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


def find_free_port(preferred: int, host: str = "127.0.0.1") -> int:
    """从 preferred 开始往后找第一个空闲端口。"""
    for offset in range(PORT_SCAN_COUNT):
        candidate = preferred + offset
        if port_is_free(candidate, host):
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


# ==========================================================
# 浏览器
# ==========================================================
def open_browser(url: str) -> bool:
    """打开默认浏览器；失败不影响服务本身。"""
    try:
        return bool(webbrowser.open(url))
    except Exception:      # noqa: BLE001 - 浏览器异常一律忽略
        return False


# ==========================================================
# 启动服务
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
    for host in ("localhost", "127.0.0.1"):
        if host not in no_proxy:
            no_proxy = f"{no_proxy},{host}" if no_proxy else host
    env["NO_PROXY"] = no_proxy
    env["no_proxy"] = no_proxy
    try:
        return subprocess.Popen(cmd, cwd=str(ROOT), env=env)
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
    """尽力优雅地结束子进程。"""
    if proc.poll() is not None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    except OSError:
        pass


# ==========================================================
# 环境自检
# ==========================================================
def check_env_file() -> None:
    """检查 .env —— 缺失只提示，不阻断启动。"""
    if (ROOT / ".env").exists():
        ok("配置文件 .env 已就绪")
        return
    warn("未找到配置文件 .env，程序仍可运行，但会有以下影响：")
    print("         1. NVD 漏洞库走匿名接口，每次查询约 6 秒，扫描明显变慢")
    print("         2. 多源交叉验证的置信度评级降级为单源，结论可信度下降")
    print("         3. 当前若没有网络，请用界面里的「离线演示模式」查看预置场景")
    print("         需要配置文件的话，复制 .env.example 为 .env 即可（密钥可留空）")


# ==========================================================
# 主流程
# ==========================================================
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=f"{APP_TITLE} 一键启动器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"起始端口，默认 {DEFAULT_PORT}（被占用会自动往后找）")
    parser.add_argument("--host", default="127.0.0.1",
                        help="监听地址，默认 127.0.0.1；改成 0.0.0.0 可让同网段设备访问")
    parser.add_argument("--no-browser", action="store_true", help="启动后不自动打开浏览器")
    parser.add_argument("--check", action="store_true", help="只做环境自检，不启动服务")
    parser.add_argument("--timeout", type=int, default=STARTUP_TIMEOUT,
                        help=f"等待服务就绪的最长秒数，默认 {STARTUP_TIMEOUT}")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    _enable_line_buffering()
    os.chdir(ROOT)
    banner()

    # ---------- [1/4] Python 解释器 ----------
    step(1, 4, "准备 Python 解释器")
    try:
        python = ensure_venv()
    except LauncherError as exc:
        fail(str(exc))
        return 1
    version = _python_version(str(python))
    version_text = f"{version[0]}.{version[1]}" if version else "未知"
    ok(f"使用虚拟环境 .venv（Python {version_text}）")

    # ---------- [2/4] 依赖 ----------
    step(2, 4, "检查依赖")
    try:
        ensure_dependencies(python)
    except LauncherError as exc:
        fail(str(exc))
        return 1

    # ---------- [3/4] 端口 ----------
    step(3, 4, "检查端口")
    port = args.port
    if port_is_free(port, args.host):
        ok(f"端口 {port} 可用")
    elif health_ok(port):
        url = f"http://localhost:{port}"
        warn(f"端口 {port} 上已经有本服务在运行，不用重复启动")
        show_url(url)
        if not args.no_browser:
            print("      正在打开浏览器 ...")
            open_browser(url)
        print("      想再开一个实例，请用 python start.py --port 8502")
        return 0
    else:
        port = find_free_port(port + 1, args.host)
        warn(f"端口 {args.port} 已被其它程序占用，自动改用 {port}")

    if args.check:
        print()
        ok("环境自检通过，可以正常启动服务")
        return 0

    check_env_file()

    # ---------- [4/4] 启动 ----------
    step(4, 4, "启动服务")
    url = f"http://localhost:{port}"
    print(f"      正在启动，首次加载约需 10-30 秒 ...")
    try:
        proc = start_streamlit(python, port, args.host)
    except LauncherError as exc:
        fail(str(exc))
        return 1

    ready = wait_until_ready(proc, port, args.timeout)
    if not ready:
        if proc.poll() is not None:
            fail(f"服务启动失败，进程已退出（退出码 {proc.returncode}）")
            print("         请看上面的错误信息，或运行 python start.py --check 排查环境。")
            return 1
        fail(f"等待 {args.timeout} 秒后服务仍未就绪，已停止本次启动")
        stop_streamlit(proc)
        return 1

    show_url(url)
    print(f"      服务已就绪，停止方式：按 Ctrl+C，或直接关闭本终端窗口。")
    if not args.no_browser:
        print("      正在打开浏览器 ...")
        open_browser(url)
    print()

    # ---------- 保持前台运行 ----------
    try:
        return proc.wait()
    except KeyboardInterrupt:
        print()
        print("      正在停止服务 ...")
        stop_streamlit(proc)
        print("      服务已停止。")
        return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n已中断。")
        sys.exit(130)
    except LauncherError as exc:
        fail(str(exc))
        sys.exit(1)
    except Exception as exc:                     # noqa: BLE001
        # 兜底：不把裸 traceback 甩给用户，但保留可复制的关键信息
        fail(f"出现未预期的错误：{exc}")
        print(f"         详细信息：{type(exc).__name__}")
        print("         请把这段信息发给开发者。")
        sys.exit(1)
