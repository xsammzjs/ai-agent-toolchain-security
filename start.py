#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""start.py —— 一键启动器（AI 技能组合风险体检站）

用法（在项目根目录执行）::

    python start.py

它会自动完成这些事，你不需要记任何命令：

1. 复用项目里的 ``.venv`` 虚拟环境；没有就自动创建；
2. 检测依赖，缺什么装什么，**已经装齐的绝不重复安装**；
3. 端口自动避让：8501 被占用就自动换到 8502、8503 ...
4. 打印真实访问地址，并自动打开浏览器；
5. 失败时给出人话提示，不甩裸 traceback。

常用参数::

    python start.py --port 8502     # 指定起始端口（被占用仍会自动往后找）
    python start.py --no-browser    # 不自动打开浏览器
    python start.py --host 0.0.0.0  # 允许同一局域网的其它设备访问
    python start.py --check         # 只做环境自检，不启动服务
    python start.py --ask-port      # 端口被占用时让你选怎么处理

停止服务：终端里按 ``Ctrl+C``，或直接关闭这个终端窗口。

实现说明：可复用的启动机制都在 ``launcher/`` 包里（output / env / net / proc
四个子模块），本文件只做「解析参数 + 组织流程 + 打印提示」。
``快速运行.bat`` 内部调用的也是本文件，因此**启动逻辑只有一份**。
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import time
from typing import List, Optional, Tuple

from launcher.const import (
    APP_TITLE,
    DEFAULT_PORT,
    LAUNCHER_ROOT,
    LauncherError,
    TOTAL_STEPS,
)
from launcher.env import ensure_dependencies, ensure_venv, python_version
from launcher.net import (
    find_free_port,
    health_ok,
    kill_port_owner,
    lan_ip,
    open_browser,
    port_is_free,
)
from launcher.output import (
    banner,
    enable_line_buffering,
    fail,
    ok,
    step_line,
    warn,
)
from launcher.proc import start_streamlit, stop_streamlit, wait_until_ready

__all__ = [
    "main",
    "port_is_free",       # 供验收脚本 import start 后直接调用
    "find_free_port",
    "health_ok",
    "lan_ip",
    "ensure_venv",
    "ensure_dependencies",
    "LauncherError",
]


# ==========================================================
# 端口选择
# ==========================================================
def _read_choice(prompt: str) -> Optional[str]:
    """读一行用户输入；非交互环境（EOF）返回 None。"""
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None


def choose_port_interactively(port: int, host: str,
                             already_running: bool = False) -> Optional[int]:
    """端口被占用时，让用户选：停旧进程 / 换端口 / 取消。

    返回实际要用的端口；用户取消或输入无效到底则返回 None。
    """
    for _ in range(5):
        print()
        print(f"  [警告] 端口 {port} 已被占用"
              + ("（本服务已在这个端口跑着）。" if already_running
                 else "（可能是别的程序占着，或之前的服务没关）。"))
        print("         很可能是之前启动的服务还在运行（那个黑窗口没关）。")
        print()
        print(f"         [1] 停掉占用端口的旧进程，继续用 {port}")
        print(f"         [2] 换一个端口启动（自动找 {port + 1}、{port + 2} ...）")
        print("         [0] 取消本次启动")
        print()
        choice = _read_choice("  请输入数字后按回车 [1/2/0]：")
        if choice is None:
            print("  没有收到输入（当前不是交互式终端），改为自动避让。")
            return find_free_port(port + 1, host)
        if choice == "1":
            print("  正在结束占用端口的旧进程 ...")
            if kill_port_owner(port):
                time.sleep(1.0)
                if port_is_free(port, host):
                    print(f"  端口 {port} 已释放，可以启动。")
                    return port
                print(f"  端口 {port} 仍被占用，请改选 [2]。")
                continue
            print("  没能结束该进程（可能需要管理员权限），请改选 [2]。")
            continue
        if choice == "2":
            new_port = find_free_port(port + 1, host)
            print(f"  端口 {new_port} 可用，将用它启动。")
            return new_port
        if choice == "0":
            print("  已取消启动。")
            return None
        print()
        print("  输入无效，请重新选择。")
    print("  多次输入无效，已取消启动。")
    return None


def resolve_port(args: argparse.Namespace) -> Tuple[Optional[int], bool]:
    """决定用哪个端口启动。

    返回 (端口, 是否已在运行)。
    端口为 None 表示用户取消；已在运行时不再重复启动。
    """
    port = args.port
    if port_is_free(port, args.host):
        step_line(4, TOTAL_STEPS, f"端口 {port} 可用。")
        return port, False

    already_running = health_ok(port)

    if args.ask_port:
        return choose_port_interactively(port, args.host, already_running), False

    # 自动模式
    if already_running:
        step_line(4, TOTAL_STEPS, f"端口 {port} 上已有本服务在运行，不用重复启动。")
        return port, True

    new_port = find_free_port(port + 1, args.host)
    step_line(4, TOTAL_STEPS,
              f"端口 {port} 已被其它程序占用，自动改用 {new_port}。")
    return new_port, False


# ==========================================================
# 配置文件检查
# ==========================================================
def check_env_file() -> None:
    """检查 .env —— 缺失只提示，不阻断启动。"""
    if (LAUNCHER_ROOT / ".env").exists():
        step_line(3, TOTAL_STEPS, "配置文件 .env 已就绪")
        return
    warn("未找到配置文件 .env，程序仍可运行，但会有以下影响：")
    print("         1. NVD 漏洞库走匿名接口，每次查询约 6 秒，扫描明显变慢")
    print("         2. 多源交叉验证的置信度评级降级为单源，结论可信度下降")
    print("         3. 当前若没有网络，请用界面里的「离线演示模式」查看预置场景")
    print("         需要配置文件的话，复制 .env.example 为 .env 即可（密钥可留空）")


# ==========================================================
# 停止服务
# ==========================================================
def _install_stop_handlers(proc) -> None:
    """接管 Ctrl+C / Ctrl+Break / 终止信号，先收干净子进程再退出。

    这段是「用户按 Ctrl+C 之后端口到底能不能被收回来」的全部关键，
    四个要点串起来读：

    1. **不能用 ``proc.wait()`` 等子进程**：Windows 上它阻塞在
       ``WaitForSingleObject`` 上，**不可中断**。主线程卡住 → Python 级的
       信号处理函数**永远排不上执行** → OS 只能按默认动作终止进程
       （退出码 3221225786 = STATUS_CONTROL_C_EXIT）→ 清理代码一行没跑 →
       **端口还被占着**，下次启动就报「端口被占用」。
    2. 所以前台等待改成**短超时轮询**（见调用处）：``time.sleep()`` 可被信号
       打断，信号处理才能及时执行，把子进程树收干净再退出。
    3. 子进程是用 ``CREATE_NEW_PROCESS_GROUP`` 起的 —— MSDN 明确写着该标志
       **禁用组内所有进程的 Ctrl+C**。也就是**子进程不会自己退出**，
       ``stop_streamlit()`` 是**唯一**能把端口收干净的主路径，不是兜底。
    4. ``stop_streamlit()`` 用 ``taskkill /T /F`` 杀**整棵进程树**：
       Windows 的 ``terminate()`` 不杀子孙进程，streamlit 派生的子进程会
       变成孤儿继续占着端口。

    ⚠️ **必须在子进程起来后立刻装**（见调用处注释）：服务冷启动要 10-30 秒，
    这期间 handler 没装的话，用户的 Ctrl+C 会被 OS 按默认动作终止进程
    （3221225786），Python 清理代码一行都不执行 → 端口一直被占。

    顺带：``CTRL_BREAK_EVENT`` 在 Python 里映射成 ``SIGBREAK``，其默认动作
    是直接终止进程（不抛 KeyboardInterrupt），所以必须显式接管，
    否则上面的清理逻辑同样不会执行。
    """
    def _handler(signum, _frame):        # noqa: ANN001 - 信号处理函数签名固定
        print()
        print("  正在停止服务 ...")
        try:
            stop_streamlit(proc)
        finally:
            print("  服务已停止。")
            sys.stdout.flush()
            sys.stderr.flush()
            os._exit(0)

    candidates = [signal.SIGINT, signal.SIGTERM]
    sigbreak = getattr(signal, "SIGBREAK", None)
    if sigbreak is not None:
        candidates.append(sigbreak)
    for sig in candidates:
        try:
            signal.signal(sig, _handler)
        except (ValueError, OSError, RuntimeError):
            pass    # 非主线程或平台不支持时忽略


# ==========================================================
# 命令行
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
    parser.add_argument("--ask-port", action="store_true",
                        help="端口被占用时让用户选择（停旧进程 / 换端口 / 取消）")
    parser.add_argument("--timeout", type=int, default=90,
                        help="等待服务就绪的最长秒数，默认 90")
    return parser


# 退出码约定
EXIT_OK = 0        # 正常启动 / 自检通过 / 服务已在运行
EXIT_CANCELLED = 2 # 用户主动取消（不是错误，调用方应友好提示）
EXIT_FAILED = 1    # 真正的失败


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    enable_line_buffering()
    os.chdir(LAUNCHER_ROOT)
    banner()

    # ---------- [1/5] Python 解释器 ----------
    try:
        python = ensure_venv()
    except LauncherError as exc:
        fail(str(exc))
        return 1
    version = python_version(str(python))
    version_text = f"{version[0]}.{version[1]}" if version else "未知"
    step_line(1, TOTAL_STEPS,
              f"找到项目虚拟环境 .venv，直接复用（Python {version_text}）")

    # ---------- [2/5] 依赖 ----------
    try:
        ensure_dependencies(python)
    except LauncherError as exc:
        fail(str(exc))
        return 1

    # ---------- [3/5] 配置文件 ----------
    check_env_file()

    # ---------- [4/5] 端口 ----------
    port, already_running = resolve_port(args)
    if port is None:
        print()
        print("  已取消启动。")
        return EXIT_CANCELLED      # 2：用户主动取消，不是错误

    if args.check:
        # --check 只做环境自检：不开浏览器、不碰端口
        print()
        ok("环境自检通过，可以正常启动服务。")
        return 0

    if already_running:
        print()
        print(f"  直接访问： http://localhost:{port}")
        print("  想再开一个实例，请用 python start.py --port 8502")
        print()
        if not args.no_browser:
            print("  正在打开浏览器 ...")
            open_browser(f"http://localhost:{port}")
        return 0

    # ---------- [5/5] 启动 ----------
    print()
    print("  " + "=" * 44)
    print("   正在启动服务，请稍候 ...")
    print("  " + "=" * 44)
    print()
    url = f"http://localhost:{port}"
    print(f"  >>> 访问地址： {url}")
    print("  停止服务： 按 Ctrl+C，或直接关闭本窗口")
    if not args.no_browser:
        print("  3 秒后会自动打开浏览器；没弹出来就手动复制上面的地址。")
    print()
    print("  正在启动，首次加载约需 10-30 秒 ...")

    try:
        proc = start_streamlit(python, port, args.host)
    except LauncherError as exc:
        fail(str(exc))
        return 1

    # 🔴 信号处理器必须**在子进程起来的第一时间**装上，不能等到服务就绪之后：
    #   ① 子进程在独立进程组里，**收不到 Ctrl+C**（见 _install_stop_handlers）；
    #   ② 服务冷启动要 10-30 秒，这期间 handler 还没装的话，用户的 Ctrl+C
    #      会被 OS 按默认动作处理（退出码 3221225786 = STATUS_CONTROL_C_EXIT），
    #      Python 的清理代码**一行都不会执行** → streamlit 变孤儿 → 端口一直被占；
    #   ③ 外部探针（浏览器、验收脚本）可能比 start.py 自己更早看到「服务就绪」，
    #      那一刻 handler 还没装，同样会漏。
    # 装 handler 只依赖 proc 本身，早装没有任何副作用。
    _install_stop_handlers(proc)

    ready = wait_until_ready(proc, port, args.timeout)
    if not ready:
        if proc.poll() is not None:
            fail(f"服务启动失败，进程已退出（退出码 {proc.returncode}）")
            print("         请看上面的错误信息，或运行 python start.py --check 排查环境。")
            return 1
        fail(f"等待 {args.timeout} 秒后服务仍未就绪，已停止本次启动")
        stop_streamlit(proc)
        return 1

    if args.host in ("0.0.0.0", "::"):
        ip = lan_ip()
        if ip:
            print(f"  >>> 手机/其它设备访问： http://{ip}:{port}")
            print("      （需在同一 WiFi 下；若打不开，检查 Windows 防火墙是否放行 Python）")
            print()
    if not args.no_browser:
        print("  正在打开浏览器 ...")
        open_browser(url)
    print()

    # ---------- 保持前台运行 ----------
    # 用轮询而不是 proc.wait()：Windows 上 Popen.wait() 阻塞在不可中断的
    # WaitForSingleObject 上，装了信号处理后 OS 不再默认终止进程，
    # 两者一叠加就成了「Ctrl+C 后进程卡住不退、端口一直被占」。
    # 详细原理见 _install_stop_handlers 的 docstring。
    # time.sleep() 是可被信号打断的，轮询能保证及时响应 Ctrl+C / Ctrl+Break。
    while proc.poll() is None:
        try:
            time.sleep(0.3)
        except KeyboardInterrupt:
            print()
            print("  正在停止服务 ...")
            stop_streamlit(proc)
            print("  服务已停止。")
            return 0
    return proc.returncode


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
