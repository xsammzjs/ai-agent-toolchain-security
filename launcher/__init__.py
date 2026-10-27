# -*- coding: utf-8 -*-
"""launcher —— 启动器内核（AI 技能组合风险体检站）

职责边界
--------
* ``launcher/``（本包）：所有**可复用**的启动机制
  —— 找虚拟环境、检依赖、探端口、开浏览器、拉起/停止 streamlit。
* ``start.py``：命令行外壳，负责解析参数、组织流程、打印人类可读的提示。

这样切分的理由：仓库的架构体检（``samples/check_architecture.py``）
要求单文件不超过 700 行，而且「启动逻辑只有一份」——
``快速运行.bat`` 与 ``python start.py`` 走的是同一条代码路径。

子模块划分
----------
===================== ====================================================
``launcher.const``    共享常量与异常类型
``launcher.output``   终端输出与提示文案
``launcher.env``      Python 解释器、虚拟环境、依赖
``launcher.net``      端口探测、健康检查、浏览器、局域网地址
``launcher.proc``     streamlit 子进程的拉起 / 就绪等待 / 干净停止
===================== ====================================================

对外 API（``from launcher import ...`` 全部可用）：
    ensure_venv() / ensure_dependencies() / port_is_free() /
    find_free_port() / health_ok() / open_browser() / lan_ip() /
    start_streamlit() / wait_until_ready() / stop_streamlit()
"""

from __future__ import annotations

from launcher.const import (
    APP_TITLE,
    DEFAULT_PORT,
    HEALTH_PATH,
    LAUNCHER_ROOT,
    LauncherError,
    PORT_SCAN_COUNT,
    REQUIRED_MODULES,
    REQUIREMENTS,
    ROOT,
    STARTUP_TIMEOUT,
    TOTAL_STEPS,
    VENV_DIR,
)
from launcher.env import (
    ensure_dependencies,
    ensure_venv,
    find_base_python,
    missing_modules,
    python_version,
    venv_python,
)
from launcher.net import (
    default_route_ip,
    find_free_port,
    health_ok,
    is_private_ip,
    iter_local_ips,
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
    show_url,
    step,
    step_line,
    warn,
)
from launcher.proc import start_streamlit, stop_streamlit, wait_until_ready

__all__ = [
    # 常量
    "APP_TITLE",
    "DEFAULT_PORT",
    "HEALTH_PATH",
    "LAUNCHER_ROOT",
    "PORT_SCAN_COUNT",
    "REQUIRED_MODULES",
    "REQUIREMENTS",
    "ROOT",
    "STARTUP_TIMEOUT",
    "TOTAL_STEPS",
    "VENV_DIR",
    # 异常
    "LauncherError",
    # 输出
    "banner",
    "enable_line_buffering",
    "fail",
    "ok",
    "show_url",
    "step",
    "step_line",
    "warn",
    # 环境
    "ensure_dependencies",
    "ensure_venv",
    "find_base_python",
    "missing_modules",
    "python_version",
    "venv_python",
    # 网络 / 端口
    "default_route_ip",
    "find_free_port",
    "health_ok",
    "is_private_ip",
    "iter_local_ips",
    "kill_port_owner",
    "lan_ip",
    "open_browser",
    "port_is_free",
    # 进程
    "start_streamlit",
    "stop_streamlit",
    "wait_until_ready",
]
