# -*- coding: utf-8 -*-
"""launcher/const.py —— 启动器共享常量与异常类型

单独放一个模块，是为了让 output/env/net/proc 四个子模块都能
直接 import 它，而不会互相形成循环依赖。
"""

from __future__ import annotations

from pathlib import Path
from typing import Tuple

# ==========================================================
# 项目路径
# ==========================================================
# 注意：本文件在 launcher/ 包内，所以 .parent 是包目录，
# .parent.parent 才是项目根目录。
LAUNCHER_ROOT = Path(__file__).resolve().parent.parent
ROOT = LAUNCHER_ROOT               # 别名：start.py 里用起来更直观
VENV_DIR = LAUNCHER_ROOT / ".venv"
REQUIREMENTS = LAUNCHER_ROOT / "requirements.txt"

# ==========================================================
# 运行参数
# ==========================================================
APP_TITLE = "AI 技能组合风险体检站"
DEFAULT_PORT = 8501
PORT_SCAN_COUNT = 60              # 端口被占时，最多往后找 60 个
HEALTH_PATH = "/_stcore/health"
STARTUP_TIMEOUT = 90              # 等待服务就绪的最长秒数
TOTAL_STEPS = 5                   # 界面上显示的步骤总数

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
CHECK_CODE = (
    "import importlib.util as u\n"
    "mods = %r\n"
    "print(' '.join(m for m in mods if u.find_spec(m) is None))\n" % (REQUIRED_MODULES,)
)


class LauncherError(Exception):
    """启动过程中的可预期错误 —— 会被转成友好提示交给用户。"""
