# -*- coding: utf-8 -*-
"""launcher/env.py —— Python 解释器、虚拟环境与依赖

回答两个问题：
  1. 用哪个 Python 解释器？（优先项目里的 .venv，没有就建一个）
  2. 依赖齐不齐？（缺什么装什么；已齐全则完全不碰网络）
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Tuple

from launcher.const import (
    CHECK_CODE,
    LauncherError,
    REQUIRED_MODULES,
    REQUIREMENTS,
    TOTAL_STEPS,
    VENV_DIR,
)
from launcher.output import ok, step_line, warn

__all__ = [
    "venv_python",
    "python_version",
    "find_base_python",
    "ensure_venv",
    "missing_modules",
    "ensure_dependencies",
]


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
            [str(python), "-c", CHECK_CODE],
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
