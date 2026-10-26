# -*- coding: utf-8 -*-
"""launcher/output.py —— 终端输出与提示文案

只管「怎么把话说到用户面前」：颜色、缩进、步骤前缀、横幅。
不涉及任何启动逻辑。
"""

from __future__ import annotations

import os
import sys

from launcher.const import APP_TITLE

__all__ = [
    "enable_line_buffering",
    "ok",
    "warn",
    "fail",
    "step",
    "step_line",
    "banner",
    "show_url",
]


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


def step(index: int, total: int, title: str) -> None:
    """打印「第 N/M 步」的小标题。"""
    print(f"\n{_c(f'[{index}/{total}]', '36')} {title}")


def step_line(index: int, total: int, message: str) -> None:
    """打印一步的结果，形如 `[1/5] 找到项目虚拟环境 .venv ...`。"""
    print(f"{_c(f'[{index}/{total}]', '36')} {message}")


def banner() -> None:
    """启动横幅。"""
    line = "=" * 46
    print(line)
    print(f"  {APP_TITLE}  一键启动")
    print(line)


def show_url(url: str) -> None:
    """醒目地打印访问地址 —— 这行是用户最需要的信息。"""
    print()
    print(f"  {_c('>>> 访问地址： ' + url, '1;32')}")
    print()
