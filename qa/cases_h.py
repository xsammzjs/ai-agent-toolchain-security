# -*- coding: utf-8 -*-
"""用例组 H —— 首次运行（慢速）

  H1 无 venv 首次运行能自建并装依赖

⚠️ 需要联网装依赖，耗时 2-5 分钟，所以默认不在常规套件里跑，
   用 `--slow` 或 `--only H1` 单独触发。
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from _harness import ROOT, Result, run_cmd, Case



def case_h1_no_venv_first_run(res: Result) -> None:
    """H1（慢速，opt-in）：没有 .venv 时能否自建并装依赖。

    ⚠️ **绝不能删项目的 .venv** —— 这里把项目复制到临时目录再测。
    ⚠️ 依赖安装要联网、耗时 2-5 分钟，所以默认不在常规套件里跑，
       用 `--only H1` 单独触发。
    """
    tmp = Path(tempfile.mkdtemp(prefix="qa_novenv_"))
    try:
        # 复制项目（排除 .venv / 大目录），模拟「用户刚拿到项目」
        for item in ("main.py", "config.py", "requirements.txt", "start.py",
                     "快速运行.bat"):
            src = ROOT / item
            if src.exists():
                shutil.copy2(src, tmp / item)
        # launcher 既可能是单文件 launcher.py，也可能是包 launcher/ ——
        # 两种都要复制，否则 start.py 的 `from launcher...` 会 ImportError。
        # （工程师把 launcher.py 拆成 launcher/ 包后，这里报过一次
        #   ModuleNotFoundError: No module named 'launcher'）
        single = ROOT / "launcher.py"
        if single.is_file():
            shutil.copy2(single, tmp / "launcher.py")
        pkg = ROOT / "launcher"
        if pkg.is_dir():
            shutil.copytree(pkg, tmp / "launcher",
                            ignore=shutil.ignore_patterns("__pycache__"))
        for sub in ("modules", "views", ".streamlit"):
            src = ROOT / sub
            if src.is_dir():
                shutil.copytree(src, tmp / sub,
                                ignore=shutil.ignore_patterns("__pycache__"))
        res.check(not (tmp / ".venv").exists(), "临时目录里确实没有 .venv")
        res.check((tmp / "launcher.py").exists() or (tmp / "launcher").is_dir(),
                  "临时目录里有 launcher（单文件或包），start.py 的 import 不会失败")

        # 用系统 Python 跑 start.py --check，验证它会自建 venv
        base = shutil.which("python") or shutil.which("py")
        if not base:
            res.check(False, "找不到系统 Python，无法测无 venv 场景")
            return
        cmd = ([base, "-3", "start.py", "--check"] if base.endswith("py.exe")
               else [base, "start.py", "--check"])
        rc, out = run_cmd(cmd, cwd=tmp, timeout=1800)
        res.note(f"临时目录 start.py --check 输出片段：{out.strip()[-600:]!r}")
        res.check(rc == 0, f"无 venv 场景退出码 = {rc}（应为 0）")
        res.check((tmp / ".venv" / "Scripts" / "python.exe").exists(),
                  "自动创建了 .venv\\Scripts\\python.exe")
        res.check("正在创建虚拟环境" in out or "创建" in out,
                  "输出说明了正在创建虚拟环境")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ==========================================================
# 本模块的用例注册表
# ==========================================================
CASES: List[Case] = [
    ("H1", "无 venv 首次运行能自建并装依赖（慢）", case_h1_no_venv_first_run, True),
]
