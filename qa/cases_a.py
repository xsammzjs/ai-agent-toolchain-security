# -*- coding: utf-8 -*-
"""用例组 A / B —— 文件编码、cmd 解析、依赖检测

  A1 bat 编码：无 BOM + CRLF
  A2 bat 能被 cmd.exe 正常解析
  A3 bat 有 chcp 65001（中文不乱码）
  B1 bat 依赖检查覆盖全部必需包
  B2 依赖齐全时不重复安装
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import List, Tuple

from _harness import (
    BAT,
    bat_bytes,
    bat_line_endings,
    Case,
    has_bom,
    Result,
    ROOT,
    run_cmd,
    START_PY,
    VENV_PY,
)



# ==========================================================
# 用例
# ==========================================================
def case_a1_bat_encoding(res: Result) -> None:
    """A1: .bat 文件编码 —— 不能有 BOM，且必须是 CRLF 换行。"""
    if not BAT.exists():
        res.check(False, f"文件不存在：{BAT}")
        return
    data = bat_bytes()
    res.check(not has_bom(data),
              f"BOM 检测：{'有 BOM（cmd.exe 会报语法错！）' if has_bom(data) else '无 BOM'}")
    crlf, bare_lf = bat_line_endings(data)
    res.check(bare_lf == 0, f"换行符：CRLF {crlf} 行，裸 LF {bare_lf} 行")



def _make_bat_probe() -> Tuple[Path, str]:
    """造一份「净化副本」：把有副作用 / 会阻塞的指令换成无害 echo。

    需要处理三类：
      - pause            —— 会等按键，stdin 接 DEVNULL 也可能挂住
      - 拉起 start.py    —— 会真的开服务（只测退出码，不需要）
      - 自举 cmd /c call —— 原样保留（这是被测结构的一部分）
    返回 (副本路径, 说明)。
    """
    data = bat_bytes()
    text = data.decode("utf-8-sig", errors="replace")
    patched: List[str] = []
    for line in text.splitlines():
        low = line.lower().strip()
        if low.startswith("cd /d"):
            patched.append(f'cd /d "{ROOT}"')
        elif "start.py" in low:
            patched.append('echo [SANITIZED] start.py launch (skipped by QA)')
        elif low.startswith("pause"):
            patched.append('echo [SANITIZED] pause (skipped by QA)')
        else:
            patched.append(line)

    tmp_dir = ROOT / "temp_upload" / "_qa_bat_probe"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    probe = tmp_dir / "probe.bat"
    probe.write_bytes(("\r\n".join(patched) + "\r\n").encode("utf-8"))
    return probe, "已在 temp_upload/_qa_bat_probe/probe.bat 生成净化副本"



def case_a2_bat_cmd_parse(res: Result) -> None:
    """A2: .bat 能否被 cmd.exe 正常解析（无 BOM 语法错）。

    注意：**不能直接跑原 .bat** —— 它会真的拉起服务、开浏览器、还可能
    卡在交互式 set /p 或 pause 上。这里跑净化副本（只把有副作用的几处
    换成 echo），其余全部原样保留，从而真实检验 cmd.exe 对该文件的解析。
    """
    if not BAT.exists():
        res.check(False, f"文件不存在：{BAT}")
        return
    data = bat_bytes()
    if has_bom(data):
        res.check(False, "含 BOM —— cmd.exe 第一行会报 "
                         "'xxx 不是内部或外部命令'，双击必然出乱码错误")
        return

    probe, note = _make_bat_probe()
    res.note(note)
    try:
        rc, out = run_cmd(["cmd", "/c", str(probe)], cwd=ROOT, timeout=120)
        bad = [ln for ln in out.splitlines()
               if "不是内部或外部命令" in ln or "不是可识别的" in ln
               or "命令语法不正确" in ln or "unexpected" in ln.lower()]
        res.check(not bad,
                  f"cmd.exe 解析无语法错误（捕获到 {len(bad)} 条语法错）")
        for ln in bad[:5]:
            res.note(f"语法错误行：{ln.strip()}")
        # 净化副本应能跑到「交给 start.py」这一步
        reached = any(k in out for k in ("start.py", "虚拟环境", "端口", "1/5"))
        res.check(reached, "批处理能实际执行到启动阶段（不只是解析通过）")
        res.note(f"输出片段：{out.strip()[:400]!r}")
    finally:
        try:
            probe.unlink()
        except OSError:
            pass



def case_a3_bat_codepage(res: Result) -> None:
    """A3: .bat 必须 chcp 65001，否则中文输出乱码。"""
    if not BAT.exists():
        res.check(False, f"文件不存在：{BAT}")
        return
    text = BAT.read_text(encoding="utf-8-sig", errors="replace")
    has_chcp = "chcp 65001" in text.lower()
    res.check(has_chcp, f"chcp 65001：{'有' if has_chcp else '没有（中文会乱码）'}")



def case_b1_bat_dep_check(res: Result) -> None:
    """B1: .bat 的依赖检查覆盖 modules/ 与 views/ 真正 import 的第三方库。"""
    if not BAT.exists():
        res.check(False, f"文件不存在：{BAT}")
        return
    text = BAT.read_text(encoding="utf-8-sig", errors="replace").lower()
    # 代码里真正 import 的第三方包（从 requirements.txt + 源码 import 扫描得出）
    needed = {"streamlit", "pandas", "requests", "nvdlib", "packaging",
              "docx", "reportlab", "dotenv", "rarfile"}
    missing = {m for m in needed if m not in text}
    res.check(not missing, f"依赖检查清单覆盖全部必需包（缺：{sorted(missing) or '无'}）")



def case_b2_no_reinstall(res: Result) -> None:
    """B2: 依赖齐全时不得重装 —— start.py --check 应秒回且不碰网络。

    断言用**多候选关键词**而不是单一固定短语 —— 文案会变，
    语义（"不会重复安装"）不变，所以优先匹配「重复安装」四个字，
    再退到其它等价表述。
    """
    if not START_PY.exists():
        res.check(False, f"start.py 不存在：{START_PY}")
        return
    t0 = time.time()
    rc, out = run_cmd([str(VENV_PY), "start.py", "--check"], timeout=180)
    dt = time.time() - t0
    res.check(rc == 0, f"start.py --check 退出码 = {rc}")

    # 候选关键词：任一命中即认为「明确表示不重复安装」
    candidates = (
        "重复安装",         # 最通用：「不会重复安装」「无需重复安装」都含这四个字
        "依赖齐全",
        "依赖检查通过",
        "组件都已就绪",
        "都已就绪",
    )
    hit = next((k for k in candidates if k in out), None)
    res.check(hit is not None,
              f"输出明确表示依赖已就绪、不重复安装（命中关键词：{hit or '无'}）")
    res.check(dt < 60, f"耗时 {dt:.1f}s（应远快于首次安装的 2-5 分钟）")

    # 真的没装东西：输出里不应出现 pip install 的痕迹
    res.check("pip install" not in out,
              "输出中无 pip install 痕迹（确认没有触发重装）")
    res.note(f"--check 输出片段：{out.strip()[:400]!r}")


# ==========================================================
# 本模块的用例注册表
# ==========================================================
CASES: List[Case] = [
    ("A1", "bat 编码：无 BOM + CRLF", case_a1_bat_encoding, True),
    ("A2", "bat 能被 cmd.exe 正常解析", case_a2_bat_cmd_parse, True),
    ("A3", "bat 有 chcp 65001（中文不乱码）", case_a3_bat_codepage, True),
    ("B1", "bat 依赖检查覆盖全部必需包", case_b1_bat_dep_check, True),
    ("B2", "依赖齐全时不重复安装", case_b2_no_reinstall, True),
]
