# -*- coding: utf-8 -*-
"""用例组 G —— bat 与 start.py 的交接

  G1 bat 委托 start.py（单一逻辑源）
  G2 --check 不开浏览器
  G3 bat 正确传递 start.py 退出码
  G4 start.py 接受 bat 传的 --ask-port
  G5 交互提示端口号跟随实际起始端口
  G6 用户取消时退出码非 0
  G7 信号退出后端口被释放
"""

from __future__ import annotations

import os
import subprocess
import time

from _harness import (
    BAT,
    Launcher,
    Result,
    ROOT,
    run_cmd,
    START_PY,
    VENV_PY,
)
from _portkit import (
    kill_holder,
    kill_port_listeners,
    netstat_listening,
    start_port_holder,
    TEST_PORT,
)



def case_g1_bat_delegates(res: Result) -> None:
    """G1: .bat 是否委托给 start.py（避免两套启动逻辑各自漂移）。"""
    if not BAT.exists():
        res.check(False, f"文件不存在：{BAT}")
        return
    text = BAT.read_text(encoding="utf-8-sig", errors="replace")
    if "start.py" in text:
        res.check(True, ".bat 已委托给 start.py（单一启动逻辑）")
    else:
        res.check(False, "❌ .bat 未引用 start.py —— 存在两套并行启动逻辑，"
                         "端口/浏览器/健康检查行为会不一致")



def case_g2_no_browser_in_check(res: Result) -> None:
    """G2: --check 模式不得打开浏览器（它承诺「只做环境自检」）。"""
    if not START_PY.exists():
        res.check(False, f"start.py 不存在：{START_PY}")
        return
    env = dict(os.environ)
    env["BROWSER"] = "echo"
    rc, out = run_cmd([str(VENV_PY), "start.py", "--check"], timeout=180,
                      env=env)
    echoed = [ln.strip() for ln in out.splitlines()
              if ln.strip().startswith("http://localhost:")]
    res.check(not echoed,
              f"--check 未触发浏览器打开（捕获到 {len(echoed)} 条 URL）")
    for ln in echoed[:2]:
        res.note(f"不该出现的浏览器 URL：{ln}")
    res.note(f"--check 输出片段：{out.strip()[:200]!r}")



def case_g3_bat_exit_code(res: Result) -> None:
    """G3: .bat 必须正确传递 start.py 的退出码。

    背景（真实踩过的坑）：bat 里用 `setlocal disabledelayedexpansion` +
    `%ERRORLEVEL%` 会在 setlocal 作用域内取到**空串**，导致 start.py
    即使成功，bat 也报「[启动失败]」。因此这里断言：
    启动成功时 bat 的退出码必须是 0，且不出现「[启动失败]」。

    这里跑**真实的 .bat**（不是净化副本）—— 因为要测的就是真实的
    退出码传递链路。传 `--check --no-browser` 让 start.py 快速成功退出，
    不拉起服务。stdin 接 DEVNULL，末尾的 `pause` 会立即返回（实测确认）。
    """
    if not BAT.exists():
        res.check(False, f"文件不存在：{BAT}")
        return
    rc, out = run_cmd(["cmd", "/c", str(BAT), "--check", "--no-browser"],
                      timeout=120)
    res.check(rc == 0,
              f"真实 bat 转发 --check --no-browser 时退出码 = {rc}（应为 0）")
    res.check("[启动失败]" not in out,
              "bat 未误报「[启动失败]」")
    res.check("环境自检通过" in out,
              "bat 确实把 start.py 的输出透传出来了")
    res.check("服务已停止" in out,
              "bat 打印了正常结束提示")
    res.note(f"bat 输出片段：{out.strip()[-400:]!r}")



def case_g4_bat_ask_port(res: Result) -> None:
    """G4: bat 传的 --ask-port 必须被 start.py 正确接受（不能因未知参数报错）。

    bat 现在固定传 `--ask-port`（端口被占时让用户选怎么处理）。
    若 start.py 不认这个参数，会直接 argparse 报错退出 2 —— 双击即失败。
    """
    if not START_PY.exists():
        res.check(False, f"start.py 不存在：{START_PY}")
        return
    rc, out = run_cmd([str(VENV_PY), "start.py", "--ask-port", "--check"],
                      timeout=180)
    res.check(rc == 0, f"start.py --ask-port --check 退出码 = {rc}（应为 0）")
    res.check("unrecognized arguments" not in out
              and "invalid choice" not in out,
              "start.py 接受 --ask-port 参数（无 argparse 报错）")
    res.note(f"输出片段：{out.strip()[-300:]!r}")



def case_g5_ask_port_prompt(res: Result) -> None:
    """G5: 交互提示里的端口号必须**跟随实际起始端口**，不能写死 8502。

    背景（真实修过的问题）：提示写死「自动找 8502、8503」，
    用户用 `--port 8899` 启动时提示会撒谎（说去 8502，实际会去找 8900）。

    验证：占住测试端口 -> `start.py --ask-port --port <该端口>`
         -> 断言提示里出现的是 <端口+1>、<端口+2>，且**不出现**写死的 8502。
    """
    if not START_PY.exists():
        res.check(False, f"start.py 不存在：{START_PY}")
        return
    kill_port_listeners(TEST_PORT)
    try:
        holder = start_port_holder(TEST_PORT, reuse=False, addr="127.0.0.1")
    except RuntimeError as exc:
        res.check(False, f"哑巴占用者没能占住端口：{exc}")
        return
    launcher = None
    try:
        launcher = Launcher(["--ask-port", "--port", str(TEST_PORT),
                             "--no-browser", "--timeout", "45"])
        launcher.pump(["请输入数字", "取消"], timeout=45)
        text = launcher.output
        res.note(f"交互提示输出：{text.strip()[-500:]!r}")

        nxt = TEST_PORT + 1
        res.check(f"{nxt}" in text,
                  f"提示里出现了实际起始端口 +1 = {nxt}")
        res.check("8502" not in text,
                  "提示里没有写死的 8502（应跟随实际起始端口）")
        # 三个选项都要在
        for opt in ("[1]", "[2]", "[0]"):
            res.check(opt in text, f"交互选项 {opt} 存在")
    finally:
        if launcher:
            launcher.close()
        kill_holder(holder)
        kill_port_listeners(TEST_PORT)



def case_g6_cancel_exit_code(res: Result) -> None:
    """G6: 用户选 [0] 取消时，退出码必须**非 0**（取消是用户的主动决定，
    不是「启动成功」；bat 靠退出码判断要不要报「[启动失败]」）。

    背景（真实修过的问题）：取消时返回 0，bat 会误判成「启动成功」。

    验证：占住测试端口 -> `start.py --ask-port` -> 从 stdin 喂 "0" -> 断言退出码 != 0。
    """
    if not START_PY.exists():
        res.check(False, f"start.py 不存在：{START_PY}")
        return
    kill_port_listeners(TEST_PORT)
    try:
        holder = start_port_holder(TEST_PORT, reuse=False, addr="127.0.0.1")
    except RuntimeError as exc:
        res.check(False, f"哑巴占用者没能占住端口：{exc}")
        return
    proc = None
    try:
        env = dict(os.environ)
        env["BROWSER"] = "echo"
        env["NO_PROXY"] = "127.0.0.1,localhost"
        env["no_proxy"] = env["NO_PROXY"]
        proc = subprocess.Popen(
            [str(VENV_PY), "start.py", "--ask-port", "--port", str(TEST_PORT),
             "--no-browser", "--timeout", "30"],
            cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", env=env,
            stdin=subprocess.PIPE)
        # 等它把选择题问出来，再喂 "0"
        time.sleep(6)
        proc.stdin.write("0\n")
        proc.stdin.flush()
        try:
            out, _ = proc.communicate(timeout=45)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate()
        res.note(f"取消流程输出：{(out or '').strip()[-400:]!r}")
        res.check(proc.returncode != 0,
                  f"用户选 [0] 取消时退出码 = {proc.returncode}（应非 0）")
        res.check("取消" in (out or ""),
                  "输出明确说明「已取消启动」")
        # 取消后不应该**再**拉起一个服务。
        # 注意：端口上本来就有我放的哑巴占用者（那是故意的），
        # 所以判据是「监听数仍为 1」，而不是「端口没有监听」。
        rows = netstat_listening(TEST_PORT)
        res.check(len(rows) <= 1,
                  f"取消后没有多拉起服务（监听行 {len(rows)} 条，"
                  f"应只有哑巴占用者那 1 条）")
        for r in rows:
            res.note(f"监听行：{r}")
    finally:
        if proc and proc.poll() is None:
            proc.kill()
        kill_holder(holder)
        kill_port_listeners(TEST_PORT)



