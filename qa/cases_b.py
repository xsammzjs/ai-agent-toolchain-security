# -*- coding: utf-8 -*-
"""用例组 C / D —— 端口冲突处理、自动开浏览器

  C1 端口占用时探测准确且不崩
  C2 实际端口 == 提示地址（避让后不串号）
  C3 占用者绑 0.0.0.0 时也能识别（防重复实例）
  D1 自动开浏览器且 URL 与实际端口一致

本文件还带两个「从输出里解析端口」的小工具（extract_port /
extract_all_ports）—— 只有 C2、D1 用得到，就近放一起。
"""

from __future__ import annotations

import re
import time
from typing import List, Optional

from _harness import (
    health_ok,
    Launcher,
    Result,
    ROOT,
    run_cmd,
    START_PY,
    VENV_PY,
    wait_for_health,
)
from _portkit import (
    kill_holder,
    kill_port_listeners,
    netstat_listening,
    start_port_holder,
    TEST_PORT,
)



def case_c1_port_conflict_behavior(res: Result) -> None:
    """C1: 端口被占用时的行为 —— 不得崩、不得静默抢占。"""
    if not START_PY.exists():
        res.check(False, f"start.py 不存在：{START_PY}")
        return
    kill_port_listeners(TEST_PORT)
    try:
        holder = start_port_holder(TEST_PORT, reuse=False, addr="127.0.0.1")
    except RuntimeError as exc:
        res.check(False, f"哑巴占用者没能占住端口：{exc}")
        return
    try:
        before = netstat_listening(TEST_PORT)
        res.check(bool(before), f"占用者已就绪，监听行 {before}")

        # start.py 的端口探测必须认为该端口「不空闲」
        code = (
            "import sys; sys.path.insert(0, %r)\n"
            "import start\n"
            "print('FREE' if start.port_is_free(%d,'127.0.0.1') else 'BUSY')\n"
            % (str(ROOT), TEST_PORT)
        )
        rc, out = run_cmd([str(VENV_PY), "-c", code], timeout=60)
        verdict = out.strip().splitlines()[-1] if out.strip() else "(无输出)"
        res.check(verdict == "BUSY",
                  f"port_is_free 对已占用端口的判定 = {verdict}（应为 BUSY）")

        # 探测不能有 SO_REUSEADDR，否则 Windows 上会误判空闲
        res.note("（Windows 语义：探测 bind 必须不带 SO_REUSEADDR，"
                 "否则后启动者会抢占已监听端口）")
    finally:
        kill_holder(holder)
        kill_port_listeners(TEST_PORT)



def case_c2_actual_port_matches(res: Result) -> None:
    """C2: 实际端口必须与提示地址一致（避让到 8502 就必须显示 8502）。

    关键：**用轮询等 health 就绪**，不能用固定 sleep。
    Streamlit 冷启动 10-30 秒，固定 sleep 会在服务还没起来时误判 FAIL。
    """
    if not START_PY.exists():
        res.check(False, f"start.py 不存在：{START_PY}")
        return
    kill_port_listeners(TEST_PORT)
    holder = start_port_holder(TEST_PORT, reuse=False, addr="127.0.0.1")
    launcher = None
    try:
        res.check(bool(netstat_listening(TEST_PORT)), "占用者已就绪")

        launcher = Launcher(["--port", str(TEST_PORT), "--no-browser",
                             "--timeout", "120"])
        # 先等到「访问地址」打印出来，解析出它打算用哪个端口
        launcher.pump(["访问地址"], timeout=90)
        res.note(f"start.py 输出：{launcher.output.strip()[:500]!r}")
        res.check("访问地址" in launcher.output, "打印了明确的「访问地址」")

        actual = extract_port(launcher.output)
        res.check(actual is not None, f"能从输出解析出访问端口：{actual}")
        if actual is None:
            return
        res.check(actual != TEST_PORT,
                  f"端口 {TEST_PORT} 被占时，实际改用 {actual}（已避让）")

        # **轮询**等 health 就绪，而不是固定 sleep
        t0 = time.time()
        ready = wait_for_health(actual, timeout=90)
        wait_s = time.time() - t0
        res.check(ready,
                  f"实际端口 {actual} 的 /_stcore/health 返回 ok（等待 {wait_s:.1f}s）")
        res.check(bool(netstat_listening(actual)),
                  f"实际端口 {actual} 上确实有监听")
    finally:
        if launcher:
            launcher.close()
        kill_holder(holder)
        kill_port_listeners(TEST_PORT)



def case_c3_wildcard_occupant(res: Result) -> None:
    """C3: 占用者绑在 **0.0.0.0**（通配地址）时，必须也能识别出来。

    背景（真实复现的缺陷）：《运行说明.md》方式二的命令
    `streamlit run main.py` 默认绑 0.0.0.0。若用户先按文档起过一次、
    那个窗口还开着，又双击了 bat，launcher 会误判「端口可用」，
    **静默拉起第二个实例**，旧实例变僵尸。

    根因：port_is_free 只 bind host(127.0.0.1)，而 Windows 上
    绑 0.0.0.0 的服务不阻止别的进程 bind 127.0.0.1。

    判据：面对 0.0.0.0 的占用者，launcher 必须能识别出
    「已有本服务在运行」或「端口被占用」，而**不是**「端口可用」。
    """
    if not START_PY.exists():
        res.check(False, f"start.py 不存在：{START_PY}")
        return
    kill_port_listeners(TEST_PORT)
    # 占用者绑 0.0.0.0（模拟 `streamlit run main.py` 的默认行为）
    try:
        holder = start_port_holder(TEST_PORT, reuse=False, addr="0.0.0.0")
    except RuntimeError as exc:
        res.check(False, f"哑巴占用者没能占住端口：{exc}")
        return
    try:
        code = (
            "import sys; sys.path.insert(0, %r)\n"
            "import launcher as L\n"
            "print('FREE' if L.port_is_free(%d, '127.0.0.1') else 'BUSY')\n"
            % (str(ROOT), TEST_PORT)
        )
        rc, out = run_cmd([str(VENV_PY), "-c", code], timeout=60)
        verdict = out.strip().splitlines()[-1] if out.strip() else "(无输出)"
        res.check(verdict == "BUSY",
                  f"占用者绑 0.0.0.0 时，port_is_free 判定 = {verdict}"
                  f"（应为 BUSY；若是 FREE，说明会静默拉起第二个实例）")

        # 端到端：start.py 必须说「已有本服务」或「被占用」，而不是「可用」
        launcher = Launcher(["--port", str(TEST_PORT), "--no-browser",
                             "--timeout", "60"])
        try:
            launcher.pump(["访问地址", "直接访问"], timeout=60)
            text = launcher.output
            res.note(f"start.py 输出：{text.strip()[-400:]!r}")
            # 注意文案是「端口 8781 可用。」（端口号夹在中间），
            # 所以要用正则匹配，不能直接找「端口可用」四个字
            misjudged = re.search(r"端口\s*\d+\s*可用", text) is not None
            res.check(not misjudged,
                      "start.py 未误判为「端口 … 可用」（应识别出已有服务/被占用）")
            res.check(("已有本服务" in text) or ("占用" in text),
                      "start.py 明确识别出端口上已有东西")
        finally:
            launcher.close()
    finally:
        kill_holder(holder)
        kill_port_listeners(TEST_PORT)



def extract_port(text: str) -> Optional[int]:
    """从启动器输出里解析出实际访问端口。

    ⚠️ 不能用「把所有冒号换成空格再 split」的办法 —— 那样连
    ``http://`` 里的 ASCII 冒号都会被拆散，任何 URL 都解析不出来。

    ⚠️ 端口可能出现在多种位置，格式各不相同：
        >>> 访问地址： http://localhost:8766     （start.py 打印的）
        URL: http://127.0.0.1:8765              （streamlit 打印的）
        http://localhost:8765                   （BROWSER=echo 那行）
    所以这里抓**所有** http(s) URL 里的端口，优先取「访问地址」那一行
    声明的端口（那是用户真正会去访问的），取不到再退回任意一个。
    """
    # 1) 优先用 start.py 明确声明的「访问地址」
    m = re.search(r"访问地址[：:]\s*https?://[^\s]*?:(\d+)", text)
    if m:
        return int(m.group(1))
    m = re.search(r"直接访问[：:]\s*https?://[^\s]*?:(\d+)", text)
    if m:
        return int(m.group(1))
    # 2) 退回：任意 http(s) URL 的端口（取第一个出现的）
    m = re.search(r"https?://[^\s]*?:(\d+)", text)
    if m:
        return int(m.group(1))
    # 3) 最后退回：裸的 localhost:PORT
    m = re.search(r"localhost:(\d+)", text)
    return int(m.group(1)) if m else None



def extract_all_ports(text: str) -> List[int]:
    """抓出输出里出现过的**所有**端口（用于与实际监听端口交叉验证）。"""
    return [int(p) for p in re.findall(r"https?://[^\s]*?:(\d+)", text)]



def case_d1_open_browser(res: Result) -> None:
    """D1: 自动开浏览器 —— 打开的 URL 必须与实际端口一致。

    用 BROWSER=echo 把 webbrowser.open 的 URL 截获下来，
    断言它等于**实际监听**的端口，而不是启动器「以为」的端口。
    """
    if not START_PY.exists():
        res.check(False, f"start.py 不存在：{START_PY}")
        return
    kill_port_listeners(TEST_PORT)
    launcher = Launcher(["--port", str(TEST_PORT), "--timeout", "120"])
    try:
        # 先等访问地址打印出来
        launcher.pump(["访问地址"], timeout=90)
        declared = extract_port(launcher.output)
        res.check(declared is not None, f"解析出声明的访问端口：{declared}")

        # **轮询**等浏览器被打开（服务就绪后才会 open_browser）
        launcher.pump(["正在打开浏览器"], timeout=90)
        launcher.read_all(seconds=5)
        res.note(f"捕获输出：{launcher.output.strip()[-600:]!r}")

        urls = [ln.strip() for ln in launcher.output.splitlines()
                if ln.strip().startswith("http://localhost:")]
        res.check(bool(urls), "BROWSER=echo 捕获到了浏览器打开的 URL")
        if not urls or declared is None:
            return
        opened = int(urls[-1].rsplit(":", 1)[1].rstrip("/"))
        res.check(opened == declared,
                  f"浏览器打开的端口 {opened} == 声明的访问端口 {declared}")
        # 打开的那个端口必须真的有服务且可用
        res.check(health_ok(opened),
                  f"浏览器打开的端口 {opened} 服务确实可用（health=ok）")
    finally:
        launcher.close()
        kill_port_listeners(TEST_PORT)
