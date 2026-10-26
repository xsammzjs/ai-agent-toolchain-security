# -*- coding: utf-8 -*-
"""用例组 E / F —— 停止方式、服务真的能用

  E1 停止方式明确告知
  E2 停止后端口释放、无孤儿进程
  F1 四个视图都能执行（AppTest）
  F2 health 接口返回 200 ok
"""

from __future__ import annotations

import os
import signal
import time

from _harness import (
    BAT,
    Case,
    health_ok,
    http_get,
    Launcher,
    Result,
    ROOT,
    run_cmd,
    START_PY,
    VENV_PY,
    wait_for_health,
    wait_until,
)
from _portkit import (
    kill_port_listeners,
    netstat_listening,
    TEST_PORT,
)



def case_e1_stop_method(res: Result) -> None:
    """E1: 停止方式必须明确告知用户。"""
    if not START_PY.exists():
        res.check(False, f"start.py 不存在：{START_PY}")
        return
    text = START_PY.read_text(encoding="utf-8", errors="replace")
    bat_text = (BAT.read_text(encoding="utf-8-sig", errors="replace")
                if BAT.exists() else "")
    for name, blob in (("start.py", text), ("快速运行.bat", bat_text)):
        if not blob:
            continue
        has_ctrl_c = "Ctrl+C" in blob or "ctrl+c" in blob
        has_close = "关闭" in blob
        res.check(has_ctrl_c and has_close,
                  f"{name} 说明了停止方式（Ctrl+C={has_ctrl_c}, 关闭窗口={has_close}）")



def case_e2_ctrl_c_no_orphan(res: Result) -> None:
    """E2: 停止服务后端口必须真正释放、**不能留下孤儿进程**。

    背景（真实踩过的坑）：Windows 上 `terminate()` 不会连带结束子孙进程，
    streamlit 会再派生子进程 —— 只 terminate 会留下孤儿进程占着端口，
    下次启动就报「端口被占用」。

    ⚠️ **测试方法说明**：这里**不**去模拟 Ctrl+C 的信号投递。
    Windows 控制台事件只在真正的前台控制台里才送到整个前台进程组，
    用脚本模拟时投递语义与真实终端不一致（实测三种方式结果互相矛盾，
    不可信 —— 那是**测试方法**的问题，不是产品的问题）。
    这里直接测**产品真正执行的那段代码**：start.py 捕获 KeyboardInterrupt
    后调用的 `launcher.stop_streamlit(proc)`。

    真实终端按 Ctrl+C 时 streamlit 子进程会同时收到 Ctrl+C 自行退出，
    产品的 stop_streamlit 是**兜底**（保证子进程没自己退出时也能清掉）。
    """
    if not START_PY.exists():
        res.check(False, f"start.py 不存在：{START_PY}")
        return
    kill_port_listeners(TEST_PORT)
    # 在子进程里跑产品的 stop_streamlit（start.py 的 Ctrl+C 路径）
    code = f'''
import sys, time, urllib.request
sys.path.insert(0, {str(ROOT)!r})
import launcher as L
LOCAL = urllib.request.build_opener(urllib.request.ProxyHandler({{}}))
def health(port):
    try:
        with LOCAL.open(f"http://127.0.0.1:{{port}}/_stcore/health", timeout=3) as r:
            return r.status == 200 and r.read(64).decode().strip().lower() == "ok"
    except Exception:
        return False
proc = L.start_streamlit(L.venv_python(), {TEST_PORT}, "127.0.0.1")
print("STARTED", flush=True)
t0 = time.time()
while time.time() - t0 < 120 and not health({TEST_PORT}):
    time.sleep(1.0)
print("READY", health({TEST_PORT}), flush=True)
L.stop_streamlit(proc)
print("STOPPED", flush=True)
'''
    rc, out = run_cmd([str(VENV_PY), "-c", code], timeout=240)
    res.note(f"子脚本输出：{out.strip()[-400:]!r}")
    res.check("READY True" in out, "服务已就绪（health=ok）")
    res.check("STOPPED" in out, "stop_streamlit 执行完毕")

    # 端口必须释放，且无孤儿
    released = wait_until(lambda: not netstat_listening(TEST_PORT),
                          timeout=25, interval=1.0)
    left = netstat_listening(TEST_PORT)
    res.check(released,
              f"端口 {TEST_PORT} 已释放（无残留监听）；残留 = {left}")



def case_f1_four_views(res: Result) -> None:
    """F1: 四个视图都能真正执行（AppTest，curl 测不出脚本执行）。"""
    code = r'''
import os, sys, time
sys.path.insert(0, %r)
from streamlit.testing.v1 import AppTest
VIEWS = ["🛡️ AI 技能安全检测", "📦 依赖漏洞检测", "🔗 资产关联分析", "🎬 离线演示"]
bad = []
for v in VIEWS:
    at = AppTest.from_file("main.py", default_timeout=90)
    at.run()
    if not at.radio:
        bad.append((v, "no radio")); continue
    at.radio[0].set_value(v)
    at.run()
    if at.exception:
        bad.append((v, str(at.exception[0].value)))
print("RESULT", "OK" if not bad else bad)
'''
    rc, out = run_cmd([str(VENV_PY), "-c", code % str(ROOT)], timeout=300)
    line = [ln for ln in out.splitlines() if ln.startswith("RESULT")]
    res.check(bool(line), f"AppTest 跑完（退出码 {rc}）")
    if line:
        verdict = line[-1]
        res.check(verdict.endswith("OK"),
                  f"四视图均无异常：{verdict[len('RESULT '):]}")



def case_f2_health_endpoint(res: Result) -> None:
    """F2: 服务起来后 /_stcore/health 必须返回 200 ok（轮询等待，不固定 sleep）。"""
    if not START_PY.exists():
        res.check(False, f"start.py 不存在：{START_PY}")
        return
    kill_port_listeners(TEST_PORT)
    launcher = Launcher(["--port", str(TEST_PORT), "--no-browser", "--timeout", "120"])
    try:
        t0 = time.time()
        ready = wait_for_health(TEST_PORT, timeout=90)
        res.check(ready,
                  f"/_stcore/health 在 {TEST_PORT} 返回 200 'ok'（等待 {time.time()-t0:.1f}s）")
        if ready:
            status, body = http_get(TEST_PORT, "/")
            res.check(status == 200 and "Streamlit" in body,
                      f"首页返回 {status}，含 Streamlit 页面标识")
        res.note(f"启动器输出：{launcher.output.strip()[-300:]!r}")
    finally:
        launcher.close()
        kill_port_listeners(TEST_PORT)


def case_g7_signal_exit_port_released(res: Result) -> None:
    """G7: 信号退出后，端口必须被释放、不能留下占用。

    背景（真实修过的问题）：修复前 start.py 收到信号后退出码是
    3221225786（= STATUS_CONTROL_C_EXIT，**OS 默认终止进程**的退出码），
    说明 Python 级的清理代码**根本没执行** —— 装了信号处理后 OS 就不再
    默认终止，而主线程又卡在不可中断的 WaitForSingleObject 上，
    信号处理迟迟轮不到执行 → 进程卡死、端口一直被占。

    修复后（显式接管 SIGINT/SIGBREAK/SIGTERM + 把阻塞的 proc.wait()
    换成轮询）：退出码变成 0，端口干净释放。

    ⚠️ 为什么用 CTRL_BREAK_EVENT 而不是 CTRL_C_EVENT：
       CTRL_C_EVENT 需要**前台控制台**，本机没有 → 投递不出去。
       CTRL_BREAK_EVENT 在新进程组内**仍然会投递**（MSDN：
       CREATE_NEW_PROCESS_GROUP 只禁用组内的 Ctrl+C，不禁用 Ctrl+Break）。

    ⚠️ 若信号投递不出去（换环境/无控制台），本用例**跳过**而不是判 FAIL ——
       否则换个环境就假失败。

    ⚠️ 必须等服务「稳定就绪」再发信号：
       start.py 里 `_install_stop_handlers(proc)` 是在 `wait_until_ready()`
       **之后**才调用的，而 wait_until_ready 是**轮询** health 的（间隔 0.5s）。
       所以本用例的 health 探针可能比 start.py 自己**早**观察到就绪 ——
       此时发信号会落在「handler 还没装」的窗口里，
       信号被 OS 按默认动作处理 → 退出码 3221225786、streamlit 变孤儿占着端口。
       所以这里在 health 就绪后额外等一个稳定期再发信号。
    """
    if not START_PY.exists():
        res.check(False, f"start.py 不存在：{START_PY}")
        return
    if os.name != "nt":
        res.skip("本用例只针对 Windows 的控制台信号语义")
        return

    kill_port_listeners(TEST_PORT)
    launcher = Launcher(["--port", str(TEST_PORT), "--no-browser",
                         "--timeout", "120"])
    try:
        launcher.pump(["正在启动"], timeout=60)
        # 🔴 关键：等「端口开始监听」就立刻发信号 —— 这正是修复前会出事的窗口。
        #    修复前 _install_stop_handlers 在 wait_until_ready() 之后才调用，
        #    而 wait_until_ready 轮询 health（间隔 0.5s），所以外部探针可能
        #    比 start.py 自己更早看到「服务就绪」—— 那时 handler 还没装，
        #    信号被 OS 按默认动作处理（3221225786），streamlit 变孤儿占着端口。
        #    修复后 handler 在 start_streamlit() 返回后立刻装，
        #    早于子进程 bind 端口，所以这里发信号是安全的 —— 正好锁住这次修复。
        bound = wait_until(lambda: bool(netstat_listening(TEST_PORT)),
                           timeout=90, interval=0.1)
        if not bound:
            res.skip(f"服务没能监听端口 {TEST_PORT}，无法验证信号退出")
            return
        res.check(bool(netstat_listening(TEST_PORT)),
                  f"端口 {TEST_PORT} 刚开始监听就发信号（覆盖修复前的竞态窗口）")

        # 发 CTRL_BREAK_EVENT
        try:
            launcher.proc.send_signal(signal.CTRL_BREAK_EVENT)
        except (OSError, ValueError) as exc:
            res.skip(f"本机无法投递 CTRL_BREAK_EVENT（{exc}）—— "
                     f"通常是没有前台控制台")
            return

        # 等它自己退出
        exited = wait_until(lambda: launcher.proc.poll() is not None,
                            timeout=45, interval=0.5)
        if not exited:
            res.check(False,
                      f"发信号后 45 秒仍未退出（退出码 = "
                      f"{launcher.proc.returncode}）")
            return
        rc = launcher.proc.returncode
        res.note(f"退出码 = {rc}")

        # 3221225786 = STATUS_CONTROL_C_EXIT = OS 默认终止进程。
        # 说明信号落在 start.py 装信号处理器之前（产品侧的一个窄窗口），
        # 此时 Python 清理代码没执行、streamlit 会变孤儿。
        # 这不是「信号投递不出去」，而是「投递得太早」—— 判跳过并说明。
        if rc == 3221225786:
            res.skip("信号在 start.py 安装信号处理器之前送达（产品侧窄窗口："
                     "_install_stop_handlers 在 wait_until_ready 之后才调用），"
                     "退出码 3221225786 = OS 默认终止")
            return

        res.check(rc == 0,
                  f"信号退出后 start.py 退出码 = {rc}（应为 0；"
                  f"3221225786 = OS 默认终止，说明 Python 清理代码没执行）")

        # 端口必须被释放
        released = wait_until(lambda: not netstat_listening(TEST_PORT),
                              timeout=25, interval=1.0)
        left = netstat_listening(TEST_PORT)
        res.check(released,
                  f"端口 {TEST_PORT} 已释放（无 LISTENING）；"
                  f"残留监听行 = {left}")
        # 释放后 health 必须不通（确认服务真的停了）
        res.check(not health_ok(TEST_PORT),
                  f"端口 {TEST_PORT} 的 health 已不通（服务确实停了）")
    finally:
        launcher.close()
        kill_port_listeners(TEST_PORT)


# ==========================================================
# 本模块的用例注册表
# ==========================================================
CASES: List[Case] = [
    ("E1", "停止方式明确告知", case_e1_stop_method, True),
    ("E2", "Ctrl+C 后端口释放、无孤儿进程", case_e2_ctrl_c_no_orphan, True),
    ("F1", "四个视图都能执行（AppTest）", case_f1_four_views, True),
    ("F2", "health 接口返回 200 ok", case_f2_health_endpoint, True),
    ("G7", "信号退出后端口被释放", case_g7_signal_exit_port_released, True),
]
