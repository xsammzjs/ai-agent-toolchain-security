# -*- coding: utf-8 -*-
"""启动方式验收工具箱（QA 工具，非产品代码）

=====================================================
用途
=====================================================
为「快速运行.bat / start.py」这套启动方式提供**可复现**的验收手段。
每个函数对应《启动方式验收清单》里的一条勾选项，工程师改完可直接跑：

    python qa/launcher_acceptance.py            # 跑全部（不含破坏性用例）
    python qa/launcher_acceptance.py --list     # 只列用例清单
    python qa/launcher_acceptance.py --only A3  # 只跑指定编号

=====================================================
重要约束（实测踩过的坑，别重复踩）
=====================================================
1. 本机设了 http_proxy / https_proxy 环境变量，**本机回环请求会走代理**，
   直接 curl http://127.0.0.1:8501 会超时。必须加 --noproxy '*'
   或用 urllib 的 ProxyHandler({}) 清空代理。
2. TaskStop 只杀 shell，不杀它派生的 python 子进程 —— 收尾要用
   netstat 找 PID 再 taskkill。
3. Streamlit 的 _bind_socket 总是设 SO_REUSEADDR，Windows 上会让
   「后启动者抢占已占用端口」。所以**探测端口是否空闲必须用
   不带 SO_REUSEADDR 的 bind**（start.py 的 port_is_free 已正确处理）。
4. netstat 输出是 GBK 编码，用 subprocess 捕获时必须 decode("gbk")。
5. 测试端口用 8765 等非 8501 端口，避免干扰工程师正在跑的实例。
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
VENV_PY = ROOT / ".venv" / "Scripts" / "python.exe"
BAT = ROOT / "快速运行.bat"
START_PY = ROOT / "start.py"

# 测端口用的哑巴占用者端口（避开 8501）
TEST_PORT = 8765

# 本机请求专用 opener：清空代理，否则 127.0.0.1 会被转发到代理服务器
LOCAL = urllib.request.build_opener(urllib.request.ProxyHandler({}))


# ==========================================================
# 基础设施
# ==========================================================
class Result:
    """单条用例的执行结果。"""

    def __init__(self, cid: str, name: str) -> None:
        self.cid = cid
        self.name = name
        self.passed = False
        self.evidence: List[str] = []
        self.error = ""

    def check(self, condition: bool, detail: str) -> bool:
        """记录一条断言；返回是否通过（便于链式使用）。"""
        mark = "PASS" if condition else "FAIL"
        self.evidence.append(f"[{mark}] {detail}")
        if not condition:
            self.passed = False
        return condition

    def note(self, detail: str) -> None:
        self.evidence.append(f"[INFO] {detail}")


def netstat_listening(port: int) -> List[str]:
    """返回该端口 LISTENING 的 netstat 行（GBK 解码）。"""
    proc = subprocess.run(["netstat", "-ano", "-p", "TCP"], capture_output=True)
    out = proc.stdout.decode("gbk", errors="replace")
    return [l.strip() for l in out.splitlines()
            if f":{port}" in l and "LISTENING" in l]


def http_get(port: int, path: str = "/", timeout: float = 5.0) -> Tuple[int, str]:
    """请求本机端口，返回 (status, body 前 200 字符)。"""
    try:
        with LOCAL.open(f"http://127.0.0.1:{port}{path}", timeout=timeout) as resp:
            return resp.status, resp.read(400).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, ""
    except Exception as exc:                      # noqa: BLE001
        return 0, f"{type(exc).__name__}: {exc}"


def health_ok(port: int, timeout: float = 3.0) -> bool:
    """Streamlit 健康检查 —— 必须是 200 且 body 恰好是 'ok'。"""
    try:
        with LOCAL.open(f"http://127.0.0.1:{port}/_stcore/health", timeout=timeout) as r:
            return r.status == 200 and r.read(64).decode("utf-8", "replace").strip().lower() == "ok"
    except Exception:                             # noqa: BLE001
        return False


def port_is_free(port: int, host: str = "127.0.0.1") -> bool:
    """端口是否空闲 —— **不能**设 SO_REUSEADDR（Windows 上会误判）。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if os.name != "nt":
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def start_port_holder(port: int, reuse: bool = False, addr: str = "127.0.0.1"):
    """启动一个占用端口的哑巴进程，返回 Popen。"""
    code = f'''
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
if {reuse}:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("{addr}", {port}))
s.listen(5)
print("HELD", flush=True)
time.sleep(120)
'''
    proc = subprocess.Popen([str(VENV_PY), "-c", code],
                            stdout=subprocess.PIPE, text=True)
    proc.stdout.readline()                          # 等 HELD
    time.sleep(0.3)
    return proc


def kill_pid(pid: int) -> None:
    subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                   capture_output=True)


def kill_port_listeners(port: int) -> None:
    """杀掉监听指定端口的所有进程。"""
    for line in netstat_listening(port):
        parts = line.split()
        if parts:
            kill_pid(int(parts[-1]))
    time.sleep(1.0)


def run_cmd(cmd: List[str], cwd: Path = ROOT, timeout: int = 120,
            env: Optional[Dict[str, str]] = None) -> Tuple[int, str]:
    """执行命令，返回 (returncode, 合并输出)。"""
    try:
        proc = subprocess.run(cmd, cwd=str(cwd), capture_output=True,
                              text=True, timeout=timeout,
                              encoding="utf-8", errors="replace", env=env)
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout or b"")
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        return -1, out


def bat_bytes() -> bytes:
    return BAT.read_bytes()


def has_bom(data: bytes) -> bool:
    return data[:3] == b"\xef\xbb\xbf"


def bat_line_endings(data: bytes) -> Tuple[int, int]:
    """返回 (CRLF 行数, 裸 LF 行数)。"""
    crlf = data.count(b"\r\n")
    return crlf, data.count(b"\n") - crlf


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


def case_a2_bat_cmd_parse(res: Result) -> None:
    """A2: .bat 能否被 cmd.exe 正常解析（无 BOM 语法错）。"""
    if not BAT.exists():
        res.check(False, f"文件不存在：{BAT}")
        return
    data = bat_bytes()
    if has_bom(data):
        res.check(False, "含 BOM —— cmd.exe 第一行会报 "
                         "'xxx 不是内部或外部命令'，双击必然出乱码错误")
        return
    # 用 cmd /c 解析一遍，截取前若干行输出看有无语法错误
    rc, out = run_cmd(["cmd", "/c", str(BAT)], timeout=20)
    bad = [ln for ln in out.splitlines()
           if "不是内部或外部命令" in ln or "不是可识别的" in ln]
    res.check(not bad, f"cmd.exe 解析无语法错误（捕获到 {len(bad)} 条）")
    for ln in bad[:3]:
        res.note(f"语法错误行：{ln.strip()}")


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
    """B2: 依赖齐全时不得重装 —— start.py --check 应秒回且不碰网络。"""
    if not START_PY.exists():
        res.check(False, f"start.py 不存在：{START_PY}")
        return
    t0 = time.time()
    rc, out = run_cmd([str(VENV_PY), "start.py", "--check"], timeout=180)
    dt = time.time() - t0
    res.check(rc == 0, f"start.py --check 退出码 = {rc}")
    res.check("无需重复安装" in out or "依赖齐全" in out,
              "输出明确说明依赖已齐全、无需重复安装")
    res.check(dt < 60, f"耗时 {dt:.1f}s（应远快于首次安装的 2-5 分钟）")
    res.note(f"--check 输出片段：{out.strip()[:300]!r}")


def case_c1_port_conflict_behavior(res: Result) -> None:
    """C1: 端口被占用时的行为 —— 不得崩、不得静默抢占。"""
    if not START_PY.exists():
        res.check(False, f"start.py 不存在：{START_PY}")
        return
    kill_port_listeners(TEST_PORT)
    holder = start_port_holder(TEST_PORT, reuse=False, addr="127.0.0.1")
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
        holder.kill()
        holder.wait()
        kill_port_listeners(TEST_PORT)


def case_c2_actual_port_matches(res: Result) -> None:
    """C2: 实际端口必须与提示地址一致（避让到 8502 就必须显示 8502）。"""
    if not START_PY.exists():
        res.check(False, f"start.py 不存在：{START_PY}")
        return
    kill_port_listeners(TEST_PORT)
    holder = start_port_holder(TEST_PORT, reuse=False, addr="127.0.0.1")
    proc = None
    try:
        env = dict(os.environ)
        env["BROWSER"] = "echo"                 # 捕获浏览器实际打开的 URL
        env["NO_PROXY"] = "127.0.0.1,localhost"
        env["no_proxy"] = env["NO_PROXY"]
        proc = subprocess.Popen(
            [str(VENV_PY), "start.py", "--port", str(TEST_PORT),
             "--no-browser", "--timeout", "90"],
            cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", env=env)
        # 等它自己探测端口并避让
        deadline = time.time() + 60
        buf = ""
        while time.time() < deadline:
            time.sleep(1.0)
            buf = proc.stdout.read() or "" if proc.stdout else ""
            if buf and ("访问地址" in buf or "改用" in buf):
                break
        res.note(f"start.py 输出：{buf.strip()[:400]!r}")
        res.check("访问地址" in buf, "打印了明确的「访问地址」")
        # 解析出实际端口
        actual = None
        for token in buf.replace("：", " ").split():
            if token.startswith("http://localhost:"):
                actual = int(token.rsplit(":", 1)[1])
        res.check(actual is not None, f"能从输出解析出访问端口：{actual}")
        if actual is not None:
            res.check(actual != TEST_PORT,
                      f"端口 {TEST_PORT} 被占时，实际用了 {actual}（应避让）")
            listeners = netstat_listening(actual)
            res.check(bool(listeners),
                      f"实际端口 {actual} 上确实有监听：{listeners}")
            res.check(health_ok(actual),
                      f"实际端口 {actual} 的 /_stcore/health 返回 ok")
    finally:
        if proc:
            proc.kill()
            proc.wait()
        holder.kill()
        holder.wait()
        kill_port_listeners(TEST_PORT)


def case_d1_open_browser(res: Result) -> None:
    """D1: 自动开浏览器 —— 打开的 URL 必须与实际端口一致。"""
    if not START_PY.exists():
        res.check(False, f"start.py 不存在：{START_PY}")
        return
    kill_port_listeners(TEST_PORT)
    env = dict(os.environ)
    env["BROWSER"] = "echo"                     # webbrowser.open 会 echo 出 URL
    env["NO_PROXY"] = "127.0.0.1,localhost"
    env["no_proxy"] = env["NO_PROXY"]
    proc = subprocess.Popen(
        [str(VENV_PY), "start.py", "--port", str(TEST_PORT), "--timeout", "90"],
        cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace", env=env)
    try:
        deadline = time.time() + 90
        seen = ""
        while time.time() < deadline:
            time.sleep(1.0)
            line = proc.stdout.readline() if proc.stdout else ""
            if not line:
                break
            seen += line
            if "http://localhost:" in line and "访问地址" not in line:
                break
        res.note(f"捕获输出：{seen.strip()[:300]!r}")
        urls = [ln.strip() for ln in seen.splitlines()
                if ln.strip().startswith("http://localhost:")]
        res.check(bool(urls), "BROWSER=echo 捕获到了浏览器打开的 URL")
        if urls:
            port = int(urls[-1].rsplit(":", 1)[1].rstrip("/"))
            res.check(port == TEST_PORT,
                      f"浏览器打开的端口 {port} == 实际启动端口 {TEST_PORT}")
            res.check(health_ok(port), f"该端口服务确实可用（health=ok）")
    finally:
        proc.kill()
        proc.wait()
        kill_port_listeners(TEST_PORT)


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
    """F2: 服务起来后 /_stcore/health 必须返回 200 ok。"""
    if not START_PY.exists():
        res.check(False, f"start.py 不存在：{START_PY}")
        return
    kill_port_listeners(TEST_PORT)
    env = dict(os.environ)
    env["NO_PROXY"] = "127.0.0.1,localhost"
    env["no_proxy"] = env["NO_PROXY"]
    proc = subprocess.Popen(
        [str(VENV_PY), "start.py", "--port", str(TEST_PORT), "--no-browser",
         "--timeout", "90"],
        cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace", env=env)
    try:
        ok = False
        deadline = time.time() + 90
        while time.time() < deadline:
            if health_ok(TEST_PORT):
                ok = True
                break
            time.sleep(1.0)
        res.check(ok, f"/_stcore/health 在 {TEST_PORT} 返回 200 'ok'")
        if ok:
            status, body = http_get(TEST_PORT, "/")
            res.check(status == 200 and "Streamlit" in body,
                      f"首页返回 {status}，含 Streamlit 页面标识")
    finally:
        proc.kill()
        proc.wait()
        kill_port_listeners(TEST_PORT)


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


# ==========================================================
# 注册表
# ==========================================================
CASES: List[Tuple[str, str, Callable[[Result], None], bool]] = [
    ("A1", "bat 编码：无 BOM + CRLF", case_a1_bat_encoding, True),
    ("A2", "bat 能被 cmd.exe 正常解析", case_a2_bat_cmd_parse, True),
    ("A3", "bat 有 chcp 65001（中文不乱码）", case_a3_bat_codepage, True),
    ("B1", "bat 依赖检查覆盖全部必需包", case_b1_bat_dep_check, True),
    ("B2", "依赖齐全时不重复安装", case_b2_no_reinstall, True),
    ("C1", "端口占用时探测准确且不崩", case_c1_port_conflict_behavior, True),
    ("C2", "实际端口 == 提示地址（避让后不串号）", case_c2_actual_port_matches, True),
    ("D1", "自动开浏览器且 URL 与实际端口一致", case_d1_open_browser, True),
    ("E1", "停止方式明确告知", case_e1_stop_method, True),
    ("F1", "四个视图都能执行（AppTest）", case_f1_four_views, True),
    ("F2", "health 接口返回 200 ok", case_f2_health_endpoint, True),
    ("G1", "bat 委托 start.py（单一逻辑源）", case_g1_bat_delegates, True),
    ("G2", "--check 不开浏览器", case_g2_no_browser_in_check, True),
]


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="启动方式验收工具箱")
    parser.add_argument("--list", action="store_true", help="只列用例清单")
    parser.add_argument("--only", nargs="*", help="只跑指定编号，如 A1 C2")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    args = parser.parse_args(argv)

    if args.list:
        print("验收用例清单：")
        for cid, name, _fn, _safe in CASES:
            print(f"  {cid:4s} {name}")
        return 0

    selected = CASES
    if args.only:
        keys = {k.upper() for k in args.only}
        selected = [c for c in CASES if c[0].upper() in keys]
        if not selected:
            print(f"没有匹配的用例：{args.only}")
            return 2

    results: List[Result] = []
    for cid, name, fn, _safe in selected:
        res = Result(cid, name)
        t0 = time.time()
        try:
            fn(res)
        except Exception as exc:                  # noqa: BLE001
            res.check(False, f"用例执行异常：{type(exc).__name__}: {exc}")
        res.evidence.append(f"[TIME] {time.time() - t0:.1f}s")
        results.append(res)

    if args.json:
        print(json.dumps(
            [{"id": r.cid, "name": r.name, "passed": r.passed,
              "evidence": r.evidence} for r in results],
            ensure_ascii=False, indent=2))
        return 0 if all(r.passed for r in results) else 1

    print("=" * 72)
    print("启动方式验收结果")
    print("=" * 72)
    for r in results:
        flag = "✅ 通过" if r.passed else "❌ 失败"
        print(f"\n[{r.cid}] {r.name}  —— {flag}")
        for line in r.evidence:
            print(f"    {line}")
    passed = sum(1 for r in results if r.passed)
    print("\n" + "=" * 72)
    print(f"合计：通过 {passed} / {len(results)}")
    print("=" * 72)
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
