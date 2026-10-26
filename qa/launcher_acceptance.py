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
6. **Streamlit 冷启动要 10-30 秒**。所有「等服务起来」的断言必须用
   **轮询 + 超时**，不能用固定 sleep —— 否则会在服务还没起来时就判 FAIL
   （这是测试方法 Bug，不是产品缺陷）。
7. 用 Popen 拉起 start.py 后，要**持续读取 stdout**（否则管道写满会死锁），
   且必须用 CREATE_NEW_PROCESS_GROUP 之外的稳妥方式在 finally 里
   连子进程一起杀干净。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
VENV_PY = ROOT / ".venv" / "Scripts" / "python.exe"
BAT = ROOT / "快速运行.bat"
START_PY = ROOT / "start.py"

# 测端口用的哑巴占用者端口（避开 8501）
#
# ⚠️ 端口必须**每个进程实例唯一** —— 实测踩过：两���人同时跑验收脚本
# （我和主理人各跑一份），固定端口 8765 会互相抢端口，
# 一方的 kill_port_listeners 还会把另一方的服务杀掉，
# 结果两边都误判 FAIL。所以这里按 PID 派生一个唯一端口。
TEST_PORT_BASE = 8900


def _pick_test_port() -> int:
    """挑一个当前没人用的测试端口。

    🔴 为什么要动态挑：
       固定端口（或只按 pid 派生）时，两个实例同时跑会撞到同一端口，
       互相 kill_port_listeners → 双方结果都不可信，还可能误杀对方的服务。
       所以这里从 pid 派生的起点开始，逐个试到没人占用为止。
    """
    start = TEST_PORT_BASE + (os.getpid() % 400)
    for candidate in range(start, start + 60):
        try:
            proc = subprocess.run(["netstat", "-ano", "-p", "TCP"],
                                  capture_output=True, timeout=8)
            out = proc.stdout.decode("gbk", errors="replace")
        except (OSError, subprocess.SubprocessError):
            return candidate
        busy = any(":%d " % candidate in line and "LISTENING" in line
                   for line in out.splitlines())
        if not busy:
            return candidate
    return start


TEST_PORT = _pick_test_port()

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
        self._failed = False
        self.evidence: List[str] = []
        self.error = ""

    @property
    def passed(self) -> bool:
        """没有任何一条断言失败才算通过。"""
        return not self._failed

    def check(self, condition: bool, detail: str) -> bool:
        """记录一条断言；返回是否通过（便于链式使用）。"""
        mark = "PASS" if condition else "FAIL"
        self.evidence.append(f"[{mark}] {detail}")
        if not condition:
            self._failed = True
        return condition

    def note(self, detail: str) -> None:
        self.evidence.append(f"[INFO] {detail}")


def netstat_listening(port: int) -> List[str]:
    """返回该端口 LISTENING 的 netstat 行（GBK 解码）。

    ⚠️ 端口必须**精确匹配**：``":8765" in line`` 会把 ``":87650"`` 也算进来
    （实测确认），导致「以为端口被占」或「以为端口已释放」的误判。
    netstat 的本地地址列格式是 ``127.0.0.1:8765`` + 空格，
    所以用 ``":<port> "``（带尾随空格）就能精确命中。
    """
    proc = subprocess.run(["netstat", "-ano", "-p", "TCP"], capture_output=True)
    out = proc.stdout.decode("gbk", errors="replace")
    needle = f":{port} "
    return [l.strip() for l in out.splitlines()
            if needle in l and "LISTENING" in l]


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
    """启动一个占用端口的哑巴进程，返回 Popen。

    🔴 两个必须做对的地方（都踩过坑）：

    1. **启动失败必须能被发现**：端口被占时 bind 抛异常、进程直接退出，
       stdout 关闭、readline() 返回空串。若把空串当成功，
       「占用者其实没起来」会被当成「占用成功」，把后面所有断言带偏。
       所以这里要求读到 "HELD" 且进程还活着，否则抛 RuntimeError。

    2. **bind 失败要重试**：端口可能还在 TIME_WAIT，
       刚 kill 掉上一个占用者立刻重绑会失败。带退避重试几次。

    调用方**必须**用 try/finally 保证 holder 被 kill —— 见 kill_holder()。
    """
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
    last_err = ""
    for attempt in range(4):
        proc = subprocess.Popen([str(VENV_PY), "-c", code],
                                stdout=subprocess.PIPE, text=True)
        line = proc.stdout.readline()
        if "HELD" in (line or "") and proc.poll() is None:
            time.sleep(0.3)
            return proc
        # 启动失败：把错误信息收回来，并确认进程真的退出了
        try:
            err = proc.stderr.read() if proc.stderr else ""
        except Exception:                      # noqa: BLE001
            err = ""
        last_err = (err or line or "").strip()
        proc.kill()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        time.sleep(1.0 + attempt)             # 退避，等 TIME_WAIT 释放
    raise RuntimeError(
        f"哑巴占用者没能占用 {addr}:{port}（重试 4 次均失败）：{last_err}")


def kill_holder(proc) -> None:
    """**保证**占位进程被清理干净（异常路径也必须走到这里）。"""
    if proc is None:
        return
    try:
        if proc.poll() is None:
            proc.kill()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    except Exception:                          # noqa: BLE001
        pass
    finally:
        # 兜底：万一 kill 没生效，用端口反查再杀一次
        try:
            for line in netstat_listening(_holder_port_of(proc)):
                parts = line.split()
                if parts:
                    kill_pid(int(parts[-1]))
        except Exception:                      # noqa: BLE001
            pass


def _holder_port_of(proc) -> int:
    """从占位进程的命令行里取回端口号（兜底清理用）。"""
    try:
        cmd = " ".join(proc.args)
        m = re.search(r"\((\"?'?\d+\.?'?),\s*(\d+)\)", cmd)
        if m:
            return int(m.group(2))
        m = re.search(r"bind\(\(.*?,\s*(\d+)\)", cmd)
        if m:
            return int(m.group(1))
    except Exception:                          # noqa: BLE001
        pass
    return TEST_PORT


def kill_pid(pid: int) -> None:
    subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                   capture_output=True)


def kill_port_listeners(port: int) -> None:
    """杀掉监听指定端口的所有进程。

    ⚠️ 只应用于**本进程实例专属**的测试端口（TEST_PORT 按 PID 派生），
    绝不能拿去扫 8501 等公共端口 —— 那会杀掉别人的服务。
    """
    for line in netstat_listening(port):
        parts = line.split()
        if parts:
            kill_pid(int(parts[-1]))
    # 等端口真正释放（taskkill 是异步的）
    deadline = time.time() + 5
    while time.time() < deadline:
        if not netstat_listening(port):
            break
        time.sleep(0.3)


def run_cmd(cmd: List[str], cwd: Path = ROOT, timeout: int = 120,
            env: Optional[Dict[str, str]] = None) -> Tuple[int, str]:
    """执行命令，返回 (returncode, 合并输出)。

    stdin 必须接 DEVNULL —— 否则 .bat 里的 `pause` 会一直等按键，
    把整个验收脚本挂死。
    """
    try:
        proc = subprocess.run(cmd, cwd=str(cwd), capture_output=True,
                              text=True, timeout=timeout,
                              encoding="utf-8", errors="replace", env=env,
                              stdin=subprocess.DEVNULL)
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
# 轮询工具 —— 替代固定 sleep，等「服务真正就绪」
# ==========================================================
def wait_until(predicate: Callable[[], bool], timeout: float,
               interval: float = 2.0) -> bool:
    """轮询直到 predicate 为真或超时。

    Streamlit 冷启动要 10-30 秒，用固定 sleep 会误判，
    所以**一律用这个**。返回是否在超时前等到。
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def wait_for_health(port: int, timeout: float = 90.0,
                    interval: float = 2.0) -> bool:
    """轮询等待 /_stcore/health 返回 ok。"""
    return wait_until(lambda: health_ok(port), timeout, interval)


class Launcher:
    """拉起 start.py 并持续收割 stdout，用完保证连子进程一起清干净。

    ⚠️ 关键实现细节：**不能**用阻塞的 `stdout.readline()` 去等关键词。
    readline() 在没有新输出时会一直阻塞，导致「超时检查」根本执行不到，
    整个验收脚本被挂死（实测踩过）。
    正确做法：起一个后台线程专门读 stdout，主线程只轮询缓冲区。
    """

    def __init__(self, args: List[str], env: Optional[Dict[str, str]] = None) -> None:
        run_env = dict(os.environ)
        run_env["BROWSER"] = "echo"          # 捕获浏览器实际打开的 URL
        run_env["NO_PROXY"] = "127.0.0.1,localhost"
        run_env["no_proxy"] = run_env["NO_PROXY"]
        if env:
            run_env.update(env)
        self.proc = subprocess.Popen(
            [str(VENV_PY), "start.py", *args],
            cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", env=run_env,
            bufsize=1,
            # Windows 上必须新建进程组，Ctrl+C(CTRL_BREAK) 才能送达子进程
            creationflags=(subprocess.CREATE_NEW_PROCESS_GROUP
                           if os.name == "nt" else 0),
        )
        self._buf: List[str] = []
        self._lock = threading.Lock()
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self) -> None:
        """后台线程：不停把 stdout 读进缓冲区。"""
        try:
            for line in self.proc.stdout:
                with self._lock:
                    self._buf.append(line)
        except (ValueError, OSError):
            pass

    @property
    def output(self) -> str:
        with self._lock:
            return "".join(self._buf)

    def pump(self, keywords: List[str], timeout: float = 120.0) -> str:
        """等到出现任一关键词或超时。"""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            text = self.output
            if any(k in text for k in keywords):
                return text
            if self.proc.poll() is not None:
                # 进程已退出，再等一会儿看有没有残留输出
                time.sleep(0.5)
                return self.output
            time.sleep(0.3)
        return self.output

    def read_all(self, seconds: float = 3.0) -> str:
        """再等一会儿，让后续输出（服务就绪提示等）进缓冲区。"""
        time.sleep(seconds)
        return self.output

    def alive(self) -> bool:
        return self.proc.poll() is None

    def close(self) -> None:
        """结束进程并清掉它派生出来的 streamlit 子进程。"""
        if self.proc.poll() is None:
            self.proc.kill()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
        # start.py 自己被 kill 后，streamlit 子进程会变孤儿，必须单独清
        for port in range(TEST_PORT, TEST_PORT + 5):
            kill_port_listeners(port)
        try:
            self.proc.stdout.close()
        except Exception:                     # noqa: BLE001
            pass

    def __enter__(self) -> "Launcher":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


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


def case_h1_no_venv_first_run(res: Result) -> None:
    """H1（慢速，opt-in）：没有 .venv 时能否自建并装依赖。

    ⚠️ **绝不能删项目的 .venv** —— 这里把项目复制到临时目录再测。
    ⚠️ 依赖安装要联网、耗时 2-5 分钟，所以默认不在常规套件里跑，
       用 `--only H1` 单独触发。
    """
    import shutil
    import tempfile

    tmp = Path(tempfile.mkdtemp(prefix="qa_novenv_"))
    try:
        # 复制项目（排除 .venv / 大目录），模拟「用户刚拿到项目」
        for item in ("main.py", "config.py", "requirements.txt", "start.py",
                     "launcher.py", "快速运行.bat"):
            src = ROOT / item
            if src.exists():
                shutil.copy2(src, tmp / item)
        for sub in ("modules", "views", ".streamlit"):
            src = ROOT / sub
            if src.is_dir():
                shutil.copytree(src, tmp / sub,
                                ignore=shutil.ignore_patterns("__pycache__"))
        res.check(not (tmp / ".venv").exists(), "临时目录里确实没有 .venv")

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
    ("C3", "占用者绑 0.0.0.0 时也能识别（防重复实例）", case_c3_wildcard_occupant, True),
    ("D1", "自动开浏览器且 URL 与实际端口一致", case_d1_open_browser, True),
    ("E1", "停止方式明确告知", case_e1_stop_method, True),
    ("E2", "Ctrl+C 后端口释放、无孤儿进程", case_e2_ctrl_c_no_orphan, True),
    ("F1", "四个视图都能执行（AppTest）", case_f1_four_views, True),
    ("F2", "health 接口返回 200 ok", case_f2_health_endpoint, True),
    ("G1", "bat 委托 start.py（单一逻辑源）", case_g1_bat_delegates, True),
    ("G2", "--check 不开浏览器", case_g2_no_browser_in_check, True),
    ("G3", "bat 正确传递 start.py 退出码", case_g3_bat_exit_code, True),
    ("G4", "start.py 接受 bat 传的 --ask-port", case_g4_bat_ask_port, True),
    ("G5", "交互提示端口号跟随实际起始端口", case_g5_ask_port_prompt, True),
    ("G6", "用户取消时退出码非 0", case_g6_cancel_exit_code, True),
]

# 慢速用例：需要联网装依赖，默认不跑（用 --only H1 或 --slow 触发）
SLOW_CASES: List[Tuple[str, str, Callable[[Result], None], bool]] = [
    ("H1", "无 venv 首次运行能自建并装依赖（慢）", case_h1_no_venv_first_run, True),
]


def main(argv: Optional[List[str]] = None) -> int:
    # 输出重定向到文件时必须实时刷新，否则中途被 kill 会一个字都看不到
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(line_buffering=True)      # type: ignore[union-attr]
        except (AttributeError, OSError, ValueError):
            pass

    parser = argparse.ArgumentParser(description="启动方式验收工具箱")
    parser.add_argument("--list", action="store_true", help="只列用例清单")
    parser.add_argument("--only", nargs="*", help="只跑指定编号，如 A1 C2")
    parser.add_argument("--slow", action="store_true",
                        help="额外跑慢速用例（需联网装依赖，耗时数分钟）")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    args = parser.parse_args(argv)

    all_cases = CASES + (SLOW_CASES if args.slow else [])

    if args.list:
        print("验收用例清单：")
        for cid, name, _fn, _safe in CASES:
            print(f"  {cid:4s} {name}")
        print("慢速用例（需 --slow 或 --only H1）：")
        for cid, name, _fn, _safe in SLOW_CASES:
            print(f"  {cid:4s} {name}")
        return 0

    selected = all_cases
    if args.only:
        keys = {k.upper() for k in args.only}
        selected = [c for c in all_cases if c[0].upper() in keys]
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
