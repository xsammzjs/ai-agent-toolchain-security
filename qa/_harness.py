# -*- coding: utf-8 -*-
"""验收测试框架（QA 内部模块）

=====================================================
职责
=====================================================
只放「怎么跑一条用例」需要的通用件：
  - Result        断言结果收集
  - http/health   本机请求（**必须绕过代理**，见下）
  - run_cmd       执行命令
  - wait_until    轮询等待（**不要用固定 sleep**）
  - Launcher      拉起 start.py 并持续收割 stdout

🔴 两条最容易踩的坑（都实测踩过）：
  1. 本机设了 http_proxy / https_proxy，本机回环请求会走代理而超时。
     所以必须用 ProxyHandler({}) 清空代理。
  2. 等子进程输出**不能**用阻塞的 stdout.readline() —— 没有新输出时
     它会一直卡住，导致「超时检查」根本执行不到，整个脚本挂死。
     必须用后台线程读 + 主线程轮询（见 Launcher）。

用例本身在 cases_*.py 里，不要往这里加断言。
"""

from __future__ import annotations

import os
import subprocess
import threading
import time
import urllib.request
from pathlib import Path
from typing import Callable, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
VENV_PY = ROOT / ".venv" / "Scripts" / "python.exe"
BAT = ROOT / "快速运行.bat"
START_PY = ROOT / "start.py"

# 本进程实例专属的测试端口（Launcher 收尾时要用它清理子进程）
from _portkit import TEST_PORT, kill_port_listeners          # noqa: E402

# 用例注册项的类型：(编号, 名称, 执行函数, 是否安全可跑)
Case = Tuple[str, str, Callable[["Result"], None], bool]

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
        self._skipped = False
        self.skip_reason = ""
        self.evidence: List[str] = []
        self.error = ""

    @property
    def passed(self) -> bool:
        """没有任何一条断言失败才算通过（跳过的也算没失败）。"""
        return not self._failed

    @property
    def skipped(self) -> bool:
        """因环境不具备条件而跳过 —— 不算失败。"""
        return self._skipped

    def check(self, condition: bool, detail: str) -> bool:
        """记录一条断言；返回是否通过（便于链式使用）。"""
        mark = "PASS" if condition else "FAIL"
        self.evidence.append(f"[{mark}] {detail}")
        if not condition:
            self._failed = True
        return condition

    def skip(self, reason: str) -> None:
        """因环境不具备条件而跳过本用例（不算失败，但要说明原因）。

        用于「这台机器没有前台控制台，信号投递不出去」这类
        **环境差异**场景 —— 判 FAIL 会让换个环境就假失败。
        """
        self._skipped = True
        self.skip_reason = reason
        self.evidence.append(f"[SKIP] {reason}")

    def note(self, detail: str) -> None:
        self.evidence.append(f"[INFO] {detail}")



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
