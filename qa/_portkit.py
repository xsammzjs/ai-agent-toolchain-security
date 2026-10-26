# -*- coding: utf-8 -*-
"""端口与进程工具（QA 内部模块）

=====================================================
职责
=====================================================
只放「跟端口/进程打交道」的低层工具：
  - 测试端口的挑选与加锁（并发跑时互不干扰）
  - 哑巴占用者（占住端口模拟冲突）的启动与**保证清理**
  - netstat 监听查询、端口空闲探测

被 cases_*.py 用例模块调用；不要在这里写断言逻辑。
"""

from __future__ import annotations

import atexit
import os
import random
import socket
import subprocess
import time
from pathlib import Path
from typing import List

ROOT = Path(__file__).resolve().parent.parent
VENV_PY = ROOT / ".venv" / "Scripts" / "python.exe"

# 测端口用的哑巴占用者端口（避开 8501）
#
# 🔴 端口必须**每个进程实例唯一**，否则并发跑的验收脚本会互相
#    kill_port_listeners → 双方结果都不可信，还可能误杀对方的服务。
#
#    ⚠️ 不要只用 `pid % N` 派生 —— PID 会回收复用，两个并发实例完全
#    可能撞到同一个余数（实测踩过：症状是「服务莫名消失、退出码
#    4294967295 = taskkill /F 的特征」）。所以这里用
#    **随机起点 + 逐个试占用**，并在候选端口上放一个带 PID 的锁文件，
#    做到「逻辑独占」而不只是「碰巧不撞」。
TEST_PORT_BASE = 8900
TEST_PORT_SPAN = 400



def _port_is_listening(port: int) -> bool:
    """该端口有没有人在 LISTEN（精确匹配，不误伤 :87650 这种）。"""
    try:
        proc = subprocess.run(["netstat", "-ano", "-p", "TCP"],
                              capture_output=True, timeout=8)
        out = proc.stdout.decode("gbk", errors="replace")
    except (OSError, subprocess.SubprocessError):
        return False
    needle = f":{port} "
    return any(needle in line and "LISTENING" in line for line in out.splitlines())



def _lock_path(port: int) -> Path:
    """端口锁文件路径 —— 内容是持有者 PID。"""
    lock_dir = Path(os.environ.get("TEMP") or "/tmp") / "sbom_qa_port_locks"
    lock_dir.mkdir(parents=True, exist_ok=True)
    return lock_dir / f"port_{port}.lock"



def _port_locked_by_other(port: int) -> bool:
    """这个端口是不是被**别的**活进程占了锁。"""
    lock = _lock_path(port)
    if not lock.exists():
        return False
    try:
        owner = int(lock.read_text(encoding="utf-8").strip() or "0")
    except (OSError, ValueError):
        return False
    if owner == os.getpid():
        return False
    # 持有者还活着吗？死了就当锁失效
    try:
        out = subprocess.run(["tasklist", "/FI", f"PID eq {owner}"],
                             capture_output=True, timeout=8).stdout
        text = out.decode("gbk", errors="replace")
        return str(owner) in text
    except (OSError, subprocess.SubprocessError):
        return True                       # 查不了就保守当成被占



def _claim_port(port: int) -> bool:
    """尝试占住这个端口的锁。"""
    lock = _lock_path(port)
    try:
        # O_EXCL 保证原子性：别人先拿到就抢不走
        fd = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        try:
            os.write(fd, str(os.getpid()).encode("ascii"))
        finally:
            os.close(fd)
        return True
    except FileExistsError:
        return False
    except OSError:
        return True                       # 建不了锁就当占住了，保守



def _release_port(port: int) -> None:
    """释放端口锁。"""
    try:
        _lock_path(port).unlink()
    except OSError:
        pass



def _pick_test_port() -> int:
    """挑一个当前没人用、也没被别的实例锁住的测试端口。

    🔴 为什么要动态挑 + 加锁：
       固定端口（或只按 pid 派生）时，两个实例同时跑会撞到同一端口，
       互相 kill_port_listeners → 双方结果都不可信，还可能误杀对方的服务。
    """
    start = TEST_PORT_BASE + random.randint(0, TEST_PORT_SPAN - 1)
    for offset in range(TEST_PORT_SPAN):
        candidate = start + offset
        if candidate >= TEST_PORT_BASE + TEST_PORT_SPAN:
            candidate = TEST_PORT_BASE + (candidate % TEST_PORT_SPAN)
        if _port_is_listening(candidate):
            continue
        if _port_locked_by_other(candidate):
            continue
        if _claim_port(candidate):
            return candidate
    # 实在挑不到就退回起点（并明确警告）
    print(f"[WARN] 没找到空闲的测试端口，退回 {start}（可能有并发实例在跑）")
    return start



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
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True)
        line = proc.stdout.readline()
        if "HELD" in (line or "") and proc.poll() is None:
            time.sleep(0.3)
            return proc
        # 启动失败：把错误信息收回来，并确认进程真的退出了
        # （stderr 单独收，避免 traceback 刷屏 —— X2 用例会故意触发失败）
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
        try:
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()
        except Exception:                      # noqa: BLE001
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


# 本进程实例专属的测试端口。挑一次、全程用它，
# 并在退出时释放锁（避免锁文件残留影响下次跑）。
TEST_PORT = _pick_test_port()
atexit.register(_release_port, TEST_PORT)
