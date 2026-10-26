# -*- coding: utf-8 -*-
"""测试端口的挑选与加锁（QA 内部模块）

=====================================================
职责
=====================================================
只管一件事：给**本进程实例**挑一个别人没占、也没锁住的测试端口。

🔴 为什么这么讲究（都是实测踩过的坑）：
  1. 固定端口 → 两个并发跑的验收脚本互相抢端口，
     一方的 kill_port_listeners 会把另一方的服务杀掉，双方结果都不可信。
  2. 只按 `pid % N` 派生 → PID 会回收复用，两个实例完全可能拿到同一个余数。
     症状是「服务莫名消失、退出码 4294967295（= taskkill /F 的特征）」。
  3. 光扫 netstat 找空闲有 TOCTOU 竞态 —— 两个实例可能同时看到同一个端口空闲。
     所以再加一把**带 PID 的锁文件**（O_CREAT|O_EXCL 原子创建）做「逻辑独占」。
  4. 锁文件靠 atexit 释放，但 atexit 只在正常退出时跑；被 SIGTERM/SIGKILL
     打断的运行会留下孤儿锁 —— 所以启动时扫一遍，把持有者已死的锁清掉。

被 _portkit.py 与 cases_*.py 使用；不要在这里写断言逻辑。
"""

from __future__ import annotations

import atexit
import os
import random
import subprocess
import time
from pathlib import Path
from typing import List

# 测端口用的哑巴占用者端口（避开 8501）
TEST_PORT_BASE = 8900
TEST_PORT_SPAN = 400


def _lock_path(port: int) -> Path:
    """端口锁文件路径 —— 内容是持有者 PID。"""
    lock_dir = Path(os.environ.get("TEMP") or "/tmp") / "sbom_qa_port_locks"
    lock_dir.mkdir(parents=True, exist_ok=True)
    return lock_dir / f"port_{port}.lock"


def _pid_alive(pid: int) -> bool:
    """这个 PID 的进程还在吗？"""
    try:
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}"],
                             capture_output=True, timeout=8).stdout
        return str(pid) in out.decode("gbk", errors="replace")
    except (OSError, subprocess.SubprocessError):
        return True                        # 查不了就保守当成活着


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
    return _pid_alive(owner)


def _claim_port(port: int) -> bool:
    """尝试占住这个端口的锁。

    锁文件被 SIGKILL/SIGTERM 打断时不会被 atexit 清掉（atexit 只在正常退出时跑），
    所以这里遇到「锁存在但持有者已死」时要**主动清理再抢**，
    否则过期锁会越积越多。
    """
    lock = _lock_path(port)
    for _attempt in range(2):
        try:
            # O_EXCL 保证原子性：别人先拿到就抢不走
            fd = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            try:
                os.write(fd, str(os.getpid()).encode("ascii"))
            finally:
                os.close(fd)
            return True
        except FileExistsError:
            if _port_locked_by_other(port):
                return False                 # 持有者还活着，不能抢
            # 持有者已死 —— 锁过期，清掉再抢一次
            try:
                lock.unlink()
            except OSError:
                return False
        except OSError:
            return True                    # 建不了锁就当占住了，保守
    return False


def _release_port(port: int) -> None:
    """释放端口锁。"""
    try:
        _lock_path(port).unlink()
    except OSError:
        pass


def _reap_stale_locks() -> None:
    """启动时清掉「持有者已死」的过期锁文件。

    锁文件靠 atexit 释放，但 atexit 只在**正常退出**时执行 ——
    被 SIGTERM/SIGKILL 打断的运行会留下孤儿锁。
    虽然过期锁在抢锁时会被判定为「可抢」，但它们会一直堆在磁盘上。
    所以这里启动时扫一遍，把持有者进程已不存在的锁删掉。
    """
    lock_dir = _lock_path(0).parent
    try:
        locks = list(lock_dir.glob("port_*.lock"))
    except OSError:
        return
    for lock in locks:
        try:
            owner = int(lock.read_text(encoding="utf-8").strip() or "0")
        except (OSError, ValueError):
            owner = 0
        if owner and _pid_alive(owner):
            continue                        # 持有者还活着，锁有效
        try:
            lock.unlink()
        except OSError:
            pass


def _pick_test_port() -> int:
    """挑一个当前没人用、也没被别的实例锁住的测试端口。

    🔴 为什么要动态挑 + 加锁：
       固定端口（或只按 pid 派生）时，两个实例同时跑会撞到同一端口，
       互相 kill_port_listeners → 双方结果都不可信，还可能误杀对方的服务。
    """
    _reap_stale_locks()
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

# 本进程实例专属的测试端口。挑一次、全程用它，
# 并在退出时释放锁（避免锁文件残留影响下次跑）。
TEST_PORT = _pick_test_port()
atexit.register(_release_port, TEST_PORT)
