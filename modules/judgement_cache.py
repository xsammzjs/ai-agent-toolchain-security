# -*- coding: utf-8 -*-
"""AI 分诊结果的磁盘缓存层（从 modules/adjudicator.py 拆出，2026-10-28）

【职责边界】本模块只做缓存读写，不含任何业务逻辑：
  - 不调用大模型、不做判定解析（那在 modules/adjudicator.py）
  - 不关心判定字段含义，entry 对调用方是不透明 dict

【安全设计（QA 验收整改）】
  1. 原子写入：临时文件用 tempfile.mkstemp 生成唯一名，写完 os.replace，
     进程崩溃 / 多进程并发都不会留下半截 JSON 或互相覆盖临时文件；
  2. 同进程并发：threading.Lock 串行化「读-改-写」，避免多线程交错覆盖；
  3. 损坏自愈：读到损坏 JSON 时把原文件改名为 .bak 保留现场（可人工排查），
     再返回空 dict——绝不静默清空用户的缓存资产。
  写入失败只打印告警：缓存丢失的代价是多花一次模型调用，不影响判定本身。
"""
import json
import os
import tempfile
import threading

# 进程内互斥锁：串行化同一进程内多线程的读-改-写
_CACHE_LOCK = threading.Lock()

# 默认缓存路径：项目根 data_store/ai_judgement_cache.json
JUDGEMENT_CACHE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data_store", "ai_judgement_cache.json")


def cache_key(name: str, text: str) -> str:
    """缓存键：sha256(技能名 + "\\0" + 正文)[:16]，内容一变即自动失效。"""
    import hashlib
    return hashlib.sha256((name + "\x00" + text).encode("utf-8")).hexdigest()[:16]


def load_cache(path: str = "") -> dict:
    """读取磁盘缓存。文件不存在返回空 dict。

    文件损坏（JSON 解析失败）时：把原文件改名为 <path>.bak 保留现场，
    再返回空 dict——不静默清空，用户可从 .bak 人工恢复。
    """
    p = path or JUDGEMENT_CACHE_PATH
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except OSError:
        return {}          # 文件不存在 / 无权限：正常首跑，直接空缓存
    except ValueError:
        bak = p + ".bak"
        try:
            if os.path.exists(bak):
                os.remove(bak)
            os.replace(p, bak)
            print(f"[AI研判] 分诊缓存文件损坏，已保留为 {bak}，本次从空缓存开始")
        except OSError as e:
            print(f"[AI研判] 分诊缓存文件损坏且备份失败（{e}），本次从空缓存开始")
        return {}


def store_entry(key: str, entry: dict, path: str = "") -> None:
    """以「读-改-写 + 原子替换」方式追加一条缓存。

    - 加锁串行化同进程并发；每次重新读盘再合并，避免覆盖他处新增条目；
    - 临时文件用 tempfile.mkstemp 生成唯一名（同进程加锁串行、跨进程也不互踩），
      写完 os.replace 原子替换，任何时刻磁盘上都只有完整 JSON。
    """
    p = path or JUDGEMENT_CACHE_PATH
    try:
        cache_dir = os.path.dirname(p)
        if cache_dir:
            os.makedirs(cache_dir, exist_ok=True)
        with _CACHE_LOCK:
            data = load_cache(p)
            data[key] = entry
            fd, tmp = tempfile.mkstemp(
                dir=cache_dir or ".",
                prefix="ai_judgement_cache.", suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(data, f, ensure_ascii=False, indent=1)
                os.replace(tmp, p)
            except OSError:
                try:
                    os.remove(tmp)      # 清理半截临时文件，原缓存不受影响
                except OSError:
                    pass
                raise
    except OSError as e:
        print(f"[AI研判] 分诊缓存写入失败（{e}），本次结果不缓存")
