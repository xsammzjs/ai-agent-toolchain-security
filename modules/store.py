"""
存储抽象层（2026-10-15 新增）
================================
让「本地运行」与「云端部署」共用同一套业务代码。

【解决什么问题】
赛题 1 要求「基于已有智能体和 Skills，进行关联 RDS、REDIS 等华为云服务
的快速开通创建」，而计算机设计大赛要求「提供互联网可访问的网站地址」。
如果业务代码里到处直接写文件读写 / SQLite，接云端时就得大改，
既赶工又容易改坏已验证的逻辑。

本层做法：定义抽象接口 → 提供多种实现 → 由配置决定用哪个。
上层业务代码只依赖接口，不依赖具体实现。

【设计原则】
1. 零第三方依赖：本地实现只用标准库，保证离线可跑
2. 华为云相关代码全部隔离在 huawei 子包，上层不感知
3. 未配置云端时自动降级到本地，不报错、不影响现有功能
4. 接口保持最小：只定义真正会用到的操作，避免过度设计

【使用方式】
    # 默认本地
    store = build_store()

    # 云端（读配置，失败自动回落到本地）
    store = build_store(use_cloud=True)
    store.save_scan_result(scan_id, result)
    history = store.list_scan_history()
"""
from __future__ import annotations

import json
import os
import time
from abc import ABC, abstractmethod
from typing import Any, Optional

DEFAULT_LOCAL_DIR = "data_store"


# ==========================================================
# 一、抽象接口
# ==========================================================
class StorageBackend(ABC):
    """
    存储后端抽象接口。

    方法刻意保持精简——只包含业务真正需要的能力，
    避免为了「看起来完整」而堆砌用不到的方法。
    """

    # ---- 生命周期 ----
    @abstractmethod
    def health_check(self) -> dict:
        """检查存储可用性。返回 {"ok": bool, "backend": str, "detail": str}"""

    # ---- 资产数据（赛题要求的 RDS 承载对象）----
    @abstractmethod
    def save_scan_result(self, scan_id: str, result: dict) -> bool:
        """保存一次完整扫描结果（依赖列表 + 漏洞 + SBOM + 攻击链）"""

    @abstractmethod
    def load_scan_result(self, scan_id: str) -> Optional[dict]:
        """按 scan_id 读取扫描结果"""

    @abstractmethod
    def list_scan_history(self, limit: int = 20) -> list:
        """列出历史扫描记录，按时间倒序。返回 [{"scan_id","name","time","vuln_count"}]"""

    # ---- 缓存（赛题要求的 Redis 承载对象）----
    @abstractmethod
    def cache_get(self, key: str) -> Optional[Any]:
        """读取缓存。不存在返回 None。"""

    @abstractmethod
    def cache_set(self, key: str, value: Any, ttl: int = 3600) -> bool:
        """写入缓存，ttl 为秒。"""

    # ---- 资产图谱（依赖节点 / Skill 节点 / 关系边）----
    @abstractmethod
    def save_asset_graph(self, scan_id: str, graph: dict) -> bool:
        """保存资产图谱，供后续关联分析与趋势对比"""

    @abstractmethod
    def load_asset_graph(self, scan_id: str) -> Optional[dict]:
        """读取资产图谱"""


# ==========================================================
# 二、本地实现（默认，纯标准库）
# ==========================================================
class LocalStore(StorageBackend):
    """
    本地文件存储。零依赖，离线可用。

    数据布局：
        data_store/
          scans/<scan_id>.json        扫描结果
          graphs/<scan_id>.json       资产图谱
          cache/<sha1>.json           缓存（带过期时间戳）
    """

    def __init__(self, base_dir: str = DEFAULT_LOCAL_DIR):
        self.base_dir = base_dir
        self._ensure_dirs()

    def _ensure_dirs(self) -> None:
        for sub in ("scans", "graphs", "cache"):
            os.makedirs(os.path.join(self.base_dir, sub), exist_ok=True)

    def _p(self, kind: str, scan_id: str) -> str:
        return os.path.join(self.base_dir, kind, f"{scan_id}.json")

    def health_check(self) -> dict:
        try:
            self._ensure_dirs()
            probe = os.path.join(self.base_dir, "cache", ".probe")
            with open(probe, "w", encoding="utf-8") as f:
                f.write("ok")
            os.remove(probe)
            return {"ok": True, "backend": "local",
                    "detail": f"本地目录可用：{os.path.abspath(self.base_dir)}"}
        except OSError as e:
            return {"ok": False, "backend": "local", "detail": f"本地目录不可用：{e}"}

    def save_scan_result(self, scan_id: str, result: dict) -> bool:
        return self._write_json(self._p("scans", scan_id), result)

    def load_scan_result(self, scan_id: str) -> Optional[dict]:
        return self._read_json(self._p("scans", scan_id))

    def save_asset_graph(self, scan_id: str, graph: dict) -> bool:
        return self._write_json(self._p("graphs", scan_id), graph)

    def load_asset_graph(self, scan_id: str) -> Optional[dict]:
        return self._read_json(self._p("graphs", scan_id))

    def list_scan_history(self, limit: int = 20) -> list:
        d = os.path.join(self.base_dir, "scans")
        if not os.path.isdir(d):
            return []
        items = []
        for fn in os.listdir(d):
            if not fn.endswith(".json"):
                continue
            path = os.path.join(d, fn)
            try:
                st = os.stat(path)
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
                items.append({
                    "scan_id": fn[:-5],
                    "name": data.get("project_name", fn[:-5]),
                    "time": st.st_mtime,
                    "time_str": time.strftime("%Y-%m-%d %H:%M:%S",
                                             time.localtime(st.st_mtime)),
                    "vuln_count": len(data.get("vulns", [])),
                    "dep_count": len(data.get("dep_list", [])),
                })
            except (OSError, ValueError):
                continue
        items.sort(key=lambda x: x["time"], reverse=True)
        return items[:limit]

    def cache_get(self, key: str) -> Optional[Any]:
        import hashlib
        path = os.path.join(self.base_dir, "cache",
                            hashlib.sha1(key.encode()).hexdigest() + ".json")
        data = self._read_json(path)
        if not data:
            return None
        if time.time() - data.get("_ts", 0) > data.get("_ttl", 3600):
            try:
                os.remove(path)
            except OSError:
                pass
            return None
        return data.get("v")

    def cache_set(self, key: str, value: Any, ttl: int = 3600) -> bool:
        import hashlib
        path = os.path.join(self.base_dir, "cache",
                            hashlib.sha1(key.encode()).hexdigest() + ".json")
        return self._write_json(path, {"v": value, "_ts": time.time(), "_ttl": ttl})

    @staticmethod
    def _write_json(path: str, data: dict) -> bool:
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
            return True
        except (OSError, TypeError) as e:
            print(f"[LocalStore] 写入失败 {path}：{e}")
            return False

    @staticmethod
    def _read_json(path: str) -> Optional[dict]:
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return None


# ==========================================================
# 三、工厂
# ==========================================================
def build_store(use_cloud: bool = False, config: Optional[dict] = None) -> StorageBackend:
    """
    创建存储后端。

    参数:
        use_cloud — 是否尝试使用云端存储
        config    — 云端配置，来自 config.py 的 CLOUD_CONFIG

    行为约定：云端未配置或连接失败时，**静默降级到本地**，并保证功能可用。
    这与 demo_mode 的「宁可明确告知降级，也不伪装正常」是同一原则：
    降级要说出来，但不能因此让系统不可用。
    """
    if not use_cloud:
        return LocalStore()

    try:
        from modules.storage.huawei import build_cloud_store
        store = build_cloud_store(config or {})
        if store is not None:
            return store
    except ImportError:
        print("[Store] 未安装云端存储模块，降级到本地存储")
    except Exception as e:
        print(f"[Store] 云端存储初始化失败（{e}），降级到本地存储")

    return LocalStore()


# ==========================================================
# 四、全局单例（业务代码直接用这个）
# ==========================================================
_STORE: Optional[StorageBackend] = None


def get_store() -> StorageBackend:
    """获取全局存储实例（懒初始化）"""
    global _STORE
    if _STORE is None:
        _STORE = build_store()
    return _STORE


def set_store(store: StorageBackend) -> None:
    """替换全局存储实例（接入云端后调用）"""
    global _STORE
    _STORE = store


if __name__ == "__main__":
    s = build_store()
    info = s.health_check()
    print(f"后端：{info['backend']}")
    print(f"状态：{info['detail']}")

    # 自测
    sid = "selftest"
    ok = s.save_scan_result(sid, {"project_name": "自检", "dep_list": [{"package": "x"}],
                                 "vulns": [{"cve_id": "CVE-TEST"}]})
    print(f"保存扫描结果：{ok}")
    print(f"读取结果：{s.load_scan_result(sid)['project_name']}")
    print(f"历史记录：{s.list_scan_history()}")

    s.cache_set("k1", {"v": 42}, ttl=60)
    print(f"缓存读取：{s.cache_get('k1')}")
    print(f"图谱保存：{s.save_asset_graph(sid, {'nodes': 3, 'edges': 2})}")
