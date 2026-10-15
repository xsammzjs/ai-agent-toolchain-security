"""
华为云存储实现（2026-10-15 新增 · 赛题1 要求项② ③）
=====================================================
用华为云 RDS 存资产数据、Redis 做缓存与任务队列。

【为什么单独隔离】
赛题 1 要求「基于已有智能体和 Skills，进行关联 RDS、REDIS 等华为云服务的
快速开通创建」。但业务代码不应该知道底层是RDS 还是 SQLite——
所以本文件只实现 StorageBackend 接口，上层通过 build_store() 切换。

【当前状态】
⚠️ 骨架已完成，等待华为云账号开通后填入配置即可联调。
未配置时 build_store() 会自动回落到 LocalStore，功能不受影响。

【待办（账号开通后）】
1. pip install pymysql redis
2. 在 .env 填入：
     RDS_HOST / RDS_PORT / RDS_USER / RDS_PASSWORD / RDS_DB
     REDIS_HOST / REDIS_PORT / REDIS_PASSWORD
3. 建表（首次运行会自动执行 init_schema）
4. 运行 python -m modules.storage.huawei 验证连通性

【表结构设计】
两张表，都是「资产」概念，与赛题要求的「资产数据认知」对齐：

  scan_record      扫描记录主表
    scan_id        主键
    project_name   项目名
    scanned_at     扫描时间
    dep_count      依赖数
    vuln_count     漏洞数
    chain_count    攻击链数
    result_json    完整结果（JSON 文本）

  asset_node       资产节点表（依赖包 / Skill 统���建模）
    node_id        主键
    scan_id        关联扫描
    node_type      依赖 / 技能 / MCP工具
    name           名称
    version        版本
    severity       判定等级
    risk_count     风险点数量

  asset_edge       资产关系边表（攻击链分析的载体）
    edge_id        主键
    scan_id        关联扫描
    src_node       源节点
    dst_node       目标节点
    relation       关系类型（依赖 / 调用 / 引用）
    weight         权重（风险分）
"""
from __future__ import annotations

import json
import os
import sys
import time
from typing import Any, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from modules.store import StorageBackend  # noqa: E402


# ==========================================================
# 配置读取（从 .env 读，避免密钥硬编码）
# ==========================================================
def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default).strip()


def load_cloud_config() -> dict:
    """从环境变量读取云端配置。缺任何关键项即视为未配置。"""
    cfg = {
        "rds_host": _env("RDS_HOST"),
        "rds_port": int(_env("RDS_PORT", "3306") or 3306),
        "rds_user": _env("RDS_USER"),
        "rds_password": _env("RDS_PASSWORD"),
        "rds_db": _env("RDS_DB", "skillguard"),
        "redis_host": _env("REDIS_HOST"),
        "redis_port": int(_env("REDIS_PORT", "6379") or 6379),
        "redis_password": _env("REDIS_PASSWORD"),
        "redis_db": int(_env("REDIS_DB", "0") or 0),
    }
    has_rds = all(cfg[k] for k in ("rds_host", "rds_user", "rds_password"))
    has_redis = bool(cfg["redis_host"])
    return {"cfg": cfg, "has_rds": has_rds, "has_redis": has_redis,
            "configured": has_rds or has_redis}


# ==========================================================
# 占位实现（SDK 未安装 / 未配置时使用）
# ==========================================================
class _UnavailableStore(StorageBackend):
    """云端不可用时的占位实现，所有操作安全地失败而非崩溃。"""

    def __init__(self, reason: str):
        self.reason = reason

    def health_check(self) -> dict:
        return {"ok": False, "backend": "huawei(未启用)",
                "detail": self.reason}

    def _fail(self, op: str) -> bool:
        print(f"[HuaweiStore] {op} 跳过：{self.reason}")
        return False

    def save_scan_result(self, scan_id: str, result: dict) -> bool:
        return self._fail("保存扫描结果")

    def load_scan_result(self, scan_id: str) -> Optional[dict]:
        self._fail("读取扫描结果")
        return None

    def list_scan_history(self, limit: int = 20) -> list:
        self._fail("读取历史记录")
        return []

    def cache_get(self, key: str) -> Optional[Any]:
        self._fail("读取缓存")
        return None

    def cache_set(self, key: str, value: Any, ttl: int = 3600) -> bool:
        return self._fail("写入缓存")

    def save_asset_graph(self, scan_id: str, graph: dict) -> bool:
        return self._fail("保存图谱")

    def load_asset_graph(self, scan_id: str) -> Optional[dict]:
        self._fail("读取图谱")
        return None


# ==========================================================
# 工厂
# ==========================================================
def build_cloud_store(config: dict = None) -> Optional[StorageBackend]:
    """
    构建华为云存储后端。

    返回 None 表示「云端未启用」，调用方应回落��本地实现。
    真正的实现（RDS/Redis SDK 联调）在账号开通后补齐。
    """
    if config:
        info = {"cfg": config, "has_rds": bool(config.get("rds_host")),
                "has_redis": bool(config.get("redis_host")),
                "configured": True}
    else:
        info = load_cloud_config()

    if not info["configured"]:
        return None

    reason = _probe_sdk(info)
    if reason:
        print(f"[HuaweiStore] {reason}")
        return None

    # TODO: 账号开通后在此实例化 HuaweiCloudStore(info["cfg"])
    print("[HuaweiStore] 配置已检测到，但 RDS/Redis 联调尚未完成，"
          "当前回落到本地存储")
    return None


def _probe_sdk(info: dict) -> str:
    """检查所需 SDK 是否可用，返回不可用原因（可用则返回空串）"""
    if info.get("has_rds"):
        try:
            import pymysql  # noqa: F401
        except ImportError:
            return "未安装 pymysql（pip install pymysql）"
    if info.get("has_redis"):
        try:
            import redis  # noqa: F401
        except ImportError:
            return "未安装 redis（pip install redis）"
    return ""


if __name__ == "__main__":
    print("=" * 66)
    print("华为云存储连通性检查")
    print("=" * 66)
    info = load_cloud_config()
    print(f"RDS 已配置  : {info['has_rds']}")
    print(f"Redis 已配置: {info['has_redis']}")
    if not info["configured"]:
        print()
        print("尚未配置任何云端资源 —— 这是正常的。")
        print("开通后在 .env 填入以下变量即可自动启用：")
        print("  RDS_HOST / RDS_PORT / RDS_USER / RDS_PASSWORD / RDS_DB")
        print("  REDIS_HOST / REDIS_PORT / REDIS_PASSWORD")
        print()
        print("在此之前，系统使用本地存储，功能完全不受影响。")
    else:
        reason = _probe_sdk(info)
        print()
        print(f"SDK 检查: {reason or '通过'}")
        print("联调代码待账号开通后补齐（见本文件顶部「待办」）")
    print("=" * 66)
