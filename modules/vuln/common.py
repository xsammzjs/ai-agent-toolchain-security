# -*- coding: utf-8 -*-
"""漏洞研判 · 公共层：查询缓存、评分工具、错误记录。

本模块被 sources / rating / detect 三层共用。
"""
import copy
import os
import sys
import threading
import time


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config import config


# ==========================================
# 查询结果缓存（2026-09-09 新增）
# 同一包版本 / CVE / GHSA 的查询结果缓存 1 小时，避免重复调外部 API。
# 1 小时过期：漏洞库更新后用户能看到新数据；仅内存缓存，重启即清空。
# ==========================================
_CACHE_TTL_SECONDS = 3600
_api_cache: dict = {}
_api_cache_lock = threading.Lock()


def _cache_get(key: tuple):
    with _api_cache_lock:
        hit = _api_cache.get(key)
        if hit and time.time() - hit[0] < _CACHE_TTL_SECONDS:
            return copy.deepcopy(hit[1])
        if hit:
            _api_cache.pop(key, None)
        return None


def _cache_set(key: tuple, value):
    with _api_cache_lock:
        if len(_api_cache) > 5000:
            now = time.time()
            expired = [k for k, v in _api_cache.items() if now - v[0] >= _CACHE_TTL_SECONDS]
            for k in expired:
                _api_cache.pop(k, None)
        _api_cache[key] = (time.time(), value)


def _notify(cb, msg: str, percent=None):
    """进度回调（cb 可能为 None；回调自身异常不影响扫描）。
    percent 为 None 时只更新阶段文本，否则同时更新整体进度百分比。"""
    if cb:
        try:
            cb(msg, percent)
        except Exception:
            pass

# ==========================================
# 工具函数
# ==========================================

def cvss_to_risk_level(score: float) -> str:
    """CVSS 分数 → 中文风险等级"""
    if score >= config.CVSS_CRITICAL:
        return "严重"
    elif score >= config.CVSS_HIGH:
        return "高危"
    elif score >= 4.0:
        return "中危"
    elif score > 0:
        return "低危"
    return "未知"


def severity_str_to_score(severity_str: str) -> float:
    """文字严重程度 → 估算 CVSS"""
    mapping = {
        "CRITICAL": 9.0, "HIGH": 7.5, "MODERATE": 5.0,
        "MEDIUM": 5.0, "LOW": 2.0, "NONE": 0.0
    }
    return mapping.get(severity_str.upper().strip(), 0.0)


def nvd_url(cve_id: str) -> str:
    """生成 NVD 直达链接"""
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"


def github_advisory_url(ghsa_id: str) -> str:
    """生成 GitHub Advisory 直达链接"""
    return f"https://github.com/advisories/{ghsa_id}"


# ==========================================
# 1. OSV 查询（主数据源）
# ==========================================

# ==========================================
# 查询失败计数（2026-10-05 新增）
# ==========================================
# 背景：原实现把超时/网络异常一律吞成空列表，并且**把空结果写进缓存**。
# 后果极其危险——网络中断、被限流、接口报错时，工具会显示"零漏洞"，
# 与"这个包真的没有漏洞"完全无法区分，属于静默假阴性。
# 现在：失败不进缓存（下次重试），并累计计数，供界面如实披露。
_QUERY_ERRORS: dict = {}


# 背景：原实现把超时/网络异常一律吞成空列表，并且**把空结果写进缓存**。
# 后果极其危险——网络中断、被限流、接口报错时，工具会显示"零漏洞"，
# 与"这个包真的没有漏洞"完全无法区分，属于静默假阴性。
# 现在：失败不进缓存（下次重试），并累计计数，供界面如实披露。
_QUERY_ERRORS: dict = {}


def _record_error(source: str):
    with _api_cache_lock:
        _QUERY_ERRORS[source] = _QUERY_ERRORS.get(source, 0) + 1


def query_errors(reset: bool = False) -> dict:
    """返回各数据源的失败计数。reset=True 时读取后清零。"""
    with _api_cache_lock:
        snapshot = dict(_QUERY_ERRORS)
        if reset:
            _QUERY_ERRORS.clear()
        return snapshot
