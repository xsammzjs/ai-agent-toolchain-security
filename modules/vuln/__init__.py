# -*- coding: utf-8 -*-
"""漏洞智能研判引擎（门面模块）

对外使用方式与拆分前完全一致：
    from modules import vulnerability as vul
    vul.query_osv(...) / vul.evaluate_confidence(...) / vul.detect_vulnerabilities(...)

内部按职责拆成四层：
    common.py   缓存 / 工具 / 错误记录
    sources.py  OSV / NVD / GitHub / EPSS 四个数据源查询
    rating.py   置信度评级 + 修复优先级
    detect.py   检测编排（串行 / 并发 / 间接依赖）
"""
from modules.vuln.common import (
    _cache_get, _cache_set, _notify, _record_error, query_errors,
    cvss_to_risk_level, severity_str_to_score, nvd_url, github_advisory_url,
)
from modules.vuln.sources import (
    query_osv, extract_ids_from_osv,
    query_nvd, query_github, query_epss,
)
from modules.vuln.rating import evaluate_confidence, calculate_fix_priority
from modules.vuln.detect import (
    detect_vulnerabilities, detect_vulnerabilities_concurrent,
    _extract_version, _is_pure_range, version_basis,
    _extract_osv_score, _iter_osv_ranges,
)

__all__ = [
    "query_osv", "query_nvd", "query_github", "query_epss",
    "extract_ids_from_osv", "evaluate_confidence", "calculate_fix_priority",
    "detect_vulnerabilities", "detect_vulnerabilities_concurrent",
    "query_errors", "cvss_to_risk_level", "severity_str_to_score",
    "nvd_url", "github_advisory_url", "version_basis",
]
