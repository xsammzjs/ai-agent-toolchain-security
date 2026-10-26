# -*- coding: utf-8 -*-
"""漏洞研判 · 间接依赖推断与修复方案生成。

- 间接依赖：基于 PyPI requires_dist 的一层推断
- 修复方案：汇总可修复版本，冲突时取最高
"""

import os
import sys
import time
import warnings

import requests
import urllib3

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config import config
from modules.vuln.common import (_cache_get, _cache_set, _notify, _record_error,
                                 query_errors, cvss_to_risk_level, severity_str_to_score,
                                 nvd_url, github_advisory_url)
from modules.vuln.sources import (query_osv, query_nvd, query_github, query_epss,
                                  extract_ids_from_osv)
from modules.vuln.version import (_extract_version, _is_pure_range, version_basis,
                                _extract_osv_score, _iter_osv_ranges,
                                _extract_fixed_from_osv, _parse_fixed_version)


# ==========================================

def detect_transitive_deps(
    direct_deps: list[dict],
    max_deps: int | None = None,
    request_interval: float | None = None
) -> dict:
    """
    推断一层间接依赖。

    原理：PyPI 每个包的发布信息（JSON API 的 requires_dist 字段）
    会声明它自己依赖哪些包。例如 django 3.2.25 声明依赖
    "asgiref>=3.6,<4"，那么 asgiref 就是 django 的一层间接依赖。
    即：直接依赖 → 查它声明的依赖 → 得到一层间接依赖。

    版本推断规则（保守策略，全部由约束字符串推导，不额外发请求）：
      - "==X"     → X（精确）
      - ">=X,<Y"  → 取 X（保守评估：宁可多报不漏报。实际 pip 会
                    安装满足约束的更新版本，风险只低不高）
      - ">=X"     → 取 X（同上）
      - 仅 "<Y" 或 无约束 → 跳过（版本无法定位，无法查询漏洞）

    限制：
      - 最多收集 max_deps 个间接依赖，超出截断并返回 truncated=True
      - 每次请求之间 sleep，控制频率避免触发 PyPI 限流

    返回: {"deps": [...], "truncated": bool, "limit": int}
    """
    import re as _re

    max_deps = max_deps or config.MAX_TRANSITIVE_DEPS
    request_interval = request_interval if request_interval is not None else config.PYPI_REQUEST_INTERVAL

    direct_keys = {(d["package"].lower(), d.get("ecosystem", "PyPI")) for d in direct_deps}
    transitive = []
    seen = set()
    truncated = False

    for dep in direct_deps:
        if dep.get("ecosystem", "PyPI") != "PyPI":
            continue
        clean_ver = _extract_version(dep["version"], None)
        if not clean_ver:
            continue

        try:
            url = f"{config.PYPI_JSON_API}/{dep['package']}/{clean_ver}/json"
            resp = requests.get(url, timeout=config.PYPI_TIMEOUT)
            if resp.status_code != 200:
                continue
            data = resp.json()
            for entry in (data.get("info", {}).get("requires_dist") or []):
                pkg_name, constraint = _parse_requires_entry(entry)
                if not pkg_name:
                    continue
                if (pkg_name, "PyPI") in direct_keys:
                    continue  # 已是直接依赖，不算间接
                ver = _constraint_to_version(constraint)
                if ver is None:
                    continue
                key = (pkg_name, ver)
                if key in seen:
                    continue
                if len(transitive) >= max_deps:
                    truncated = True
                    break
                seen.add(key)
                transitive.append({
                    "package": pkg_name,
                    "version": ver,
                    "ecosystem": "PyPI",
                    "is_transitive": True,
                    "transitive_from": dep["package"],
                })
        except Exception:
            pass  # 单个依赖查询失败不影响整体

        if truncated:
            break
        time.sleep(request_interval)

    return {"deps": transitive, "truncated": truncated, "limit": max_deps}



def _parse_requires_entry(entry: str) -> tuple:
    """
    解析 requires_dist 单条记录 → (包名, 版本约束)。
    支持格式：
      "asgiref>=3.6,<4"
      "requests (>=2.25.0) ; python_version >= \"3.6\""
      "django[security]>=3.2"
      "Flask>=2.0 ; extra == \"async\""  ← extra 为可选功能标记，跳过
    """
    import re as _re

    main = entry.split(";")[0].strip()  # 去掉环境标记（; 之后）
    if not main:
        return None, None
    if "extra ==" in entry or "extra==" in entry:
        return None, None  # 可选功能依赖（extras），非默认安装，跳过

    m = _re.match(r"^([A-Za-z0-9_.-]+)", main)
    if not m:
        return None, None
    pkg_name = m.group(1).lower()

    rest = main[m.end():].strip()
    constraint = ""
    cm = _re.search(r"([<>=!~].*)$", rest)
    if cm:
        constraint = cm.group(1).replace(" ", "").rstrip(")")
    return pkg_name, constraint



def _constraint_to_version(constraint: str) -> str | None:
    """约束字符串 → 推断版本（保守策略，见 detect_transitive_deps 注释）"""
    import re as _re

    if not constraint:
        return None
    # ==X → 精确
    m = _re.search(r"==\s*([0-9][\w.]*)", constraint)
    if m:
        return m.group(1)
    # >=X（含 ">=X,<Y"）→ 取下限 X 保守评估
    m = _re.search(r">=\s*([0-9][\w.]*)", constraint)
    if m:
        return m.group(1)
    # 仅 "<Y" 无下限 → 无法定位版本
    return None

# ==========================================

def generate_fix_plan(vulns: list[dict]) -> dict:
    """
    汇总所有可修复漏洞，生成一键修复方案。

    规则：
      - 一个包有多个漏洞 → 修复版本取最高（用 PEP 440 版本比较）
      - 一个包多个修复版本冲突时 → 同样取最高
      - 无法修复（无修复版本）→ 单独列入 unfixable

    返回: {
        "fix_map": {包名: {"current": 当前版本, "target": 修复版本,
                          "cve_ids": [...], "severity": 最高风险等级}},
        "unfixable": [{漏洞记录...}]  按 CVE 去重
    }
    """
    import re as _re
    from packaging.version import Version as _PkgVersion

    fix_map = {}
    unfixable = []
    unfixable_seen = set()

    for v in vulns:
        pkg = v["package"]
        fixed = v.get("fixed_version", "未知")
        target = _parse_fixed_version(fixed)
        if target is None:
            key = (v["cve_id"], pkg)
            if key not in unfixable_seen:
                unfixable_seen.add(key)
                unfixable.append(v)
            continue

        if pkg not in fix_map:
            fix_map[pkg] = {
                "current": v["version"],
                "target": target,
                "cve_ids": [v["cve_id"]],
                "severity": v.get("severity", "未知"),
            }
            continue

        entry = fix_map[pkg]
        entry["cve_ids"].append(v["cve_id"])
        # 修复版本冲突 → 取最高
        try:
            if _PkgVersion(target) > _PkgVersion(entry["target"]):
                entry["target"] = target
        except Exception:
            pass  # 版本格式无法比较时保持原值

    return {"fix_map": fix_map, "unfixable": unfixable}
