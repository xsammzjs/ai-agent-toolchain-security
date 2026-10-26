# -*- coding: utf-8 -*-
"""漏洞研判 · 数据源查询层：OSV / NVD / GitHub Advisory / EPSS。

每个查询函数都带 1 小时内存缓存，避免重复调外部 API。
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
                                 query_errors, cvss_to_risk_level,
                                 severity_str_to_score, nvd_url, github_advisory_url)

def query_osv(package_name: str, version: str, ecosystem: str = "PyPI") -> list[dict]:
    """
    向 OSV.dev 查询指定包版本的漏洞。
    返回原始漏洞列表。同包同版本结果缓存 1 小时（见 _CACHE_TTL_SECONDS）。

    失败处理（重要）：查询失败时**不写入缓存**，返回空列表并累计失败计数，
    由调用方通过 stats / query_errors() 向用户披露"本次扫描有多少次查询失败"。
    """
    _key = ("osv", package_name.lower(), version, ecosystem)
    _hit = _cache_get(_key)
    if _hit is not None:
        return _hit

    payload = {
        "package": {"name": package_name, "ecosystem": ecosystem},
        "version": version,
    }
    last_exc = None
    for attempt in range(2):          # 失败重试 1 次，抵御偶发抖动/短时限流
        try:
            resp = requests.post(config.OSV_API, json=payload,
                                 timeout=config.OSV_TIMEOUT)
            resp.raise_for_status()
            result = resp.json().get("vulns", [])
            _cache_set(_key, result)
            return result
        except Exception as e:
            last_exc = e
            time.sleep(0.6 * (attempt + 1))

    _record_error("osv")
    return []


def extract_ids_from_osv(item: dict) -> tuple:
    """从 OSV 返回项中提取 CVE ID 和 GHSA ID"""
    cve_id = None
    ghsa_id = None
    vuln_id = item.get("id", "")
    if vuln_id.startswith("CVE-"):
        cve_id = vuln_id
    elif vuln_id.startswith("GHSA-"):
        ghsa_id = vuln_id
    for alias in item.get("aliases", []):
        if alias.startswith("CVE-") and not cve_id:
            cve_id = alias
        elif alias.startswith("GHSA-") and not ghsa_id:
            ghsa_id = alias
    return cve_id, ghsa_id


# ==========================================
# 2. NVD 查询（精确 CVSS + 向量 + 描述）
# ==========================================

def query_nvd(cve_id: str) -> dict:
    """
    从 NIST NVD 查询 CVE 详细信息。
    返回: {cvss_score, severity, vector, description, cwe_id}
    同 CVE 结果缓存 1 小时（见 _CACHE_TTL_SECONDS）。
    """
    _key = ("nvd", cve_id)
    _hit = _cache_get(_key)
    if _hit is not None:
        return _hit
    result = _query_nvd_uncached(cve_id)
    _cache_set(_key, result)
    return result


def _query_nvd_uncached(cve_id: str) -> dict:
    try:
        import nvdlib
        # 新版 nvdlib：传 delay 参数必须同时提供 API key
        # 有 key → 快速请求（0.7s 间隔，nvdlib 要求 delay>0.6）；无 key → 走 NVD 官方匿名限速（约 6s/次）
        kwargs = {"cveId": cve_id}
        if config.NVD_API_KEY:
            kwargs["key"] = config.NVD_API_KEY
            kwargs["delay"] = 0.7
        results = nvdlib.searchCVE(**kwargs)
        if results:
            cve = results[0]
            score = 0.0
            severity = ""
            vector = ""

            # 优先级：v3.1 > v3.0 > v2.0
            if hasattr(cve, 'v31score') and cve.v31score:
                score = float(cve.v31score)
                severity = cve.v31severity or ""
                vector = getattr(cve, 'v31vector', '') or ''
            elif hasattr(cve, 'v30score') and cve.v30score:
                score = float(cve.v30score)
                severity = cve.v30severity or ""
            elif hasattr(cve, 'v20score') and cve.v20score:
                score = float(cve.v20score)
                severity = cve.v20severity or ""

            # CWE（新版 nvdlib 返回列表，元素是 CVE 对象或 dict，取第一个的 value）
            cwe_id = ""
            if hasattr(cve, 'cwe') and cve.cwe:
                if isinstance(cve.cwe, list) and cve.cwe:
                    first = cve.cwe[0]
                    if isinstance(first, dict):
                        cwe_id = first.get('value', '')
                    else:
                        cwe_id = getattr(first, 'value', '') or str(first)
                else:
                    cwe_id = str(cve.cwe)

            # 描述
            description = ""
            if hasattr(cve, 'descriptions') and cve.descriptions:
                for desc in cve.descriptions:
                    if desc.lang == 'en':
                        description = desc.value[:300]
                        break

            if score > 0:
                return {
                    "cvss_score": round(score, 1),
                    "severity": severity,
                    "vector": vector,
                    "description": description,
                    "cwe_id": cwe_id,
                    "source": "NVD"
                }
    except Exception:
        _record_error("nvd")

    return {"cvss_score": 0.0, "severity": "", "vector": "", "description": "", "cwe_id": "", "source": "NVD"}


# ==========================================
# 3. GitHub Advisory 查询（精确 CVSS + 修复版本）
# ==========================================

def query_github(ghsa_id: str) -> dict:
    """
    从 GitHub Advisory 查询漏洞详情。
    返回: {cvss_score, severity, fixed_version, cwe_id, summary}
    同 GHSA 结果缓存 1 小时（见 _CACHE_TTL_SECONDS）。
    """
    _key = ("gh", ghsa_id)
    _hit = _cache_get(_key)
    if _hit is not None:
        return _hit
    result = _query_github_uncached(ghsa_id)
    _cache_set(_key, result)
    return result


def _query_github_uncached(ghsa_id: str) -> dict:
    try:
        url = f"{config.GITHUB_ADVISORY_API}/{ghsa_id}"
        headers = {"Accept": "application/vnd.github+json"}
        if config.GITHUB_TOKEN:
            headers["Authorization"] = f"Bearer {config.GITHUB_TOKEN}"

        with warnings.catch_warnings():
            # 本机 GitHub 加速工具（Steam++ 等）会以自签证书转发流量，
            # 按 .env 里的 GITHUB_VERIFY_SSL 配置决定是否校验证书
            if not config.GITHUB_VERIFY_SSL:
                warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)
            resp = requests.get(url, headers=headers, timeout=config.GITHUB_TIMEOUT,
                                verify=config.GITHUB_VERIFY_SSL)
        if resp.status_code != 200:
            return {"cvss_score": 0.0, "severity": "", "fixed_version": "未知", "cwe_id": "", "summary": "", "source": "GitHub"}

        data = resp.json()

        # CVSS 分数
        cvss = data.get("cvss", {})
        score = 0.0
        severity = ""
        if cvss and cvss.get("score"):
            score = float(cvss["score"])
            severity = cvss.get("severity", "")

        # 文字降级估算
        if score == 0.0:
            sev_str = data.get("severity", "").upper()
            score = severity_str_to_score(sev_str)
            severity = sev_str

        # 修复版本
        fixed_version = "未知"
        for vuln_item in data.get("vulnerabilities", []):
            for pkg in vuln_item.get("patched_versions", []):
                if pkg.get("identifier"):
                    fixed_version = pkg["identifier"]
                    break
            if fixed_version != "未知":
                break

        # CWE
        cwes = data.get("cwes", [])
        cwe_id = cwes[0].get("cwe_id", "") if cwes else ""

        # 摘要
        summary = data.get("summary", "") or data.get("description", "")

        return {
            "cvss_score": round(score, 1) if score > 0 else 0.0,
            "severity": severity,
            "fixed_version": fixed_version,
            "cwe_id": cwe_id,
            "summary": (summary or "")[:300],
            "source": "GitHub"
        }
    except Exception:
        _record_error("github")
        return {"cvss_score": 0.0, "severity": "", "fixed_version": "未知", "cwe_id": "", "summary": "", "source": "GitHub"}


# ==========================================
# 4. EPSS 查询（利用预测）
# ==========================================

def query_epss(cve_id: str) -> dict:
    """
    查询 FIRST EPSS（漏洞利用预测评分系统）。
    EPSS 分数 = 该漏洞未来 30 天内被利用的概率（0~1）。
    同 CVE 结果缓存 1 小时（见 _CACHE_TTL_SECONDS）。
    """
    _key = ("epss", cve_id)
    _hit = _cache_get(_key)
    if _hit is not None:
        return _hit
    result = _query_epss_uncached(cve_id)
    _cache_set(_key, result)
    return result


def _query_epss_uncached(cve_id: str) -> dict:
    try:
        epss_url = f"{config.EPSS_API}?cve={cve_id}"
        resp = requests.get(epss_url, timeout=config.EPSS_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            items = data.get("data", [])
            if items:
                epss_score = float(items[0].get("epss", "0"))
                percentile = float(items[0].get("percentile", "0"))
                return {
                    "epss_score": round(epss_score, 4),
                    "percentile": round(percentile, 1),
                    "is_actively_exploited": epss_score > config.EPSS_ALERT
                }
    except Exception:
        _record_error("epss")
    return {"epss_score": 0.0, "percentile": 0.0, "is_actively_exploited": False}


# ==========================================
# 5. 置信度评级（★ 权威权重方案 v3.1）
# ==========================================
