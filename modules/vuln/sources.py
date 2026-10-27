# -*- coding: utf-8 -*-
"""漏洞研判 · 数据源查询层：OSV / NVD / GitHub Advisory / EPSS。

每个查询函数都带 1 小时内存缓存，避免重复调外部 API。
"""
import os
import sys
import time
import threading
import warnings

import requests
import urllib3

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config import config
from modules.vuln.common import (_cache_get, _cache_set, _notify, _record_error,
                                 query_errors, cvss_to_risk_level,
                                 severity_str_to_score, nvd_url, github_advisory_url)


def _call_with_timeout(fn, timeout: float, *args, **kwargs):
    """在守护线程里执行 fn，超过 timeout 秒就放弃等待。

    为什么需要它：nvdlib.searchCVE() **不接受 timeout 参数**，
    config.NVD_TIMEOUT 对它完全无效。NVD 服务端慢或网络抖动时，
    这个调用会一直挂着 —— 界面进度条停在原地，看起来就是「卡死」。

    返回 (结果, 是否超时)。超时返回 (None, True)，结果异常返回 (None, False)。
    超时后那个线程仍在后台跑（daemon，不阻塞进程退出），但我们不再等它。
    """
    box = {"value": None, "error": None}

    def _worker():
        try:
            box["value"] = fn(*args, **kwargs)
        except BaseException as exc:      # 捕获一切，避免线程静默死掉
            box["error"] = exc

    th = threading.Thread(target=_worker, daemon=True)
    th.start()
    th.join(timeout)
    if th.is_alive():
        return None, True
    if box["error"] is not None:
        raise box["error"]
    return box["value"], False


class _Breaker:
    """连续失败熔断器：某个外部源连续失败若干次后，冷却期内直接短路。

    为什么需要：NVD / EPSS 只要有一家不可用，每条漏洞都要白等一个完整超时
    （NVD 10 秒、EPSS 8 秒）。一个包 8 条就是 60-80 秒，界面看起来又是「卡死」。
    熔断后只损失前几次的超时，其余立刻跳过，并在 query_errors 里如实记录，
    界面据此提示「本次扫描有多少次查询失败」—— 不静默吞掉。
    """

    def __init__(self, name: str, threshold: int, cooldown: float):
        self.name = name
        self.threshold = threshold
        self.cooldown = cooldown
        self.fails = 0
        self.open_until = 0.0

    def is_open(self) -> bool:
        return time.time() < self.open_until

    def ok(self) -> None:
        self.fails = 0

    def fail(self) -> None:
        self.fails += 1
        if self.fails >= self.threshold:
            self.open_until = time.time() + self.cooldown

    def reset(self) -> None:
        self.fails = 0
        self.open_until = 0.0


_NVD_BREAKER = _Breaker("nvd", config.LOOKUP_BREAKER_THRESHOLD,
                        config.LOOKUP_BREAKER_COOLDOWN)
_EPSS_BREAKER = _Breaker("epss", config.LOOKUP_BREAKER_THRESHOLD,
                         config.LOOKUP_BREAKER_COOLDOWN)

_EMPTY_NVD = {"cvss_score": 0.0, "severity": "", "vector": "",
              "description": "", "cwe_id": "", "source": "NVD"}
_EMPTY_EPSS = {"epss_score": 0.0, "percentile": 0.0,
               "is_actively_exploited": False}

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
    # 熔断中：该源最近连续失败，直接短路，不再白等一个超时
    if _NVD_BREAKER.is_open():
        _record_error("nvd")
        return dict(_EMPTY_NVD)
    try:
        import nvdlib
        # 新版 nvdlib：传 delay 参数必须同时提供 API key
        # 有 key → 快速请求（0.7s 间隔，nvdlib 要求 delay>0.6）；无 key → 走 NVD 官方匿名限速（约 6s/次）
        kwargs = {"cveId": cve_id}
        if config.NVD_API_KEY:
            kwargs["key"] = config.NVD_API_KEY
            kwargs["delay"] = 0.7
        # nvdlib.searchCVE 不接受 timeout 参数 —— config.NVD_TIMEOUT 对它无效。
        # NVD 慢或网络抖动时该调用会长时间挂起，界面就「卡在 95% 不动」。
        # 这里用守护线程兜底：超过 NVD_TIMEOUT 秒就放弃等待，当作没查到，
        # 该 CVE 仍会保留在结果里（用 OSV 的分数），只是少了 NVD 的交叉验证。
        results, timed_out = _call_with_timeout(
            nvdlib.searchCVE, config.NVD_TIMEOUT, **kwargs)
        if timed_out:
            _NVD_BREAKER.fail()
            _record_error("nvd")
            return {"cvss_score": 0.0, "severity": "", "vector": "",
                    "description": "", "cwe_id": "", "source": "NVD",
                    "timed_out": True}
        _NVD_BREAKER.ok()
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
        _NVD_BREAKER.fail()
        _record_error("nvd")

    return dict(_EMPTY_NVD)


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
    # 熔断中：EPSS 服务最近连续失败，直接短路（EPSS 只是补充信息，缺了不影响判定）
    if _EPSS_BREAKER.is_open():
        _record_error("epss")
        return dict(_EMPTY_EPSS)
    try:
        epss_url = f"{config.EPSS_API}?cve={cve_id}"
        resp = requests.get(epss_url, timeout=config.EPSS_TIMEOUT)
        if resp.status_code == 200:
            _EPSS_BREAKER.ok()
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
        _EPSS_BREAKER.fail()
        _record_error("epss")
    return dict(_EMPTY_EPSS)


# ==========================================
# 5. 置信度评级（★ 权威权重方案 v3.1）
# ==========================================
