# -*- coding: utf-8 -*-
"""漏洞研判 · 检测编排层：串行/并发漏洞检测与间接依赖推断。

对外只暴露 detect_vulnerabilities 与 detect_vulnerabilities_concurrent。
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
from modules.vuln.rating import evaluate_confidence, calculate_fix_priority

def detect_vulnerabilities(dep_list: list[dict], parser_module=None,
                           use_nvd: bool = True, do_epss: bool = True,
                           progress_cb=None, stats: dict | None = None) -> list[dict]:
    """
    四源融合综合漏洞检测 + 置信度评级 + EPSS + 修复优先级。

    流程:
      1. OSV 获取漏洞列表
      2. OSV severity 数组提取精确 CVSS
      3. NVD 补全 + 交叉验证
      4. GitHub Advisory 补全
      5. EPSS 利用预测
      6. 置信度评级
      7. 修复优先级排序结果

    参数:
      dep_list: [{"package": "...", "version": "...", "ecosystem": "PyPI"}, ...]
      parser_module: 解析器模块（用于版本号提取）

    返回:
      [{
        "cve_id": "CVE-2021-35042",
        "package": "django",
        "version": "3.2.1",
        "ecosystem": "PyPI",
        "severity": "严重",
        "cvss_score": 9.8,
        "score_source": "NVD+OSV+GitHub",
        "score_type": "exact",
        "confidence": {"level": "高", "badge": "🟢", "detail": "四源交叉验证一致"},
        "fix_priority": {"priority": 1, "label": "🔴 立即修复", "urgency": "24小时内"},
        "epss_score": 0.32,
        "epss_percentile": 0.95,
        "fixed_version": "3.2.2",
        "evidence_links": ["https://nvd.nist.gov/vuln/detail/CVE-2021-35042", ...],
        "summary": "...",
        "cwe_id": "CWE-89",
        "vuln_source": "OSV+NVD+GitHub"
      }, ...]
    """
    vulns_result = []
    seen_keys = set()
    skipped_deps: list[dict] = []   # 被跳过的依赖，不再静默丢弃，交由界面披露

    for dep_idx, dep in enumerate(dep_list):
        pkg = dep["package"]
        ver_with_op = dep["version"]
        ecosystem = dep.get("ecosystem", "PyPI")
        is_transitive = dep.get("is_transitive", False)
        basis = version_basis(ver_with_op)

        # 版本号提取
        clean_ver = _extract_version(ver_with_op, parser_module)
        if not clean_ver:
            skipped_deps.append({"package": pkg, "version": ver_with_op,
                                 "reason": "未声明版本号，无法定位"})
            continue

        # 仅跳过「无下界」的纯范围约束（如 <3.0）
        if _is_pure_range(ver_with_op):
            skipped_deps.append({"package": pkg, "version": ver_with_op,
                                 "reason": "仅声明上界（如 <3.0），实际版本无法确定"})
            continue

        # 查询 OSV
        _notify(progress_cb, f"正在查询 OSV 漏洞库：{pkg}=={clean_ver}"
                           f"（第 {dep_idx + 1}/{len(dep_list)} 个依赖）",
                percent=15 + int(dep_idx / len(dep_list) * 75))
        osv_ecosystem = "PyPI" if ecosystem == "PyPI" else ecosystem
        osv_vulns = query_osv(pkg, clean_ver, osv_ecosystem)

        if not osv_vulns:
            continue

        # 依赖内进度：一个依赖可能查出几十条漏洞，逐条 NVD/GitHub/EPSS 查询很耗时，
        # 百分比在依赖粒度基础上按漏洞条目再细分，避免进度条长时间卡住不动
        dep_span = 75 / max(len(dep_list), 1)
        dep_base = 15 + int(dep_idx / max(len(dep_list), 1) * 75)

        for item_idx, item in enumerate(osv_vulns):
            item_pct = min(90, dep_base + int(item_idx / max(len(osv_vulns), 1) * dep_span))
            cve_id, ghsa_id = extract_ids_from_osv(item)
            display_id = cve_id or ghsa_id or item.get("id", "无编号")

            # 去重
            dedup_key = (display_id, pkg, clean_ver)
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            # ===== Step 1: OSV 精确分数 =====
            osv_score, osv_severity = _extract_osv_score(item)
            score_source_parts = ["OSV"] if osv_score > 0 else []
            has_exact = (osv_score > 0)

            # ===== Step 2: NVD 交叉验证 =====
            nvd_data = {}
            if cve_id and use_nvd:
                _notify(progress_cb, f"正在交叉验证 NVD：{cve_id}", percent=item_pct)
                nvd_data = query_nvd(cve_id)
                if nvd_data["cvss_score"] > 0:
                    score_source_parts.append("NVD")

            # ===== Step 3: GitHub Advisory =====
            gh_data = {}
            if ghsa_id:
                _notify(progress_cb, f"正在查询 GitHub Advisory：{ghsa_id}", percent=item_pct)
                gh_data = query_github(ghsa_id)
                if gh_data["cvss_score"] > 0:
                    score_source_parts.append("GitHub")

            # ===== Step 4: 确定最优 CVSS 分数 =====
            # 优先级：NVD（官方权威）> GitHub > OSV > 估算
            final_score = osv_score
            score_type = "exact" if osv_score > 0 else "estimated"

            if nvd_data.get("cvss_score", 0) > 0:
                final_score = nvd_data["cvss_score"]
                score_type = "exact"
            elif gh_data.get("cvss_score", 0) > 0 and final_score == 0:
                final_score = gh_data["cvss_score"]
                score_type = "exact"

            # 分数仍为0，估算兜底
            if final_score == 0.0:
                db_spec = item.get("database_specific", {})
                sev_str = db_spec.get("severity", "").upper()
                if sev_str:
                    final_score = severity_str_to_score(sev_str)
                score_type = "estimated"

            # ===== Step 5: 源间分歧检测（v3.1 权威权重方案）=====
            # 给出评分的来源之间最大分差 ≥ 2 → 视为源间分歧
            # 分歧时分数采信 NVD（Step 4 已按 NVD 优先），置信度降一档
            voting_count = sum(1 for s in [osv_score, nvd_data.get("cvss_score", 0),
                                           gh_data.get("cvss_score", 0)] if s > 0)
            active_scores = [s for s in [osv_score, nvd_data.get("cvss_score", 0),
                                         gh_data.get("cvss_score", 0)] if s > 0]
            divergent = False
            if len(active_scores) >= 2:
                divergent = (max(active_scores) - min(active_scores) >= 2.0)

            score_source_str = "+".join(score_source_parts) if score_source_parts else "OSV(估算)"

            # ===== Step 6: 置信度评级（权威权重决策表）=====
            confidence = evaluate_confidence(osv_score, nvd_data.get("cvss_score", 0),
                                             gh_data.get("cvss_score", 0), score_type, divergent)

            # ===== Step 7: 修复版本提取 =====
            # 传入当前版本，让 OSV 多分支数据能选对所属分支（否则会给出降级建议）
            fixed_version = gh_data.get("fixed_version", "未知") if gh_data else "未知"
            if fixed_version == "未知":
                fixed_version = _extract_fixed_from_osv(item, clean_ver)

            # ===== Step 8: 风险等级 =====
            level = cvss_to_risk_level(final_score)

            # ===== Step 9: EPSS =====
            epss_data = {}
            if cve_id and final_score > 0 and do_epss:
                _notify(progress_cb, f"正在查询 EPSS 利用概率：{cve_id}", percent=item_pct)
                epss_data = query_epss(cve_id)
            if not epss_data:
                epss_data = {"epss_score": 0.0, "percentile": 0.0, "is_actively_exploited": False}

            # ===== Step 10: 修复优先级 =====
            fix_priority = calculate_fix_priority(final_score, epss_data.get("epss_score", 0), confidence["level"])

            # ===== Step 11: 证据链接 =====
            evidence_links = []
            if cve_id:
                evidence_links.append({"label": "NVD 官方页面", "url": nvd_url(cve_id)})
            if ghsa_id:
                evidence_links.append({"label": "GitHub Advisory", "url": github_advisory_url(ghsa_id)})

            # ===== Step 12: 汇总描述 =====
            summary = ""
            if nvd_data.get("description"):
                summary = nvd_data["description"]
            elif gh_data.get("summary"):
                summary = gh_data["summary"]
            else:
                summary = item.get("summary", "") or item.get("details", "")

            vuln_record = {
                # 基础信息
                "cve_id": display_id,
                "package": pkg,
                "version": clean_ver,
                "ecosystem": ecosystem,
                # 版本依据：exact=精确锁定 / lower_bound=按下限推断（结论偏保守）
                "version_basis": basis,
                # ★ 依赖层级（v3.1 新增）
                "is_transitive": is_transitive,
                "transitive_from": dep.get("transitive_from", ""),

                # 评分
                "severity": level,
                "cvss_score": round(final_score, 1),
                "score_source": score_source_str,
                "score_type": score_type,

                # ★ 新增：置信度
                "confidence": confidence,

                # ★ 新增：EPSS
                "epss_score": epss_data.get("epss_score", 0.0),
                "epss_percentile": epss_data.get("percentile", 0.0),
                "is_actively_exploited": epss_data.get("is_actively_exploited", False),

                # ★ 新增：修复优先级
                "fix_priority": fix_priority,

                # 修复信息
                "fixed_version": fixed_version,

                # ★ 新增：证据链接
                "evidence_links": evidence_links,

                # 备注
                "summary": (summary or "")[:300],
                "cwe_id": nvd_data.get("cwe_id", "") or gh_data.get("cwe_id", ""),
                "vuln_source": score_source_str or "OSV",
                "divergent": divergent,
            }

            vulns_result.append(vuln_record)

    # 按修复优先级排序
    _notify(progress_cb, "正在计算置信度评级与修复优先级…", percent=92)
    vulns_result.sort(key=lambda v: (
        v["fix_priority"].get("priority", 5),
        -v["cvss_score"]
    ))

    if stats is not None:
        stats["skipped"] = skipped_deps
        stats["skipped_count"] = len(skipped_deps)
        stats["scanned_count"] = len(dep_list) - len(skipped_deps)
        stats["lower_bound_count"] = sum(
            1 for v in vulns_result if v.get("version_basis") == "lower_bound")
        # 查询失败次数：为 0 才说明"零漏洞"是可信的
        stats["query_errors"] = query_errors()

    return vulns_result


# ==========================================
# 并发扫描（2026-10-15 新增）
# ==========================================
def detect_vulnerabilities_concurrent(dep_list: list[dict], parser_module=None,
                                       use_nvd: bool = True, do_epss: bool = True,
                                       progress_cb=None, stats: dict | None = None,
                                       max_workers: int = 8) -> list[dict]:
    """
    并发版漏洞检测：在依赖粒度上开线程池，加速最耗时的网络 IO。

    【为什么要并发】
    实测（2026-10-05，11 个真实 GitHub 项目串行扫描）：耗时 1035 秒。
    根因是网络请求串行——OSV → NVD → GitHub → EPSS 四源查询，
    绝大多数时间在等网络响应，CPU 空闲。
    而单次查询失败（限流/断网）在日志中反复出现，重试进一步拉长耗时。

    【为什么在依赖粒度并发、而不是在漏洞条目粒度】
    依赖粒度并发实现简单、线程数可控（max_workers），
    且单线程内部的逻辑（去重、评分、评级）完全复用串行版本，
    保证结果与串行版一致 —— 这一点很重要：并发只改变速度，不改变结论。
    漏洞条目粒度并发需要在共享的 seen_keys / skipped_deps 上加锁，
    复杂度与风险都更高，实测依赖粒度已足够把 1035s 压到百秒级。

    【线程安全】
    以下共享状态需要注意：
    - seen_keys / skipped_deps：只在单线程内使用（每个依赖自己的局部集），
      但最终结果在主线程按顺序合并，保证输出顺序稳定（可复现）
    - _api_cache：模块级字典。CPython 字典操作在 GIL 下是原子的，
      可能重复请求同一 key（浪费一次），但不会数据损坏；
      query_osv 等函数内部已有"失败不缓存"保护，不会污染缓存
    - _record_error：计数 += 1 在 GIL 下基本原子，误差可忽略，
      且该计数仅用于界面披露"有数据源不可用"，不需要精确

    【降级】
    任一线程内抛异常都被捕获，该依赖标记为跳过并记录原因，
    不会因单个依赖失败而中断整体扫描。
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    if not dep_list:
        return []

    total = len(dep_list)
    results_by_idx = {}
    skipped_all: list = []
    done_count = 0
    lock = __import__("threading").Lock()

    def _scan_one(idx_dep):
        """扫描单个依赖。返回 (idx, vulns, skipped) 或抛异常由上层捕获。"""
        idx, dep = idx_dep
        vulns = detect_vulnerabilities([dep], parser_module,
                                       use_nvd=use_nvd, do_epss=do_epss,
                                       progress_cb=None, stats=None)
        return idx, vulns, dep

    # 索引化，便于结果按原顺序合并（保证输出可复现）
    indexed = list(enumerate(dep_list))

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(_scan_one, item): item[0] for item in indexed}

            for fut in as_completed(futures):
                idx = futures[fut]
                try:
                    idx, vulns, dep = fut.result()
                    results_by_idx[idx] = vulns
                except Exception as e:
                    # 单个依赖失败不影响整体
                    results_by_idx[idx] = []
                    skipped_all.append({"package": dep.get("package", "?"),
                                        "version": dep.get("version", ""),
                                        "reason": f"并发扫描失败：{type(e).__name__}"})
                finally:
                    with lock:
                        done_count += 1
                        pct = 15 + int(done_count / total * 75)
                    _notify(progress_cb,
                            f"并发扫描进度：{done_count}/{total} 个依赖"
                            f"（线程数 {max_workers}）", percent=pct)
    except Exception as e:
        print(f"[并发扫描] 线程池异常（{e}），回退到串行模式")
        return detect_vulnerabilities(dep_list, parser_module,
                                      use_nvd=use_nvd, do_epss=do_epss,
                                      progress_cb=progress_cb, stats=stats)

    # 按原索引顺序合并，保证输出顺序稳定可复现
    merged: list = []
    for i in range(total):
        merged.extend(results_by_idx.get(i, []))

    if stats is not None:
        stats["concurrent_workers"] = max_workers
        stats["dep_count"] = total
        stats["skipped_deps"] = skipped_all
        # 查询失败统计从全局取（四源共享的模块级计数器）
        stats["query_errors"] = query_errors()

    return merged


# ==========================================
# 辅助函数
# ==========================================

def _extract_version(ver_str: str, parser_module) -> str | None:
    """从版本约束字符串提取清洁版本号"""
    if not ver_str or ver_str == "未限定版本":
        return None
    if parser_module:
        try:
            return parser_module.extract_clean_version(ver_str)
        except Exception:
            pass
    # 兜底：尝试直接匹配
    import re
    import packaging.version
    match = re.search(r'(\d+\.\d+(?:\.\d+)?)', ver_str)
    if match:
        try:
            packaging.version.Version(match.group(1))
            return match.group(1)
        except Exception:
            pass
    return None


def _is_pure_range(ver_str: str) -> bool:
    """
    判断是否是「只有上界、没有下界」的纯范围约束（如 <3.0 / <=3.0 / !=2.0）。

    只有这类约束才真正无法定位实际安装版本（可能是 0.1 也可能是 2.9），
    检测没有意义，应跳过。

    【修复说明】原实现是 `has_range and not has_exact`，会把
      requests>=2.20.0   → has_range=True, has_exact=False → 判为纯范围 → 跳过
      urllib3>=1.26.5    → 同上                                        → 跳过
    也就是说**所有用 >= 声明的依赖都不检测**，属于静默漏检。
    而 >=X、>=X,<Y、~=X、==X 都给出了明确下界，可以按下界做保守检测。
    """
    if not ver_str:
        return False
    s = str(ver_str).replace(" ", "")
    # == 精确 / ~= 兼容 / >= 或 > 下限 —— 都提供了可定位的下界
    has_lower_bound = ("==" in s) or ("~=" in s) or (">=" in s) or (">" in s)
    return not has_lower_bound


def version_basis(ver_str: str) -> str:
    """
    判定版本依据，用于向用户如实披露结论的可靠程度：
      - "exact"       : == 精确锁定，结论最可靠
      - "lower_bound" : >= / ~= / 范围下限，实际安装版本可能更高，结论偏保守
                        （即可能报出已在新版本中修复的漏洞）
    """
    if not ver_str:
        return "unknown"
    s = str(ver_str).replace(" ", "")
    if "==" in s:
        return "exact"
    if (">=" in s) or ("~=" in s) or (">" in s):
        return "lower_bound"
    # 裸版本号：npm package.json 解析时已剥离 ^ ~，得到 "4.17.15" 这类纯版本号，
    # 视为精确锁定；解析失败（"未限定版本"、"<1.20"）才是真正无法定位
    try:
        from packaging.version import Version as _V
        _V(s)
        return "exact"
    except Exception:
        return "unknown"


def _extract_osv_score(item: dict) -> tuple:
    """从 OSV 返回项提取 CVSS 分数"""
    for s in item.get("severity", []):
        if s.get("type") in ("CVSS_V3", "CVSS_V4", "CVSS_V2"):
            try:
                score = s.get("score")
                if score is not None and float(score) > 0:
                    return float(score), s.get("type", "")
            except (ValueError, TypeError):
                pass
    return 0.0, ""


def _iter_osv_ranges(item: dict):
    """
    遍历 OSV 条目里所有 (introduced, fixed) 受影响区间。

    OSV 的 affected 数组按**发布分支**拆分：同一个 CVE 在不同的维护分支上
    各自有独立的修复版本。例如 django CVE-2019-14234 实际有三条：
        1.11a1 → fixed 1.11.23
        2.1a1  → fixed 2.1.11
        2.2a1  → fixed 2.2.4
    原实现取「第一个」fixed，导致 django 2.2.0 被建议升级到 1.11.23（实为降级）。
    """
    sources = []
    if item.get("ranges"):
        sources.append(item["ranges"])
    for aff in item.get("affected", []):
        if aff.get("ranges"):
            sources.append(aff["ranges"])

    for ranges in sources:
        for rng in ranges:
            introduced = "0"
            for event in rng.get("events", []):
                if "introduced" in event:
                    introduced = event["introduced"]
                if "fixed" in event:
                    yield introduced, event["fixed"]


def _extract_fixed_from_osv(item: dict, current_version: str | None = None) -> str:
    """
    从 OSV 返回项提取**适用于当前版本**的修复版本。

    current_version 为空时（无法定位实际版本）：取所有分支中最高的修复版本，
    升级到该版本在所有分支上都是安全的。
    """
    from packaging.version import Version as _V

    def _v(s):
        try:
            return _V(str(s))
        except Exception:
            return None

    pairs = list(_iter_osv_ranges(item))
    if not pairs:
        return "未知"

    cur = _v(current_version) if current_version else None

    if cur is not None:
        candidates = []
        for introduced, fixed in pairs:
            lo = _v(introduced)
            if lo is not None and cur < lo:
                continue          # 当前版本早于该分支引入点，不属于这条分支
            fx = _v(fixed)
            if fx is None or cur >= fx:
                continue          # 该分支已修复 / 版本无法比较，跳过
            candidates.append((fx, fixed))
        if candidates:
            # 取高于当前版本的最小修复版本 —— 最小必要升级，避免跨大版本跳跃
            return min(candidates, key=lambda t: t[0])[1]
        return "未知"

    best = None
    for _, fixed in pairs:
        fx = _v(fixed)
        if fx is None:
            continue
        if best is None or fx > best[0]:
            best = (fx, fixed)
    return best[1] if best else "未知"


# ==========================================
# 8. 间接依赖检测（一层推断，v3.1 新增）
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
# 9. 一键修复方案生成（v3.1 新增）
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


def _parse_fixed_version(fixed_str: str) -> str | None:
    """
    修复版本字符串 → 具体版本号。
    GitHub Advisory 的修复版本可能是约束形式：
      "<2.4.4"          → 2.4.4（低于该版本受影响）
      ">=2.0,<2.4.4"    → 2.4.4
      ">=3.2.2"         → 3.2.2
      "3.2.2"           → 3.2.2
    """
    import re as _re

    if fixed_str in ("未知", "", None):
        return None
    s = fixed_str.replace(" ", "")
    # "<X" → X 即修复版本
    m = _re.search(r"<([0-9][\w.]*)", s)
    if m:
        return m.group(1)
    # ">X" / ">=X" → X
    m = _re.search(r">=?([0-9][\w.]*)", s)
    if m:
        return m.group(1)
    # 纯版本号
    m = _re.match(r"^([0-9][\w.]*)$", s)
    if m:
        return m.group(1)
    return None
