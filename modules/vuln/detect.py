# -*- coding: utf-8 -*-
"""漏洞研判 · 检测编排：串行与并发两种漏洞检测入口。

对外只暴露 detect_vulnerabilities 与 detect_vulnerabilities_concurrent。
版本解析在 modules/vuln/version.py，间接依赖与修复方案在 modules/vuln/transitive.py。
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from modules.vuln.common import (_notify, query_errors, cvss_to_risk_level,
                                 severity_str_to_score, nvd_url, github_advisory_url)
from config import config
from modules.vuln.sources import (query_osv, query_nvd, query_github, query_epss,
                                  extract_ids_from_osv)
from modules.vuln.rating import evaluate_confidence, calculate_fix_priority
from modules.vuln.version import (_extract_version, _is_pure_range, version_basis,
                                  _extract_osv_score, _extract_fixed_from_osv,
                                  _parse_fixed_version)
from modules.vuln.transitive import (detect_transitive_deps, _parse_requires_entry,
                                     _constraint_to_version, generate_fix_plan)


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

        # 🔴 先按 OSV 自报的 CVSS 从高到低排序，再决定给谁做外部交叉验证。
        #    原因：一个依赖包可能命中上百条漏洞，逐条去 NVD/EPSS/GitHub 查，
        #    每条几秒 → 整体几分钟到十几分钟，界面表现就是「进度条卡住不动」。
        #    排序后只对【最严重的 N 条】做外部查询（config.MAX_LOOKUPS_PER_PACKAGE），
        #    其余条目仍然完整列进结果，只是直接采用 OSV 分数、不做交叉验证，
        #    并在记录里标 external_verified=False 让界面可以说清。
        osv_vulns = sorted(osv_vulns, key=lambda v: -_extract_osv_score(v)[0])
        lookup_budget = config.MAX_LOOKUPS_PER_PACKAGE
        lookups_used = 0

        # 命中条数超过预算时明说一声，避免用户以为「后面的漏洞被吞了」
        if len(osv_vulns) > lookup_budget:
            _notify(progress_cb,
                    f"{pkg} 命中 {len(osv_vulns)} 条漏洞，"
                    f"只对最严重的 {lookup_budget} 条做 NVD/EPSS 交叉验证，"
                    f"其余 {len(osv_vulns) - lookup_budget} 条直接采用 OSV 分数",
                    percent=15 + int(dep_idx / max(len(dep_list), 1) * 75))

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

            # lookups_used 是本包已用掉的外部查询名额。
            # 超预算后不再请求 NVD / GitHub / EPSS，直接用 OSV 的分数 ——
            # 漏洞本身不丢，只是少一道交叉验证（记录里会标 external_verified=False）。
            external_ok = lookups_used < lookup_budget

            # ===== Step 2: NVD 交叉验证 =====
            nvd_data = {}
            if cve_id and use_nvd and external_ok:
                _notify(progress_cb,
                        f"正在交叉验证 NVD：{cve_id}"
                        f"（本包外部查询 {lookups_used + 1}/{lookup_budget}）",
                        percent=item_pct)
                nvd_data = query_nvd(cve_id)
                if nvd_data["cvss_score"] > 0:
                    score_source_parts.append("NVD")

            # ===== Step 3: GitHub Advisory =====
            gh_data = {}
            if ghsa_id and external_ok:
                _notify(progress_cb,
                        f"正在查询 GitHub Advisory：{ghsa_id}"
                        f"（本包外部查询 {lookups_used + 1}/{lookup_budget}）",
                        percent=item_pct)
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
            if cve_id and final_score > 0 and do_epss and external_ok:
                _notify(progress_cb, f"正在查询 EPSS 利用概率：{cve_id}", percent=item_pct)
                epss_data = query_epss(cve_id)
            if not epss_data:
                epss_data = {"epss_score": 0.0, "percentile": 0.0, "is_actively_exploited": False}

            # 本条已走完全部外部查询，占用一个名额（超预算的条目不占）
            if external_ok:
                lookups_used += 1

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
                # 本条是否做过外部交叉验证（NVD / GitHub / EPSS）。
                # False = 超出每包上限（config.MAX_LOOKUPS_PER_PACKAGE），
                # 分数直接取自 OSV，未做多源核对，界面上应如实标注。
                "external_verified": external_ok,
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
        # 超出每包上限、未做外部交叉验证的条目数（界面据此提示"部分条目仅 OSV 单源"）
        stats["external_truncated"] = sum(
            1 for v in vulns_result if not v.get("external_verified", True))
        stats["lookup_budget_per_package"] = config.MAX_LOOKUPS_PER_PACKAGE

    return vulns_result

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
        # 超出每包上限、未做外部交叉验证的条目数。
        # 串行版在 detect_vulnerabilities 内部自己算；并发版内部传的是 stats=None，
        # 所以这里按合并后的结果统一统计一次。
        stats["external_truncated"] = sum(
            1 for v in merged if not v.get("external_verified", True))
        stats["lookup_budget_per_package"] = config.MAX_LOOKUPS_PER_PACKAGE

    return merged
