# -*- coding: utf-8 -*-
"""漏洞研判 · 版本解析辅助。

从依赖声明里抽出「实际安装版本」，并判断声明的语义
（精确锁定 / 版本区间 / 约束条件），供置信度评级使用。
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config import config


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
