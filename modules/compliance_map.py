# -*- coding: utf-8 -*-
"""合规对照映射框架：把风险点按类别聚合，并对照 OWASP Agentic Skills Top 10。

【官方来源（必读）】
OWASP Agentic Skills Top 10 —— 条目名与编号取自此官方来源，逐条核对：
  · 官方项目站：https://owasp.org/projects/agentic-skills-top-10
  · 官方条目总表（Summary Table）：https://owasp.github.io/www-project-agentic-skills-top-10/
  · 官方白皮书：ast10-top10-whitepaper.pdf（同上站点 assets/publications/ 下）
官方原文明确：AST 为该标准自有编号 **AST01–AST10**，
**不要与 ASI（OWASP Agentic Security Initiative Top 10）或抽象语法树混淆**。

【🔴 口径边界（必读）】
1. 本项目把「技能风险点」按**本项目自有的威胁类别**聚合（沿用
   modules/skill_scanner.py / modules/combo_analysis.py 的 category，不另造一套）。
2. 「类别 → OWASP 条目」是**依据官方条目名的语义对照**，供对照展示用，
   **不是 OWASP 官方的认证映射**；界面会原样标注这一点。
3. MITRE ATLAS 的条目编号**本轮不填**（条目多、核实成本高），
   待官方核实后再补 `ATLAS_BY_CATEGORY`；未填前界面不展示 ATLAS 编号。
"""
from __future__ import annotations

# OWASP Agentic Skills Top 10 —— 官方条目（编号 + 官方英文名 + 中文意译）
# 来源：https://owasp.github.io/www-project-agentic-skills-top-10/（Summary Table）
OWASP_AST10 = {
    "AST01": ("Malicious Skills", "恶意技能"),
    "AST02": ("Supply Chain Compromise", "供应链投毒"),
    "AST03": ("Over-Privileged Skills", "过度权限"),
    "AST04": ("Insecure Metadata", "元数据不安全"),
    "AST05": ("Untrusted External Instructions", "外部不可信指令"),
    "AST06": ("Weak Isolation", "隔离薄弱"),
    "AST07": ("Update Drift", "更新漂移"),
    "AST08": ("Poor Scanning", "扫描不足"),
    "AST09": ("No Governance", "缺乏治理"),
    "AST10": ("Cross-Platform Reuse", "跨平台复用"),
}

# 本项目威胁类别 → OWASP 条目（语义对照，非官方认证映射）
OWASP_BY_CATEGORY = {
    "提示注入":     ["AST05"],
    "凭证窃取":     ["AST03"],
    "危险命令":     ["AST03"],
    "供应链风险":   ["AST02"],
    "数据外发":     ["AST01"],
    "混淆载荷":     ["AST04", "AST08"],
    "持久化污染":   ["AST01"],
    "隐藏字符注入": ["AST04"],
}

# MITRE ATLAS 对照：本轮留空，待官方核实后回填
ATLAS_BY_CATEGORY: dict = {}

_ETL_NOTE = "类别 → OWASP 条目为依据官方条目名的语义对照，非 OWASP 官方认证映射"


def map_findings(findings: list) -> dict:
    """按类别聚合风险点，返回 {类别: [finding, ...]}。"""
    groups: dict = {}
    for f in findings or []:
        cat = f.get("category") or f.get("threat") or "其他"
        groups.setdefault(cat, []).append(f)
    return groups


def owasp_for(category: str) -> list:
    """返回该类别对照的 OWASP 条目编号列表（未知类别返回空列表）。"""
    return list(OWASP_BY_CATEGORY.get(category or "其他", []))


def atlas_for(category: str) -> list:
    """返回该类别对照的 MITRE ATLAS 技术编号（当前尚未核实，返回空）。"""
    return list(ATLAS_BY_CATEGORY.get(category or "其他", []))


def owasp_label(codes: list) -> str:
    """把编号列表渲染成「AST03 · Over-Privileged Skills（过度权限）」这类可读串。"""
    out = []
    for c in codes or []:
        name, cn = OWASP_AST10.get(c, ("", ""))
        out.append(f"{c} · {name}（{cn}）" if name else c)
    return "；".join(out)


def to_standard(finding: dict) -> dict:
    """把单个风险点对照到 OWASP Agentic Skills Top 10（MITRE ATLAS 暂空）。"""
    cat = finding.get("category") or "其他"
    codes = owasp_for(cat)
    return {"category": cat, "owasp": codes, "owasp_label": owasp_label(codes),
            "atlas": atlas_for(cat), "note": _ETL_NOTE}


def summary(findings: list) -> dict:
    """合规对照摘要：{类别: 命中数}，供界面/报告使用。"""
    groups = map_findings(findings)
    return {cat: len(items) for cat, items in groups.items()}


def standard_refs() -> dict:
    """对外展示的「标准引用」元信息（含官方来源，供界面注明）。"""
    return {
        "owasp": "OWASP Agentic Skills Top 10（AST01–AST10）",
        "owasp_source": "https://owasp.github.io/www-project-agentic-skills-top-10/",
        "mitre": "",   # MITRE ATLAS 条目编号待官方核实后回填
        "note": _ETL_NOTE,
    }