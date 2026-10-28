# -*- coding: utf-8 -*-
"""技能风险标准化评分（0–100，越高越危险）。

【口径（唯一来源；改这里必须同步 docs/材料写作规格_数字与口径红线.md）】
  1. 每个「风险点」(finding) 按其严重度扣分：
       严重 40 / 高危 25 / 中危 12 / 低危 5
     （量纲与 combo_analysis / attack_chain 的 SEV_WEIGHT 同源：严重>高危>中危>低危）
  2. 聚合：同一规则(rule) 只计一次（取该规则下的最高严重度），避免同一规则在长文里
     刷屏把分数刷高；不同规则之间**累加**。
  3. 截断：累加结果取 100 封顶；无风险点则为 0。

score → 等级：>=70 严重 / >=40 高危 / >=15 中危 / >0 低危 / ==0 安全。
"""
from __future__ import annotations

SEV_PENALTY = {"严重": 40, "高危": 25, "中危": 12, "低危": 5}
_SEV_RANK = {"严重": 4, "高危": 3, "中危": 2, "低危": 1, "安全": 0}


def normalize_findings(findings: list) -> list:
    """按 rule 去重：同一规则取最高严重度。返回 [(rule, severity), ...]。"""
    best: dict = {}
    for f in findings or []:
        rule = f.get("rule") or f.get("category") or f.get("id") or "?"
        sev = f.get("severity", "低危")
        if rule not in best or _SEV_RANK.get(sev, 0) > _SEV_RANK.get(best[rule], 0):
            best[rule] = sev
    return [(r, s) for r, s in best.items()]


def skill_score(findings: list) -> dict:
    """计算单技能风险分。

    返回 {"score": 0-100, "level": str, "rules_hit": int, "items": [...]}。
    """
    items = normalize_findings(findings)
    total = sum(SEV_PENALTY.get(s, 0) for _, s in items)
    score = min(100, total)
    if score >= 70:
        level = "严重"
    elif score >= 40:
        level = "高危"
    elif score >= 15:
        level = "中危"
    elif score > 0:
        level = "低危"
    else:
        level = "安全"
    return {
        "score": score,
        "level": level,
        "rules_hit": len(items),
        "items": [{"rule": r, "severity": s, "penalty": SEV_PENALTY.get(s, 0)}
                  for r, s in items],
    }