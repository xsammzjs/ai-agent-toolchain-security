# -*- coding: utf-8 -*-
"""漏洞研判 · 评级层：置信度评级与修复优先级计算。

这是本项目在依赖侧最有价值的设计 —— 不是「多个库查一遍」，而是按权威性加权并处理源间分歧。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config import config

def evaluate_confidence(
    osv_score: float,
    nvd_score: float,
    gh_score: float,
    score_type: str,
    divergent: bool = False
) -> dict:
    """
    权威权重置信度评级（v3.1 大改，替代原交叉验证方案）。

    设计思想：三个漏洞库的权威性不同，不能平均对待。
      NVD    = 3 分（NIST 官方漏洞库，最权威）
      GitHub = 2 分（官方安全通告库）
      OSV    = 1 分（聚合库，收录广但权威性一般）

    【决策表】总分 = 各来源有评分则计权之和

      ┌──────────────┬─────────────────────────────┬────────┐
      │ 权重合计      │ 来源组合                     │ 置信度 │
      ├──────────────┼─────────────────────────────┼────────┤
      │ ≥ 4          │ NVD + GitHub/OSV 任一方      │ 高     │
      │ = 3 (仅NVD)  │ 仅 NVD                      │ 中     │
      │ ≤ 3 (无NVD)  │ 仅 GitHub/OSV（NVD 未确认）   │ 低     │
      │ = 0          │ 四源均无评分（估算分兜底）     │ 低     │
      └──────────────┴─────────────────────────────┴────────┘
      注：GitHub+OSV 双源 = 2+1 = 3 分，但缺少最权威的 NVD 确认，
      按"无 NVD 则降为低"处理（高/中置信度必须包含 NVD）。

    【分歧规则】给出评分的来源之间最大分差 ≥ 2 视为"源间分歧"，
    最终分数采信 NVD（官方权威），置信度在原评级基础上降一档，
    详情注明"源间分歧，已采信 NVD"。
    """
    weight_total = 0
    if nvd_score > 0:
        weight_total += 3
    if gh_score > 0:
        weight_total += 2
    if osv_score > 0:
        weight_total += 1

    if weight_total >= 4:
        level, badge, detail = "高", "🟢", "NVD官方库 + 第二数据源交叉验证（权威加权评级）"
    elif nvd_score > 0:
        # 仅 NVD（3 分），无第二数据源
        level, badge, detail = "中", "🟡", "仅 NVD 官方库确认（权威单源评级）"
    elif weight_total >= 1:
        level, badge, detail = "低", "🔴", "仅 GitHub/OSV 收录，NVD 未确认"
    else:
        level, badge, detail = "低", "⚪", "缺少精确评分，采用估算分"

    # 源间分歧：降一档 + 标注
    if divergent:
        down_map = {"高": ("中", "🟡"), "中": ("低", "🔴"), "低": ("低", "🔴")}
        level, badge = down_map[level]
        detail = f"源间分歧（分差≥2），已采信 NVD；{detail}"

    return {"level": level, "badge": badge, "detail": detail}


# ==========================================
# 6. 修复优先级评分（★ 核心新增）
# ==========================================

def calculate_fix_priority(cvss_score: float, epss_score: float, confidence_level: str) -> dict:
    """
    综合多个维度计算修复优先级。
    返回: {priority: 1-5, label: 说明, urgency: 紧急程度}
    """
    # 置信度权重
    conf_weight = {"高": 1.0, "中": 0.7, "低": 0.3}

    # 综合评分 = CVSS(60%) + EPSS(30%) + 置信度(10%)
    epss_normalized = min(epss_score * 10, 10)  # EPSS 0.1 → 1分, 0.5 → 5分
    composite = (
        cvss_score * 0.6 +
        epss_normalized * 0.3 +
        (conf_weight.get(confidence_level, 0.5) * 10) * 0.1
    )

    if composite >= 8.0:
        return {"priority": 1, "label": "🔴 立即修复", "urgency": "24小时内", "composite_score": round(composite, 1)}
    elif composite >= 6.0:
        return {"priority": 2, "label": "🟠 尽快修复", "urgency": "本周内", "composite_score": round(composite, 1)}
    elif composite >= 4.0:
        return {"priority": 3, "label": "🟡 计划修复", "urgency": "本迭代内", "composite_score": round(composite, 1)}
    elif composite >= 2.0:
        return {"priority": 4, "label": "🟢 关注即可", "urgency": "下次发布前", "composite_score": round(composite, 1)}
    else:
        return {"priority": 5, "label": "⚪ 低优先", "urgency": "择期处理", "composite_score": round(composite, 1)}


# ==========================================
# 7. 综合漏洞检测（重构版）
# ==========================================
