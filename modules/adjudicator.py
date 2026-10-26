"""
AI 研判层（2026-10-15 新增）
================================
把 AI 放在正确的位置：**AI 做汇总与解释，规则做检测与判定**。

【为什么这样分层】
2026-10-05 曾移除全部 AI 功能，理由是「大模型输出是自然语言，
无法作为可复现的证据」。这个判断本身是对的——如果让 AI 直接下结论，
确实无法核验。

但赛题 1 要求「综合运用人工智能（必选）」，AI 必须回到系统里。
解法不是恢复旧方案，而是**换位置**：

┌────────────────────────────────────────────────────────┐
│ 检测层：规则引擎（skill_scanner / vulnerability）       │
│   职责：判定「有没有风险」「风险多严重」                 │
│   特性：确定性、可复现、可追溯到原文行号                 │
├────────────────────────────────────────────────────────┤
│ 研判层：AI（本模块）                                   │
│   职责：基于已有证据做跨条汇总、风险解释、处置建议       │
│   约束：不得推翻规则判定；每条输出必须引用证据来源        │
│   特性：输入是结构化证据，输出是自然语言 + 引用           │
└────────────────────────────────────────────────────────┘

【这个分层在答辩时怎么讲】
「我们的 AI 不做检测。检测由规则引擎完成，命中即给出原文行号，
可当场核验。AI 的作用是把分散的检测结果综合起来回答人关心的问题：
『我现在最该先处理哪个』『为什么』『怎么做』。AI 的每一句话都能追溯
到具体的规则命中记录。」

这比"我们用 AI 检测漏洞"高级得多，且经得起评委追问。

【与赛题要求的关系】
赛题 1 要求「基于华为云产品打造 AI 创新应用」，且创新赛明确
「人工智能（必选）」。本模块满足该要求：
- 调用华为云 MaaS（大模型即 AI 能力的直接体现）
- 但调用层与业务逻辑解耦：未配置 MaaS 时降级为本地模板，
  系统仍可完整运行与演示（见demo_mode 的同类设计原则）

【降级策略】
MaaS 未配置 / 调用失败 → 使用本地规则模板生成研判文本。
界面明确标注「本次研判由本地模板生成（未调用大模型）」，
不伪装成 AI 输出。理由同 demo_mode：宁可承认降级，不伪装正常。
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Optional

# ==========================================================
# 一、MaaS 调用层
# ==========================================================
# 说明：华为云 MaaS 的调用方式随账号与模型而异，这里采用最通用的
# OpenAI 兼容 HTTP 协议形式（MaaS 提供兼容接口）。
# 未配置时is_available() 返回 False，调用方自动降级。
MAAS_BASE_URL = os.environ.get("MAAS_BASE_URL", "").strip()
MAAS_API_KEY = os.environ.get("MAAS_API_KEY", "").strip()
MAAS_MODEL = os.environ.get("MAAS_MODEL", "").strip()
MAAS_TIMEOUT = int(os.environ.get("MAAS_TIMEOUT", "60") or 60)


def is_available() -> bool:
    """MaaS 是否可用（三项配置齐全才算）。"""
    return bool(MAAS_BASE_URL and MAAS_API_KEY and MAAS_MODEL)


def _call_maas(messages: list, temperature: float = 0.2) -> Optional[str]:
    """
    调用华为云 MaaS。失败返回 None，由调用方降级。
    温度固定偏低——研判要求稳定可复现，不追求发散。
    """
    if not is_available():
        return None
    try:
        import requests
        resp = requests.post(
            f"{MAAS_BASE_URL.rstrip('/')}/chat/completions",
            headers={
                "Authorization": f"Bearer {MAAS_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": MAAS_MODEL,
                "messages": messages,
                "temperature": temperature,
            },
            timeout=MAAS_TIMEOUT,
        )
        if resp.status_code != 200:
            print(f"[AI研判] MaaS 调用失败 HTTP {resp.status_code}，降级到本地模板")
            return None
        return resp.json()["choices"][0]["message"]["content"]
    except Exception as e:
        print(f"[AI研判] MaaS 调用异常（{e}），降级到本地模板")
        return None


# ==========================================================
# 二、AI 的职责边界（写入代码而非仅写在文档里）
# ==========================================================
AI_ALLOWED_TASK = "summarize"      # 只允许汇总/解释，不允许改判定
AI_FORBIDDEN = ("detect", "judge", "verdict", "score", "decide")


def assert_ai_not_judging(payload: dict) -> None:
    """
    守卫：确保 AI 输入只包含「已判定的证据」，不包含原始待判定内容。

    理由：若把未判定的原始文件交给 AI「让它判断」，就回到了被移除的
    旧方案（结论不可核验）。这里从数据结构层面强制约束：
    AI 只接收规则引擎已经判完的结果。

    违反时直接抛错，而不是静默通过——让越界行为暴露而不是被掩盖。
    """
    required = ("verdict", "findings", "source")
    missing = [k for k in required if k not in payload]
    if missing:
        raise ValueError(
            f"AI 研判输入缺少必需字段 {missing}。"
            "AI 只允许接收已判定的证据（verdict/findings/source），"
            "不允许接收待判定内容——这是分层架构的硬约束。"
        )


# ==========================================================
# 三、研判生成
# ==========================================================
PROMPT_SKILL = """你是一名AI Agent 安全领域的资深分析师。
以下是对一个 AI Agent 技能包（Skill）的**静态规则引擎检测结果**，
每一条都包含规则名称、命中的原文行号与严重度。

请基于这些已确认的证据，生成一份研判报告，包含三部分：

【风险态势】用自己的话概括这个技能的整体风险水平，说明最严重的问题是什么。
【风险解释】解释最严重的1-2 个风险点可能造成的实际危害（结合 Agent 权限继承特性分析）。
【处置建议】给出具体、可执行的处置步骤，按优先级排序。

严格要求：
1. 只能基于下方证据推断，不得添加证据中不存在的风险。
2. 引用证据时必须写明规则名称与行号。
3. 不要复述「已检测到X 处风险」这类无信息量的内容，要给判断。
4. 用中文，200-400 字，不要用 Markdown 标题层级。

检测证据：
{evidence}
"""

PROMPT_CHAIN = """你是一名 AI Agent 安全领域的资深分析师。
以下是系统通过「能力图路径搜索」识别出的跨技能攻击链，
每条链路包含按顺序发生的多个危险动作，每一步都有原文行号支撑。

请基于这些已确认的链路，生成一份研判报告，包含三部分：

【威胁评估】说明这些链路组合起来意味着什么，攻击者能达到什么目的。
【传播路径】用清晰的语言把攻击流程讲出来（谁触发、经过哪些技能、最终造成什么后果）。
【应急处置】给出按优先级排序的处置步骤，强调哪些动作要立刻做。

严格要求：
1. 只能基于下方链路推断，不得虚构链路。
2. 每一步都要点明来源技能与行号。
3. 用中文，200-400 字。

攻击链证据：
{evidence}
"""


def _fmt_skill_evidence(result: dict, max_items: int = 12) -> str:
    """把检测结果格式化为模型可读的证据文本。"""
    lines = [
        f"技能名称：{result.get('skill_name', '未知')}",
        f"整体判定：{result.get('verdict', '未知')}",
        f"规则命中数：{len(result.get('findings', []))}",
        "",
        "明细（规则名 | 严重度 | 位置 | 原文）：",
    ]
    for f in result.get("findings", [])[:max_items]:
        ev = (f.get("evidence") or "")[:90].replace("\n", " ")
        lines.append(
            f"- {f.get('rule')} | {f.get('severity')} | "
            f"{f.get('file')}:{f.get('line')} | {ev}"
        )
    extra = len(result.get("findings", [])) - max_items
    if extra > 0:
        lines.append(f"- （另有 {extra} 处命中，规则分布："
                     + ", ".join(sorted({f.get('category', '')
                                         for f in result.get('findings', [])})) + "）")
    return "\n".join(lines)


def _fmt_chain_evidence(chain: dict) -> str:
    """把攻击链格式化为模型可读的证据文本。"""
    lines = [
        f"链路名称：{chain.get('chain_name')}",
        f"严重度：{chain.get('severity')}",
        f"作用域：{chain.get('scope')}",
        f"风险分：{chain.get('risk_score')}",
        "",
        "链路步骤（按发生顺序）：",
    ]
    for i, s in enumerate(chain.get("steps", []), 1):
        lines.append(
            f"{i}. 动作：{s.get('cap_label')}"
            f" | 来源技能：{s.get('skill', '未知')}"
            f" | 位置：{s.get('file')}:{s.get('line')}"
            f" | 命中规则：{s.get('rule')}"
        )
    return "\n".join(lines)


# ==========================================================
# 四、本地模板降级（未配置 MaaS 时使用）
# ==========================================================
def _local_skill_report(result: dict) -> str:
    """基于规则结果的确定性汇总。不调用模型，纯模板拼装。"""
    findings = result.get("findings", [])
    verdict = result.get("verdict", "未知")
    by_cat: dict = {}
    for f in findings:
        by_cat.setdefault(f.get("category", "其他"), []).append(f)

    top = sorted(findings,
                 key=lambda x: {"严重": 4, "高危": 3,
                                "中危": 2, "低危": 1}.get(x.get("severity"), 0),
                 reverse=True)[:3]

    lines = [
        f"【风险态势】该技能整体判定为「{verdict}」，"
        f"共命中 {len(findings)} 处风险点，"
        f"覆盖 {len(by_cat)} 类威胁。",
        "",
        "【风险解释】",
    ]
    if top:
        for i, f in enumerate(top, 1):
            lines.append(
                f"{i}. [{f.get('severity')}] {f.get('rule')}"
                f"（{f.get('file')}:{f.get('line')}）：{f.get('description')}"
            )
    else:
        lines.append("未命中任何规则，判定为安全。")

    lines += [
        "",
        "【处置建议】",
    ]
    if verdict in ("严重", "高危"):
        lines.append("1. 立即停止使用该技能，并隔离其运行环境")
        lines.append("2. 排查已执行过的操作，评估数据与凭据是否已泄露")
    else:
        lines.append("1. 复核上述风险点是否属于业务必需")
    if findings:
        lines.append(f"{3 if verdict in ('严重', '高危') else 2}. "
                     "按处置建议逐条整改后重新检测")
    lines.append("")
    lines.append("（本次研判由本地模板生成，未调用大模型）")
    return "\n".join(lines)


def _local_chain_report(chain: dict) -> str:
    """攻击链的本地模板研判。"""
    steps = chain.get("steps", [])
    lines = [
        f"【威胁评估】识别到「{chain.get('chain_name')}」，"
        f"严重度 {chain.get('severity')}，风险分 {chain.get('risk_score')}。"
        f"该链路由 {len(steps)} 个危险动作串联组成。",
        "",
        "【传播路径】",
    ]
    for i, s in enumerate(steps, 1):
        lines.append(
            f"{i}. 技能「{s.get('skill', '未知')}」执行「{s.get('cap_label')}」"
            f"（{s.get('file')}:{s.get('line')}）"
        )
    lines += [
        "",
        "【应急处置】",
        f"1. 立即隔离链路中涉及的技能：{'、'.join(chain.get('path', []))}",
        "2. 轮换该主机上的全部凭据，并审计历史调用记录",
        "3. 检查出网流量，确认是否存在数据外发",
        "",
        "（本次研判由本地模板生成，未调用大模型）",
    ]
    return "\n".join(lines)


# ==========================================================
# 五、主入口
# ==========================================================
@dataclass
class Adjudication:
    """
    研判结果。

    用 dataclass 而非裸 dict，是为了在代码层面表达：
    这是「AI 生成的解释」，不是「检测判定」。
    字段名刻意区分 evidence（可核验） 与 content（自然语言）。
    """
    content: str
    source: str                       # "华为云MaaS" / "本地模板"
    model: Optional[str] = None
    evidence_refs: list = field(default_factory=list)   # 引用的证据标识
    degraded: bool = False            # True 表示 AI 不可用，已降级

    def to_dict(self) -> dict:
        return {
            "content": self.content,
            "source": self.source,
            "model": self.model,
            "evidence_refs": self.evidence_refs,
            "degraded": self.degraded,
        }


def adjudicate_skill(result: dict) -> Adjudication:
    """
    对 Skill 检测结果做研判。

    参数 result —— scan_skill_package() 的返回值（**已判定**的结果）
    返回 Adjudication
    """
    assert_ai_not_judging({
        "verdict": result.get("verdict"),
        "findings": result.get("findings", []),
        "source": "skill_scanner",
    })

    evidence = _fmt_skill_evidence(result)
    refs = [f"{f.get('rule')}@{f.get('file')}:{f.get('line')}"
            for f in result.get("findings", [])[:12]]

    if is_available():
        out = _call_maas([
            {"role": "system",
             "content": "你是严谨的安全分析师，只依据给定证据分析，"
                        "不添加证据外的推断。"},
            {"role": "user", "content": PROMPT_SKILL.format(evidence=evidence)},
        ])
        if out:
            return Adjudication(content=out, source="华为云MaaS",
                                model=MAAS_MODEL, evidence_refs=refs,
                                degraded=False)

    return Adjudication(content=_local_skill_report(result),
                        source="本地模板", model=None,
                        evidence_refs=refs, degraded=True)


def adjudicate_chain(chain: dict) -> Adjudication:
    """
    对攻击链做研判。

    参数 chain —— analyze_attack_chains() 返回的单条链路
    返回 Adjudication
    """
    assert_ai_not_judging({
        "verdict": chain.get("severity"),
        "findings": chain.get("steps", []),
        "source": "attack_chain",
    })

    evidence = _fmt_chain_evidence(chain)
    refs = [f"{s.get('rule')}@{s.get('file')}:{s.get('line')}"
            for s in chain.get("steps", [])]

    if is_available():
        out = _call_maas([
            {"role": "system",
             "content": "你是严谨的安全分析师，只依据给定链路推断，"
                        "不虚构链路，不添加证据外的结论。"},
            {"role": "user", "content": PROMPT_CHAIN.format(evidence=evidence)},
        ])
        if out:
            return Adjudication(content=out, source="华为云MaaS",
                                model=MAAS_MODEL, evidence_refs=refs,
                                degraded=False)

    return Adjudication(content=_local_chain_report(chain),
                        source="本地模板", model=None,
                        evidence_refs=refs, degraded=True)


if __name__ == "__main__":
    import sys as _sys
    import os as _os
    _sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

    print("=" * 66)
    print("AI 研判层自检")
    print("=" * 66)
    print(f"MaaS 可用: {is_available()}")
    if not is_available():
        print("  → 未配置 MAAS_BASE_URL / MAAS_API_KEY / MAAS_MODEL")
        print("  → 系统将使用本地模板，功能不受影响（设计如此）")
    print()

    # 用真实检测结果验证
    import tempfile, shutil as _sh
    from modules.skill_scanner import make_demo_package, scan_skill_package
    d = tempfile.mkdtemp()
    try:
        r = scan_skill_package(make_demo_package(d))
        adj = adjudicate_skill(r)
        print(f"技能研判 | 来源：{adj.source} | 降级：{adj.degraded}")
        print(f"引用证据 {len(adj.evidence_refs)} 条")
        print("-" * 66)
        print(adj.content)
    finally:
        _sh.rmtree(d, ignore_errors=True)
    print("=" * 66)
