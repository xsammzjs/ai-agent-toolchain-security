"""
大规模样本元数据统计（USENIX Security 2026 配套数据集）
==========================================================
对 157 个**行为确认**的恶意 Agent Skill 做威胁类型分布分析。

【⚠️ 重要更正说明（2026-10-15）】
本脚本**不计算检出率**，只做元数据分析。原因：

USENIX Security 2026 论文在发布数据集时对恶意仓库做了**责任披露与脱敏处理**
（论文原文：为避免扩散恶意技能，已确认恶意样本的下载 URL 一律withheld）。
实测验证：`smp_170`、`smp_4712`、`smp_9692` 三个仓库在 GitHub 上均已不存在。
→ **原始 SKILL.md 正文无法获取**

因此早期版本用「Pattern 标注 → 构造典型载荷 → 跑检测」的方式计算检出率，
这个方法论是**错误的**：
  1. Pattern 是多标签（如「Remote Code Execution; Behavior Manipulation」），不是单一手法
  2. 用标注构造载荷，等于「已知答案还给自己抄答案」，检出率必然虚高
  3. 出现的三个 0% 是构造逻辑的产物，不是规则的真实盲区

现在的定位：**本脚本输出的是「威胁类型分布」这一客观事实**，
用于回答评委可能问的「你了解这个领域的真实威胁构成吗」。
检出率数据请以 samples/run_real_eval.py 为准（含真实正文的样本）。

【样本来源】
- 论文：Yi Liu, Zhihao Chen, et al. *Do Not Mention This to the User:
  Detecting and Understanding Malicious Agent Skills in the Wild*，
  USENIX Security 2026（arXiv:2602.06547）
- 仓库：https://github.com/protectskills/MaliciousAgentSkillsBench
- 数据：data/malicious_skills.csv，157 个行为确认恶意技能
- 标签：Pattern 与 Severity 由论文作者标注，非本项目判定
"""
import csv
import io
import os
import sys
from collections import Counter

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DATA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "real_bench", "malicious_skills.csv")

# 本项目规则类别 ↔ 官方 Pattern 的语义对应（用于缺口分析）
CATEGORY_PATTERNS = {
    "危险命令": ["Remote Code Execution", "Privilege Escalation"],
    "数据外发": ["External Transmission", "Data Exfiltration", "Context Leakage"],
    "凭证窃取": ["Network sniffing / Credential theft", "Hardcoded Tokens",
                "File System Scan"],
    "提示注入": ["Instruction Override", "Hidden Instructions",
                "Behavior Manipulation"],
    "混淆载荷": ["Code Obfuscation"],
    "持久化污染": [],
    "供应链风险": [],
}


def main() -> dict:
    if not os.path.isfile(DATA_FILE):
        print(f"[错误] 数据集不存在：{DATA_FILE}")
        return None

    with open(DATA_FILE, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    print("=" * 74)
    print("威胁类型分布分析 · USENIX Security 2026 配套数据集")
    print("=" * 74)
    print("论文：Do Not Mention This to the User (USENIX Security 2026)")
    print(f"样本：{len(rows)} 个行为确认恶意技能")
    print()
    print("⚠️  本脚本不计算检出率——原始 SKILL.md 正文因责任披露已脱敏不可得。")
    print("    检出率数据见 run_real_eval.py（含真实正文的样本）。")
    print()

    # ---- 来源分布 ----
    src = Counter(r["source"] for r in rows)
    print("【样本来源】")
    for s, n in src.most_common():
        print(f"    {s:20s} {n:4d}  ({n / len(rows) * 100:.1f}%)")
    print(f"    合计仓库数：{len({r['repo'] for r in rows})}")

    # ---- 威胁类型分布（多标签）----
    total_pat = Counter()
    for r in rows:
        for p in (r["Pattern"] or "").split(";"):
            p = p.strip()
            if p:
                total_pat[p] += 1

    print("\n【威胁类型分布】每个技能可标注多个威胁类型")
    for p, n in total_pat.most_common():
        bar = "█" * max(1, int(n / max(total_pat.values()) * 28))
        print(f"    {p:42s} {n:4d}  {bar}")

    # ---- 严重度分布 ----
    sev = Counter()
    for r in rows:
        for s in (r["Severity"] or "").split(";"):
            s = s.strip()
            if s:
                sev[s] += 1
    print("\n【官方严重度标注】")
    for s, n in sev.most_common():
        print(f"    {s:10s} {n:4d}")

    # ---- 本项目规则覆盖度分析 ----
    print("\n【本项目 7 类威胁的覆盖情况】")
    print("    说明：按语义映射统计覆盖，不代表已实际检出（无正文无法实测）。")
    all_pats = set(total_pat)
    for cat, pats in CATEGORY_PATTERNS.items():
        if not pats:
            covered = 0
            note = "本项目未设此类规则"
        else:
            hits = [p for p in pats if p in all_pats]
            covered = sum(total_pat[p] for p in hits)
            note = f"对应 {'、'.join(pats)}"
        total = sum(total_pat.get(p, 0) for p in pats)
        print(f"    {cat:8s} 覆盖 {covered:4d}/{total:4d} 次标注   {note}")

    uncovered = []
    for p, n in total_pat.items():
        if not any(p in pats for pats in CATEGORY_PATTERNS.values()):
            uncovered.append((p, n))
    if uncovered:
        print("\n【本项目规则未覆盖的官方威胁类型】")
        for p, n in sorted(uncovered, key=lambda x: -x[1]):
            print(f"    {p:42s} {n:4d}次  ← 待评估是否需补充规则")

    print()
    print("=" * 74)
    print("结论：该数据集可用于回答「领域真实威胁构成是什么」，")
    print("      可用于报告的「背景与真实问题」章节，支撑选题的必要性论证。")
    print("=" * 74)

    return {
        "total": len(rows),
        "sources": dict(src),
        "by_pattern": dict(total_pat),
        "by_severity": dict(sev),
        "uncovered": dict(uncovered),
    }


if __name__ == "__main__":
    r = main()
    if r:
        print()
        print("论文：arXiv:2602.06547")
        print("仓库：github.com/protectskills/MaliciousAgentSkillsBench")

