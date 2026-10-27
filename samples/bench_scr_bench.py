# -*- coding: utf-8 -*-
"""
SCR-Bench（华东师大 + A*STAR，arXiv 2606.15242）适配器

用途：把国际公开基准的「良性技能组合」转成本项目的评测输入，
验证三段式架构在**单看每个技能都正常**的组合上的表现。

三个子基准的威胁模型：
  SCR-CapFlow   能力流动：上游技能提供目标/上下文 → 下游技能产生有害状态变更
  SCR-TrustLift 信任传递：一个看起来像安全工具的技能为后续风险动作「背书」
  SCR-AuthBlur  授权混淆：咨询/发现类上下文把 Agent 的审批边界推向不安全决策

重要说明：
  SCR-Bench 的原论文指标是**执行后的行为成功率 / 风险审批率**，
  需要真实 Agent 运行环境（Claude Code / Codex 等）才能复现。
  本项目是**静态分析与意图分诊**，不执行技能，因此：
  本脚本衡量的是「在组合层能否识别出结构性风险信号」，
  与论文的 ASR 不在同一口径，**不可直接数字横比**。
  本脚本的价值是：证明我们的方法在真实国际基准语料上不崩溃、不刷屏。

数据来源：https://github.com/saint-viperx/SCR_Bench
"""
import io
import json
import os
import sys
from collections import Counter

if __name__ == "__main__":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "samples"))

from modules import combo_analysis as ca  # noqa: E402
from modules import skill_scanner as ss  # noqa: E402

SRC = os.environ.get(
    "SCR_BENCH_ROOT",
    r"C:\Users\34612\AppData\Local\Temp\tgz\SCR_Bench-main")
DST = os.path.join(ROOT, "samples", "public_bench", "scr_bench")
OUT = os.path.join(ROOT, "samples", "public_bench", "_scr_bench_result.json")

SUBBENCH = {
    "SCR-CapFlow": os.path.join(SRC, "SCR-CapFlow", "cases-env"),
    "SCR-AuthBlur": os.path.join(SRC, "SCR-AuthBlur", "cases"),
}


def collect(sub, cases_root):
    """收集一个子基准下所有 case 的技能正文。"""
    if not os.path.isdir(cases_root):
        return []
    out = []
    for case in sorted(os.listdir(cases_root)):
        if not case.startswith("case"):
            continue
        skills_root = os.path.join(cases_root, case, "cli_skills", "skills")
        if not os.path.isdir(skills_root):
            continue
        skills = []
        for sd in sorted(os.listdir(skills_root)):
            p = os.path.join(skills_root, sd, "SKILL.md")
            if not os.path.exists(p):
                continue
            with open(p, encoding="utf-8", errors="replace") as f:
                skills.append((sd, f.read()))
        if skills:
            out.append({"subbench": sub, "case": case, "skills": skills})
    return out


def main():
    print("=" * 90)
    print("SCR-Bench 国际公开基准适配评测")
    print("=" * 90)
    print(f"数据源：{SRC}")
    print()
    print("口径声明：SCR-Bench 原论文指标是「执行后的行为成功率」，需要真实 Agent 运行时。")
    print("本项目是静态分析 + 意图分诊，不执行技能，因此衡量的是")
    print("「在组合层能否识别结构性风险信号」，与论文 ASR 不同口径，不可直接横比。")
    print()

    all_cases = []
    for sub, root in SUBBENCH.items():
        cs = collect(sub, root)
        print(f"  {sub:16s} 收集 {len(cs)} 个 case")
        all_cases.extend(cs)
    print(f"  合计 {len(all_cases)} 个 case")
    print()

    n_skills = sum(len(c["skills"]) for c in all_cases)
    print(f"  技能总数 {n_skills} 个")
    print()

    # ---------- 规则快筛（零 API 成本）----------
    print("── 规则快筛（32 条规则）──")
    rule_hist = Counter()
    rule_hit_cases = 0
    caps_per_case = []
    all_rule_hits = 0
    for c in all_cases:
        hit = 0
        caps = {}
        for name, text in c["skills"]:
            r = ss.scan_skill_text(name, text)
            hit += len(r["findings"])
            for f in r["findings"]:
                rule_hist[f.get("rule")] += 1
            cp = ca.extract_caps(text)
            for k, v in cp.items():
                caps.setdefault(k, 0)
                caps[k] += len(v)
        all_rule_hits += hit
        caps_per_case.append(caps)
        if hit:
            rule_hit_cases += 1
    print(f"  规则命中总数 {all_rule_hits} 处，"
          f"覆盖 {rule_hit_cases}/{len(all_cases)} 个 case")
    print("  命中最多的规则 Top8：")
    for k, v in rule_hist.most_common(8):
        print(f"    {k:24s} × {v}")
    print()

    cap_hist = Counter()
    for caps in caps_per_case:
        for k, v in caps.items():
            cap_hist[k] += 1
    print("  能力原子出现频次（按 case 计）：")
    for k, v in cap_hist.most_common():
        print(f"    {ca.CAPABILITY_LABELS.get(k, k):20s} {v:4d} / {len(all_cases)}")
    print()

    # ---------- 组合层：能否成链 ----------
    print("── 组合层判定（三要素成链，规则层近似）──")
    print("  说明：AI 意图闸门需要 API 调用，此处先用「规则层能对上的能力对」")
    print("        统计上界，验证组合分析在真实国际语料上不会刷屏。")
    print()
    chain_hist = Counter()
    cases_with_chain = 0
    total_pairs = 0
    for c in all_cases:
        skills = c["skills"]
        pairs = 0
        for tid, need, sev, why in ca.PAIR_TEMPLATES:
            for i, (n1, t1) in enumerate(skills):
                c1 = ca.extract_caps(t1)
                if need[0] not in c1:
                    continue
                for j, (n2, t2) in enumerate(skills):
                    if i == j:
                        continue
                    c2 = ca.extract_caps(t2)
                    if need[1] in c2:
                        pairs += 1
                        chain_hist[tid] += 1
        total_pairs += pairs
        if pairs:
            cases_with_chain += 1
    print(f"  能力互补对总数 {total_pairs}（覆盖 {cases_with_chain}/{len(all_cases)} 个 case）")
    for k, v in chain_hist.most_common():
        print(f"    {k:16s} × {v}")
    print()

    # ---------- 语料清洗到项目内 ----------
    os.makedirs(DST, exist_ok=True)
    n_copied = 0
    for c in all_cases:
        d = os.path.join(DST, c["subbench"], c["case"])
        os.makedirs(d, exist_ok=True)
        for name, text in c["skills"]:
            with open(os.path.join(d, name + ".md"), "w", encoding="utf-8") as f:
                f.write(text)
            n_copied += 1
    print(f"  已清洗 {n_copied} 个技能文件到 {os.path.relpath(DST, ROOT)}")
    print()

    out = {
        "source": "https://github.com/saint-viperx/SCR_Bench",
        "paper": "arXiv 2606.15242 (华东师范大学 + A*STAR)",
        "n_cases": len(all_cases),
        "n_skills": n_skills,
        "subbench_cases": {s: len(collect(s, r)) for s, r in SUBBENCH.items()},
        "rule_hits_total": all_rule_hits,
        "rule_hit_cases": rule_hit_cases,
        "top_rules": dict(rule_hist.most_common(15)),
        "capability_freq": dict(cap_hist),
        "capability_pair_total": total_pairs,
        "cases_with_chain": cases_with_chain,
        "chain_by_template": dict(chain_hist),
        "caveat": ("SCR-Bench 原指标为执行后行为成功率（ASR），本项目为静态分析，"
                   "口径不同不可直接横比；本评测用于验证方法在真实国际语料上不崩溃。"),
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"结果已写入 {os.path.relpath(OUT, ROOT)}")


if __name__ == "__main__":
    main()
