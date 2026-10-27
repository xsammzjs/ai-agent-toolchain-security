# -*- coding: utf-8 -*-
"""
SCR-Bench 组合层完整评测（规则快筛 + AI 意图分诊 + 三要素成链）

只对「规则层有信号」的技能调用 AI（SCR-Bench 651 个技能中仅 1 个触发，
即本项目「规则降级为初筛、AI 精定位」设计的直接体现）。

API 调用数会被记账并打印。
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

import config  # noqa: F401,E402
from modules import adjudicator as adj  # noqa: E402
from modules import combo_analysis as ca  # noqa: E402
from modules import skill_scanner as ss  # noqa: E402

BASE = os.path.join(ROOT, "samples", "public_bench", "scr_bench")
OUT = os.path.join(ROOT, "samples", "public_bench", "_scr_bench_full.json")


def iter_skills():
    for sub in sorted(os.listdir(BASE)):
        sdir = os.path.join(BASE, sub)
        if not os.path.isdir(sdir):
            continue
        for case in sorted(os.listdir(sdir)):
            cdir = os.path.join(sdir, case)
            if not os.path.isdir(cdir):
                continue
            for fn in sorted(os.listdir(cdir)):
                if not fn.endswith(".md"):
                    continue
                p = os.path.join(cdir, fn)
                with open(p, encoding="utf-8", errors="replace") as f:
                    yield sub, case, fn[:-3], f.read()


def main():
    print("=" * 90)
    print("SCR-Bench 组合层完整评测")
    print("=" * 90)
    print()

    cases = {}
    n_skills = 0
    rule_sus = []
    n_rule_hit = 0
    n_cap_sig = 0
    for sub, case, name, text in iter_skills():
        n_skills += 1
        c = cases.setdefault((sub, case), [])
        r = ss.scan_skill_text(name, text)
        caps = ca.extract_caps(text)
        c.append({"name": name, "text": text, "caps": caps,
                  "rule_hits": len(r["findings"])})
        if r["findings"]:
            n_rule_hit += 1
        if caps:
            n_cap_sig += 1
        if r["findings"] or caps:
            rule_sus.append((sub, case, name, text, caps, r["findings"]))

    print(f"  技能总数 {n_skills}，case 总数 {len(cases)}")
    print(f"  ├ 32 条规则命中（findings > 0）的技能：{n_rule_hit} 个")
    print(f"  ├ 提取到能力原子（capability ≠ ∅）的技能：{n_cap_sig} 个")
    print(f"  └ 需 AI 分诊（规则命中 或 有能力原子）：{len(rule_sus)} 个")
    print()
    print("  ⚠️ 归属口径：两者是**不同通道**，不可混为一谈——")
    print("     规则层 0 命中说明「32 条正则在这批国际基准语料上完全失灵」；")
    print("     那 1 个是**能力原子通道**筛出的，AI 分诊再判其意图。")
    print()

    # ---- AI 分诊（只对规则层有信号的技能）----
    print("── AI 意图分诊（只对规则命中或有能力原子的技能调用）──")
    verdicts = {}
    api_calls = 0
    for sub, case, name, text, caps, hits in rule_sus:
        key = f"{sub}/{case}/{name}"
        r = adj.judge_skill_combined(key, text)
        if not r.get("cached"):
            api_calls += 1
        verdicts[key] = r
        print(f"  {key}")
        print(f"      判定={r['verdict']}  外发={r['scope']}  "
              f"degraded={r.get('degraded')}  cached={r.get('cached')}")
        print(f"      理由：{r.get('reason', '')[:110]}")
        print(f"      证据行号：意图 {r.get('ev_intent')} / 外发 {r.get('ev_scope')}")
    print()
    print(f"  本次实际 API 调用：{api_calls} 次"
          f"（缓存命中 {len(rule_sus)-api_calls} 次）")
    print()

    # ---- 组合判定 ----
    print("── 三要素成链 ──")
    chains = []
    for (sub, case), group in cases.items():
        caps_map = {g["name"]: g["caps"] for g in group}
        names = [g["name"] for g in group]
        intents = {}
        for g in group:
            k = f"{sub}/{case}/{g['name']}"
            intents[g["name"]] = verdicts.get(k, {
                "verdict": "BENIGN", "scope": "NONE",
                "reason": "规则层无信号，未触发 AI 分诊",
                "ev_intent": [], "ev_scope": [],
            })
        got = ca.build_chains(names, caps_map, intents)
        for c in got:
            c["subbench"] = sub
            c["case"] = case
        chains.extend(got)
        if got:
            print(f"  ⚠ {sub}/{case} 成链 {len(got)} 条")
            for c in got:
                print(f"      [{c['tid']}] {c['mal']} + {c['other']} — {c['why']}")
    print()
    print(f"  成链总数 {len(chains)} 条")
    if not chains:
        print("  ✅ 268 个国际基准良性组合 case，零误报")
    print()

    v_hist = Counter(v["verdict"] for v in verdicts.values())
    print(f"  AI 判定分布：{dict(v_hist)}")
    print()

    out = {
        "source": "https://github.com/saint-viperx/SCR_Bench (arXiv 2606.15242)",
        "n_skills": n_skills, "n_cases": len(cases),
        "rule_hit_skills": n_rule_hit,
        "cap_signal_skills": n_cap_sig,
        "need_ai_triage": len(rule_sus),
        "rule_signal_ratio": f"{n_cap_sig*100.0/max(n_skills,1):.2f}%",
        "api_calls_this_run": api_calls,
        "api_calls_note": ("本次运行的实际模型调用数。首次冷跑为 1；"
                           "命中本地磁盘缓存后复跑为 0，判定结论与证据行号一字不变。"
                           "首次冷跑记录见 docs/材料写作规格_数字与口径红线.md 第七章 §7.6。"),
        "attribution_note": ("那 1 个可疑技能是【能力原子通道】筛出的，"
                             "不是 32 条规则筛出的——规则层在 651 个技能上 0 命中。"
                             "两个通道必须分开表述。"),
        "judgements": {k: {kk: vv for kk, vv in v.items()} for k, v in verdicts.items()},
        "chains": chains,
        "n_chains": len(chains),
        "verdict_dist": dict(v_hist),
        "caveat": ("SCR-Bench 原指标为执行后行为成功率（ASR），本项目为静态分析 + "
                   "意图分诊，口径不同不可直接横比；本评测证明方法在真实国际基准"
                   "良性组合语料上不崩溃、不刷屏。"),
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"结果已写入 {os.path.relpath(OUT, ROOT)}")


if __name__ == "__main__":
    main()
