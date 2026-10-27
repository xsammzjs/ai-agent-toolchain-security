"""
生死点验证 · 探针脚本（2026-10-26）
==================================
目的：验证「多技能组合风险关联分析」这个方向**到底能不能立得住**。

【要回答的三个问题】
Q1. 把 107 个真实样本同时放进组合分析，会爆出多少条链路？
    → 如果是几百上千条，说明能力原子太粗，一堆良性 skill 凑在一起也报警，
       这个方向直接死。
Q2. 这些链路里，有多少是真信号？
    → 真信号 = 恶意样本提供的链路；假信号 = 良性样本之间凑出来的链路。
Q3. 现有模板（6 条链路）在真实语料上覆盖得住吗？
    → 如果 107 个样本里能力原子分布很散、模板套不上，说明模板要重做。

【只做静态分析】
不执行任何样本内容，纯字符串匹配 + 图搜索。

【跑法】
  python samples/probe_combo_analysis.py
"""
import io
import json
import os
import sys
from collections import Counter, defaultdict

if __name__ == "__main__":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules import skill_scanner as ss
from modules import attack_chain as ac

SAMPLES_DIR = os.path.dirname(os.path.abspath(__file__))

MAL_DIRS = [
    os.path.join(SAMPLES_DIR, "real_toxicskills"),
    os.path.join(SAMPLES_DIR, "real_corpus", "toxic_skills"),
]
BEN_DIRS = [
    os.path.join(SAMPLES_DIR, "real_corpus", "benign_scientific"),
]


def load_dir(d, truth):
    """读取目录下所有 .md 样本，返回 [(name, text, truth)]。"""
    out = []
    if not os.path.isdir(d):
        return out
    labels = {}
    lf = os.path.join(d, "_labels.json")
    if os.path.isfile(lf):
        try:
            labels = json.load(open(lf, encoding="utf-8"))
        except (OSError, ValueError):
            labels = {}
    for fn in sorted(os.listdir(d)):
        if not fn.endswith(".md") or fn.startswith("_"):
            continue
        try:
            text = open(os.path.join(d, fn), encoding="utf-8").read()
        except OSError:
            continue
        eff = labels.get(fn) or truth
        out.append((fn[:-3], text, eff))
    return out


def main():
    samples = []
    for d in MAL_DIRS:
        samples += load_dir(d, "malicious")
    for d in BEN_DIRS:
        samples += load_dir(d, "benign")

    print("=" * 78)
    print("生死点验证 · 组合分析真实成色探针")
    print("=" * 78)
    print(f"样本总数：{len(samples)}")
    mal_n = sum(1 for s in samples if s[2] == "malicious")
    print(f"  恶意 {mal_n} / 良性 {len(samples) - mal_n}")
    print()

    # ---------- 逐个扫描，提取能力原子 ----------
    scan_results = []
    for name, text, truth in samples:
        res = ss.scan_skill_text(name, text)
        res["_truth"] = truth
        res["_text"] = text
        scan_results.append(res)

    # ---------- Q2 前置：能力原子在语料上的分布 ----------
    index = ac.build_index(scan_results)
    providers = index["providers"]
    print("【能力原子分布】每个能力被多少个样本提供")
    print("-" * 78)
    cap_to_skills = defaultdict(list)
    for (sname, cap) in index["cap_owners"]:
        cap_to_skills[cap].append(sname)
    truth_of = {r["skill_name"]: r["_truth"] for r in scan_results}
    for cap in sorted(cap_to_skills, key=lambda c: -len(cap_to_skills[c])):
        names = cap_to_skills[cap]
        n_mal = sum(1 for n in names if truth_of.get(n) == "malicious")
        label = ac.CAPABILITY_LABEL.get(cap, cap)
        print(f"  {cap:12s} {label:12s} 共 {len(names):4d} 个样本提供"
              f"（其中恶意 {n_mal}）")
    print()

    # 每个样本平均带几个能力
    cap_counts = [len(v["caps"]) for v in index["per_skill"].values()]
    if cap_counts:
        avg = sum(cap_counts) / len(cap_counts)
        print(f"  每个样本平均携带能力原子数：{avg:.2f}")
        zero = sum(1 for c in cap_counts if c == 0)
        print(f"  完全不带任何能力的样本：{zero}/{len(cap_counts)}")
    print()

    # ---------- Q1：全体放进组合分析 ----------
    combo = ac.analyze_attack_chains(scan_results)
    chains = combo["chains"]
    print("【Q1 · 组合分析在 107 真实样本上的产出】")
    print("-" * 78)
    print(f"  命中链路总数：{len(chains)}")
    print(f"  其中跨技能链路：{combo['summary']['cross_skill_count']}")
    print(f"  最高风险分：{combo['summary']['max_score']}")
    print(f"  涉及能力原子种类：{combo['total_caps']}")
    print()

    # ---------- Q2：链路里有多少真信号 ----------
    print("【Q2 · 链路的真假构成】")
    print("-" * 78)
    chain_by_type = Counter()
    for ch in chains:
        # 链路涉及的样本里，只要有恶意样本就算"涉及恶意"，否则是纯良性凑出来的
        involved = set(ch["path"])
        has_mal = any(truth_of.get(s) == "malicious" for s in involved)
        chain_by_type["涉及恶意样本" if has_mal else "纯良性组合"] += 1
    for k, v in chain_by_type.items():
        print(f"  {k:16s} {v:5d} 条")
    pure_benign = chain_by_type.get("纯良性组合", 0)
    if chains:
        purity = pure_benign / len(chains) * 100
        print(f"  → 纯良性凑出的假链路占比：{purity:.1f}%")
    print()

    # 按链路模板统计
    print("  按模板分布（链路 ID → 数量 / 其中纯良性）：")
    tmpl_stat = defaultdict(lambda: [0, 0])
    for ch in chains:
        involved = set(ch["path"])
        has_mal = any(truth_of.get(s) == "malicious" for s in involved)
        tmpl_stat[ch["chain_id"]][0] += 1
        if not has_mal:
            tmpl_stat[ch["chain_id"]][1] += 1
    for tid, (total, fake) in sorted(tmpl_stat.items()):
        tname = next((t["name"] for t in ac.CHAIN_TEMPLATES if t["id"] == tid), tid)
        print(f"    {tid:16s} {tname:16s} {total:5d} 条 / 假 {fake:5d}")
    print()

    # ---------- Q3：模板覆盖度 ----------
    print("【Q3 · 6 类链路模板的覆盖情况】")
    print("-" * 78)
    for t in ac.CHAIN_TEMPLATES:
        n = tmpl_stat.get(t["id"], [0])[0]
        print(f"  {t['id']:16s} {t['name']:18s} 命中 {n:5d} 条  "
              f"({'✅ 有产出' if n else '❌ 真实语料上从未命中'})")
    print()

    # ---------- 详细样本：恶意样本各自贡献了什么能力 ----------
    print("【恶意样本能力明细】（看单个恶意 skill 能不能被单点判定）")
    print("-" * 78)
    for r in scan_results:
        if r["_truth"] != "malicious":
            continue
        info = index["per_skill"].get(r["skill_name"], {})
        caps = info.get("caps", {})
        cap_names = [ac.CAPABILITY_LABEL.get(c, c) for c in caps]
        print(f"  {r['skill_name'][:44]:46s}")
        print(f"      判定 {r.get('verdict', '?'):4s}  "
              f"命中 {len(r['findings']):3d} 处  能力: {', '.join(cap_names) or '（无）'}")
    print()

    # ---------- 关键：单点 vs 组合的对比数字 ----------
    print("【对比 · 单点检测 vs 组合关联】")
    print("-" * 78)
    # 单点：多少个样本单独就会报警
    single_alarm = sum(1 for r in scan_results if r["findings"])
    mal_alarm = sum(1 for r in scan_results
                    if r["_truth"] == "malicious" and r["findings"])
    # 组合：多少个"组合"（恶意 skill + 任意 benign skill 的配对）能触发链路
    mal_names = {r["skill_name"] for r in scan_results if r["_truth"] == "malicious"}
    ben_names = {r["skill_name"] for r in scan_results if r["_truth"] != "malicious"}
    print(f"  单点检测会报警的样本：{single_alarm}/{len(scan_results)}")
    print(f"    其中恶意样本：{mal_alarm}/{mal_n}（这是已知的 TPR）")
    print(f"  组合分析覆盖的能力原子种类：{combo['total_caps']}")
    print(f"  跨技能链路数：{combo['summary']['cross_skill_count']}")
    print()

    # 保存原始数据供后续分析
    out = os.path.join(SAMPLES_DIR, "_probe_combo_output.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump({
            "total_samples": len(scan_results),
            "malicious": mal_n,
            "chain_count": len(chains),
            "cross_skill_count": combo["summary"]["cross_skill_count"],
            "pure_benign_chains": pure_benign,
            "capabilities_per_skill": {
                r["skill_name"]: sorted(index["per_skill"]
                                       .get(r["skill_name"], {}).get("caps", {}).keys())
                for r in scan_results
            },
            "chains": [
                {"id": c["chain_id"], "scope": c["scope"], "path": c["path"],
                 "score": c["risk_score"],
                 "involves_malicious": any(truth_of.get(s) == "malicious"
                                           for s in c["path"])}
                for c in chains
            ],
        }, f, ensure_ascii=False, indent=2)
    print(f"原始数据已存：{out}")
    print("=" * 78)


if __name__ == "__main__":
    main()
