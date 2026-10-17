"""
真实语料评测（检出率 + 误报率）
==================================
在含完整正文的真实 Skill 样本上评测本项目。

【解决的问题】
评测有两个方向，缺一不可：
- **检出率（TPR）**：真恶意样本能否查出来？→靠 toxic_skills 语料
- **误报率（FPR）**：正常技能会不会被误判？→ **靠 benign 语料，这是之前最缺的**

此前只有 8 个含正文的样本（5恶意 + 2良性），统计意义不足。
本脚本配合 fetch_real_samples.py 下载的语料，可覆盖百余个真实样本。

【重要原则】
1. 只做**静态分析**，不执行任何样本内容
2. 良性样本误报数是**核心指标**——安全检测工具如果天天误报，
   用户就不会再用它
3. 如实输出，不粉饰：误报高就说误报高，并分析具体规则为什么误报
"""
import io
import json
import os
import sys
from collections import Counter

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules import skill_scanner as ss

CORPUS_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "real_corpus")


def _load(corpus: str) -> list:
    """读取一个语料目录，返回 (name, text, meta) 列表"""
    d = os.path.join(CORPUS_ROOT, corpus)
    if not os.path.isdir(d):
        return []
    mf = os.path.join(d, "_manifest.json")
    meta_by_file = {}
    if os.path.isfile(mf):
        try:
            meta_by_file = {i["file"]: i
                            for i in json.load(open(mf, encoding="utf-8"))["items"]}
        except (OSError, ValueError):
            pass

    items = []
    for fn in sorted(os.listdir(d)):
        if not fn.endswith(".md") or fn.startswith("_"):
            continue
        try:
            text = open(os.path.join(d, fn), encoding="utf-8").read()
        except OSError:
            continue
        items.append((fn[:-3], text, meta_by_file.get(fn, {})))
    return items


def eval_corpus(corpus: str, expect: str) -> dict:
    items = _load(corpus)
    if not items:
        print(f"  [跳过] {corpus} 无样本")
        return None

    tp = fp = tn = fn = 0
    false_positives = []      # 误报样本明细（用于分析原因）
    hit_rules = Counter()

    for name, text, meta in items:
        res = ss.scan_skill_text(name, text)
        detected = len(res["findings"]) > 0

        if expect == "malicious":
            tp += detected
            fn += not detected
        else:
            fp += detected
            tn += not detected
            if detected:
                false_positives.append({
                    "name": name,
                    "verdict": res["verdict"],
                    "count": len(res["findings"]),
                    "rules": sorted({f["rule"] for f in res["findings"]}),
                })
        for f in res["findings"]:
            hit_rules[f["rule"]] += 1

    return {
        "corpus": corpus, "expect": expect, "total": len(items),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "false_positives": false_positives, "hit_rules": hit_rules,
    }


def main():
    if not os.path.isdir(CORPUS_ROOT):
        print("[错误] 语料目录不存在，请先运行 fetch_real_samples.py")
        return

    print("=" * 76)
    print("真实语料评测 · 检出率与误报率")
    print("=" * 76)
    print(f"规则数量：{len(ss.RULE_TABLE)} 条")
    print("所有样本仅做静态分析，不执行")
    print()

    # 恶意语料（多个来源合并）
    mal_sources = [("toxic_skills", "malicious"),
                   ("real_toxicskills", "malicious")]
    mal_results = [r for r in (eval_corpus(c, e) for c, e in mal_sources) if r]

    ben_sources = [("benign_scientific", "benign"),
                   ("benign_misc", "benign")]
    ben_results = [r for r in (eval_corpus(c, e) for c, e in ben_sources) if r]

    # ---------- 汇总 ----------
    def agg(rs, key_total="total"):
        return {k: sum(r[k] for r in rs) for k in ("total", "tp", "fp", "tn", "fn")}

    M = agg(mal_results) if mal_results else None
    B = agg(ben_results) if ben_results else None

    if M and M["total"]:
        tpr = M["tp"] / M["total"] * 100
        print("【恶意样本 · 检出率】")
        for r in mal_results:
            rate = r["tp"] / r["total"] * 100 if r["total"] else 0
            print(f"    {r['corpus']:22s} {r['tp']:4d}/{r['total']:<4d} = {rate:5.1f}%")
        print(f"    {'合计':22s} {M['tp']:4d}/{M['total']:<4d} = {tpr:5.1f}%")
        print()

    if B and B["total"]:
        fpr = B["fp"] / B["total"] * 100
        specificity = B["tn"] / B["total"] * 100
        print("【良性样本 · 误报率】")
        for r in ben_results:
            rate = r["fp"] / r["total"] * 100 if r["total"] else 0
            print(f"    {r['corpus']:22s} {r['fp']:4d}/{r['total']:<4d} = {rate:5.1f}% 误报")
        print(f"    {'合计':22s} {B['fp']:4d}/{B['total']:<4d} = {fpr:5.1f}% 误报")
        print(f"    特异度（正确放行率） {specificity:.1f}%")
        print()

        # 误报明细——这是最需要如实展示的部分
        fps = [fp for r in ben_results for fp in r["false_positives"]]
        if fps:
            print(f"    误报样本明细（前15 条）：")
            for item in sorted(fps, key=lambda x: -x["count"])[:15]:
                print(f"      {item['name'][:42]:44s} {item['verdict']:4s} "
                      f"{item['count']:3d} 处  {'、'.join(item['rules'][:2])}")
            # 哪条规则贡献了最多误报
            print()
            bad = Counter()
            for item in fps:
                for rule in item["rules"]:
                    bad[rule] += 1
            print("    误报贡献规则 Top5（这些规则需要收紧）：")
            for rule, n in bad.most_common(5):
                print(f"      {rule:28s} 涉及 {n} 个良性样本")
        else:
            print("    ✅ 无误报")
        print()

    # ---------- 命中分布 ----------
    all_rules = Counter()
    for r in mal_results + ben_results:
        all_rules.update(r["hit_rules"])
    if all_rules:
        print("【规则命中分布】Top10")
        for rule, n in all_rules.most_common(10):
            print(f"    {rule:28s} {n:5d}")

    print()
    print("=" * 76)
    print("复现命令：")
    print("  python samples/fetch_real_samples.py   # 下载语料")
    print("  python samples/run_corpus_eval.py      # 运行评测")
    print("=" * 76)

    return {"malicious": M, "benign": B}


if __name__ == "__main__":
    main()