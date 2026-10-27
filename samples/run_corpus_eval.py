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

【2026-10-22 修复：语料路径 bug】
原实现把恶意语料指向 ``real_corpus/real_toxicskills/``，但恶意样本实际
位于 ``real_toxicskills/``（与 ``real_bench/`` 同级），导致本脚本
**从未统计过恶意样本**——检出率一直由 run_real_eval.py 单独提供，
两个脚本各算一半，没人发现。

现改为**多候选路径 + 标签文件**机制：
- 每个语料声明多个候选目录，找到即用
- 恶意/良性判定优先读语料目录下的 ``_labels.json``（逐文件标注），
  缺省时按目录整体标注
这样无论语料放在哪、怎么混装，TPR 与 FPR 都在本脚本内合并输出，
并给出完整混淆矩阵。
"""
import io
import json
import os
import sys
from collections import Counter

# 仅在本脚本作为 __main__ 直接运行时接管 stdout（避免 import 时关闭父进程的流）
if __name__ == "__main__":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules import skill_scanner as ss

SAMPLES_DIR = os.path.dirname(os.path.abspath(__file__))

# 每个语料名 → 候选目录（按顺序找第一个存在的）
CORPUS_CANDIDATES = {
    "benign_scientific": [os.path.join(SAMPLES_DIR, "real_corpus", "benign_scientific"),
                          os.path.join(SAMPLES_DIR, "benign_scientific")],
    "toxic_skills":      [os.path.join(SAMPLES_DIR, "real_corpus", "toxic_skills"),
                          os.path.join(SAMPLES_DIR, "toxic_skills")],
    "real_toxicskills":  [os.path.join(SAMPLES_DIR, "real_corpus", "real_toxicskills"),
                          os.path.join(SAMPLES_DIR, "real_toxicskills")],
    "benign_misc":       [os.path.join(SAMPLES_DIR, "real_corpus", "benign_misc"),
                          os.path.join(SAMPLES_DIR, "benign_misc")],
}


def _resolve_dir(corpus: str):
    """定位语料目录：返回 (目录路径, 是否找到)。"""
    for cand in CORPUS_CANDIDATES.get(corpus, []):
        if os.path.isdir(cand):
            return cand, True
    return None, False


def _load_labels(d: str) -> dict:
    """读取语料目录下的 _labels.json（逐文件 ground truth）。

    格式：{"<文件名>": "malicious" | "benign"}
    缺省文件时返回空 dict，调用方回退到目录级标注。
    """
    lf = os.path.join(d, "_labels.json")
    if not os.path.isfile(lf):
        return {}
    try:
        raw = json.load(open(lf, encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return raw if isinstance(raw, dict) else {}


def _load(corpus: str) -> list:
    """读取一个语料目录，返回 (name, text, meta, truth) 列表。

    truth = "malicious" | "benign"，来自 _labels.json 或目录级默认标注。
    """
    d, found = _resolve_dir(corpus)
    if not found:
        return []

    mf = os.path.join(d, "_manifest.json")
    meta_by_file = {}
    if os.path.isfile(mf):
        try:
            meta_by_file = {i["file"]: i
                            for i in json.load(open(mf, encoding="utf-8"))["items"]}
        except (OSError, ValueError):
            pass

    labels = _load_labels(d)

    items = []
    for fn in sorted(os.listdir(d)):
        if not fn.endswith(".md") or fn.startswith("_"):
            continue
        try:
            text = open(os.path.join(d, fn), encoding="utf-8").read()
        except OSError:
            continue
        truth = labels.get(fn)
        items.append((fn[:-3], text, meta_by_file.get(fn, {}), truth))
    return items


def eval_corpus(corpus: str, expect: str) -> dict:
    """评测单个语料目录。

    expect 是目录级默认标注；若 _labels.json 对某文件给出标注，
    以文件级标注为准（支持恶意/良性混装目录）。

    统计口径说明：
    - ``total``       = 该目录样本总数
    - ``mal_total``   = 其中 ground truth 为 malicious 的数量（TPR 的分母）
    - ``ben_total``   = 其中 ground truth 为 benign 的数量（FPR 的分母）
    混装目录里两类样本都要各自计入正确的分母，否则 TPR 会被稀释。
    """
    items = _load(corpus)
    if not items:
        d, found = _resolve_dir(corpus)
        if not found:
            print(f"  [跳过] {corpus} 目录不存在")
        else:
            print(f"  [跳过] {corpus} 无样本")
        return None

    tp = fp = tn = fn = 0
    mal_total = ben_total = 0
    false_positives = []      # 误报样本明细（用于分析原因）
    false_negatives = []      # 漏报样本明细
    hit_rules = Counter()
    unlabeled = 0

    for name, text, meta, truth in items:
        # 文件级 ground truth 优先；没有标注才用目录级默认
        eff_expect = truth or expect
        if not truth:
            unlabeled += 1

        res = ss.scan_skill_text(name, text)
        detected = len(res["findings"]) > 0

        if eff_expect == "malicious":
            mal_total += 1
            if detected:
                tp += 1
            else:
                fn += 1
                false_negatives.append({"name": name})
        else:
            ben_total += 1
            if detected:
                fp += 1
                false_positives.append({
                    "name": name,
                    "verdict": res["verdict"],
                    "count": len(res["findings"]),
                    "rules": sorted({f["rule"] for f in res["findings"]}),
                })
            else:
                tn += 1
        for f in res["findings"]:
            hit_rules[f["rule"]] += 1

    return {
        "corpus": corpus, "expect": expect,
        "total": len(items),
        "mal_total": mal_total, "ben_total": ben_total,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "hit_rules": hit_rules,
        "unlabeled": unlabeled,
    }


def main():
    print("=" * 76)
    print("真实语料评测 · 检出率与误报率（合并输出完整混淆矩阵）")
    print("=" * 76)
    # 🔴 2026-10-28 修正：原来打印 len(ss.RULE_TABLE)=30，但本脚本走的是
    #    ss.scan_skill_text()，实际跑的是**完整规则集**（30 条正则 + 1 条隐藏
    #    字符检测通道 + 1 条跨行组合规则 = 32 条）。写 30 会跟材料里的
    #    「32 条规则」对不上，而这份输出会原样显示在界面按钮的输出框里。
    #    口径改为直接取 stats.rule_count —— 与界面「检测规则数」指标卡同源，
    #    改一处两处一起变，不会再各算各的。
    _rule_count = ss.scan_skill_text("", "")["stats"]["rule_count"]
    print(f"规则数量：{_rule_count} 条")
    print("所有样本仅做静态分析，不执行")
    print()

    # 恶意语料（多个来源合并）
    mal_sources = [("toxic_skills", "malicious"),
                   ("real_toxicskills", "malicious")]
    mal_results = [r for r in (eval_corpus(c, e) for c, e in mal_sources) if r]

    # 良性语料（多个来源合并）
    ben_sources = [("benign_scientific", "benign"),
                   ("benign_misc", "benign")]
    ben_results = [r for r in (eval_corpus(c, e) for c, e in ben_sources) if r]

    if not mal_results and not ben_results:
        print("[错误] 未找到任何语料。")
        print("       仓库已内置 samples/real_corpus/ 全部语料，如缺失请执行：")
        print("         python samples/fetch_real_samples.py")
        return None

    # ---------- 汇总 ----------
    # 分母按 ground truth 拆分：恶意样本进 mal_total，良性样本进 ben_total。
    # 混装目录（real_toxicskills 5恶意+2良性）也能算对。
    #
    # 注意：agg() 直接对各来源的 mal_total / ben_total 求和即可，
    # 混装目录的良性样本已经由 eval_corpus 按文件级标注计入它自己的
    # ben_total，**不需要也不应该在此处再做加减**（曾因重复累加导致
    # 良性分母从 102 变成 104）。
    def agg(rs):
        return {k: sum(r[k] for r in rs)
                for k in ("total", "mal_total", "ben_total", "tp", "fp", "tn", "fn")}

    M = agg(mal_results) if mal_results else None
    B = agg(ben_results) if ben_results else None

    # 全部语料合计（用于混淆矩阵的分母）
    ALL = agg(mal_results + ben_results) if (mal_results or ben_results) else None

    if M and M["mal_total"]:
        tpr = M["tp"] / M["mal_total"] * 100
        print("【恶意样本 · 检出率】")
        for r in mal_results:
            if not r["mal_total"]:
                continue
            rate = r["tp"] / r["mal_total"] * 100
            print(f"    {r['corpus']:22s} {r['tp']:4d}/{r['mal_total']:<4d} = {rate:5.1f}%")
        print(f"    {'合计':22s} {M['tp']:4d}/{M['mal_total']:<4d} = {tpr:5.1f}%")
        fns = [x for r in mal_results for x in r.get("false_negatives", [])]
        if fns:
            print("    漏报明细：")
            for x in fns:
                print(f"      {x['name'][:50]}")
        print()

    if ALL and ALL["ben_total"]:
        fpr = ALL["fp"] / ALL["ben_total"] * 100
        specificity = ALL["tn"] / ALL["ben_total"] * 100
        print("【良性样本 · 误报率】")
        for r in ben_results + mal_results:
            if not r["ben_total"]:
                continue
            rate = r["fp"] / r["ben_total"] * 100
            tag = "(混装)" if r in mal_results else ""
            print(f"    {r['corpus'] + tag:22s} {r['fp']:4d}/{r['ben_total']:<4d} = {rate:5.1f}% 误报")
        print(f"    {'合计':22s} {ALL['fp']:4d}/{ALL['ben_total']:<4d} "
              f"= {fpr:5.1f}% 误报")
        print(f"    特异度（正确放行率） {specificity:.1f}%")
        print()

        # 误报明细——这是最需要如实展示的部分
        fps = [fp for r in ben_results for fp in r["false_positives"]]
        fps += [fp for r in mal_results for fp in r["false_positives"]]
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

    # ---------- 合并混淆矩阵 ----------
    # 全部取自 ALL（一次性求和，避免各处重复累加导致口径分裂）
    mal_n = ALL["mal_total"]
    ben_n = ALL["ben_total"]
    tp_n = ALL["tp"]
    fn_n = ALL["fn"]
    fp_n = ALL["fp"]
    tn_n = ALL["tn"]
    total = ALL["total"]
    correct = tp_n + tn_n
    if total:
        print("【合并混淆矩阵】")
        print(f"    真阳 TP {tp_n:4d}   假阴 FN {fn_n:4d}   （恶意 {mal_n} 个）")
        print(f"    假阳 FP {fp_n:4d}   真阴 TN {tn_n:4d}   （良性 {ben_n} 个）")
        print(f"    总样本 {total}    判定正确 {correct}/{total} = {correct/total*100:.1f}%")
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
    print("复现命令（语料已随仓库提供，无需联网下载）：")
    print("  python samples/run_corpus_eval.py      # 本脚本：TPR + FPR + 混淆矩阵")
    print("  python samples/verify_reproduction.py  # 一键校验：语料 + 指标 + 回归测试")
    print("=" * 76)

    return {"malicious": M, "benign": B}


if __name__ == "__main__":
    main()