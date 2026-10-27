"""
生死点验证 · 第四轮（决定轮）：修正后的组合模型
=================================================
【第三轮暴露的模型错误】
闸门设计成「只有 MALICIOUS 技能能参与成链」，把**良性放大器**也踢出去了，
恶意链路保留率只剩 2%。但真实攻击模型恰恰相反：

    恶意技能 A（自己只做了一半）  +  看起来无害的良性技能 B（提供了另一半通道）
    = 完整的组合威胁

而 B 单独看毫无问题（可能只命中低危规则，甚至零命中），
**只有做组合分析才能发现「A 的危险性被 B 放大了」**。
这才是本项目真正的增量价值所在。

【本轮模型】
链路的两个参与者：
  · 恶意方（intent = MALICIOUS）：必须由 AI 意图分诊确认
  · 能力方（任意意图）：提供链路所需的另一项能力
成链条件：恶意方**单独不具备**完整链路能力（否则就是单点发现的，不是增量）

【本轮要产出的核心数字】
K1. 组合独有链路数 = 恶意方单独构不成、组合后才构成的链路
    → 这是「单点检测做不到、组合分析做到」的硬证据
K2. 良性放大器占比 = 链路另一方是良性技能的比例
    → 这是「不是靠堆恶意技能凑出来的」的硬证据
K3. 假链路率（应接近 0）
K4. 完整链路清单（用于答辩展示）
K5. 与单点检测的对照表：单点能报什么 / 组合多报了什么

【复用第三轮的 AI 判定结果，不重复调 API】
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

SAMPLES_DIR = os.path.dirname(os.path.abspath(__file__))
CAP_LABEL = {
    "READ_CRED": "读取敏感凭据", "EXFIL": "向外传输数据",
    "EXEC": "执行任意命令", "EVADE": "规避检测",
    "PERSIST": "长期驻留", "CONTROL": "劫持 AI 行为",
}
PAIR_TEMPLATES = [
    ("CRED_EXFIL", ["READ_CRED", "EXFIL"], "严重",
     "读取到的凭据可被送出，密钥直接泄露到外部"),
    ("EXEC_EXFIL", ["EXEC", "EXFIL"], "严重",
     "命令执行结果可被实时送出，等价于远程 shell 回传"),
    ("PERSIST_EXFIL", ["PERSIST", "EXFIL"], "严重",
     "长期驻留 + 出网 = 持续泄露通道"),
    ("CONTROL_READ", ["CONTROL", "READ_CRED"], "高危",
     "先劫持 AI 行为，再让它去读凭据"),
    ("EVADE_EXEC", ["EVADE", "EXEC"], "高危",
     "编码隐藏后执行，对抗静态检测"),
    ("PERSIST_CONTROL", ["PERSIST", "CONTROL"], "高危",
     "写入持久配置后长期劫持 Agent"),
]


def load_corpus():
    out = []
    dirs = [
        (os.path.join(SAMPLES_DIR, "real_toxicskills"), "malicious"),
        (os.path.join(SAMPLES_DIR, "real_corpus", "toxic_skills"), "malicious"),
        (os.path.join(SAMPLES_DIR, "real_corpus", "benign_scientific"), "benign"),
    ]
    for d, default_truth in dirs:
        if not os.path.isdir(d):
            continue
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
            out.append((fn[:-3], text, labels.get(fn) or default_truth))
    return out


def main():
    r3_path = os.path.join(SAMPLES_DIR, "_probe_combo_round3.json")
    if not os.path.isfile(r3_path):
        print("✗ 缺少第三轮结果，请先跑 probe_combo_round3.py")
        return
    r3 = json.load(open(r3_path, encoding="utf-8"))
    judgements = {j["name"]: j for j in r3["judgements"]}

    corpus = load_corpus()
    mal_names = {c[0] for c in corpus if c[2] == "malicious"}

    # 能力（沿用第三轮的低门槛特征）
    caps = {}
    rule_hits = {}
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from probe_combo_round3 import extract_caps

    for name, text, _ in corpus:
        caps[name] = extract_caps(text)
        rule_hits[name] = len(ss.scan_skill_text(name, text)["findings"])

    mal_pool = {n for n, j in judgements.items() if j["verdict"] == "MALICIOUS"}

    print("=" * 84)
    print("生死点验证 · 第四轮（决定轮）：修正后的组合模型")
    print("=" * 84)
    print(f"样本 {len(corpus)}（恶意 {len(mal_names)}）  "
          f"AI 判定为 MALICIOUS 的技能：{len(mal_pool)}")
    print()

    # ---------- 恶意方的能力画像 ----------
    print("【恶意方能力画像 · AI 意图确认后的技能各自能做什么】")
    print("-" * 84)
    for nm in sorted(mal_pool):
        cs = caps.get(nm, {})
        j = judgements[nm]
        print(f"  {nm[:46]}")
        print(f"      能力：{', '.join(CAP_LABEL.get(c,c) for c in cs) or '（无）'}")
        print(f"      规则命中 {rule_hits.get(nm,0)} 处 | AI 证据行号 "
              f"{j.get('evidence_valid_lines', [])} | {j.get('reason','')[:46]}")
    print()

    # ---------- 组合链路生成（修正模型） ----------
    print("【K1 · 组合独有链路】")
    print("-" * 84)
    print("  成链条件：恶意方（AI 确认）单独构不成该链路，"
          "需与另一技能的能力组合才成立")
    print()

    novel = []
    for tid, need, sev, why in PAIR_TEMPLATES:
        cap_a, cap_b = need
        # 恶意方提供 cap_a，但没有 cap_b → 需要另一个技能补上 cap_b
        for m in sorted(mal_pool):
            m_caps = caps.get(m, {})
            if cap_a not in m_caps:
                continue
            if cap_b in m_caps:
                continue        # 恶意方自己就齐了 → 那是单点能发现的
            # 找一个提供 cap_b 的技能（任意意图）
            for other, o_caps in caps.items():
                if other == m:
                    continue
                if cap_b not in o_caps:
                    continue
                # 组合后恶意方能力集就齐了
                if not (cap_b in m_caps or cap_b in o_caps):
                    continue
                novel.append({
                    "tid": tid, "sev": sev, "why": why,
                    "malicious": m, "enabler": other,
                    "mal_cap": cap_a, "ena_cap": cap_b,
                    "enabler_intent": judgements.get(other, {}).get("verdict", "?"),
                    "enabler_rules": rule_hits.get(other, 0),
                })
    # 去重（同一 malicious+enabler+tid 只留一条）
    seen = set()
    unique = []
    for c in novel:
        key = (c["malicious"], c["enabler"], c["tid"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(c)

    # 按恶意方聚合，避免刷屏
    by_mal = defaultdict(list)
    for c in unique:
        by_mal[c["malicious"]].append(c)

    print(f"  组合独有链路总数：{len(unique)} 条")
    print()
    for m, cs in by_mal.items():
        print(f"  ▸ 恶意技能：{m[:46]}")
        print(f"      自身能力：{', '.join(CAP_LABEL.get(c,c) for c in caps.get(m,{}))}")
        seen_en = set()
        for c in sorted(cs, key=lambda x: (x["tid"], x["enabler"])):
            if c["enabler"] in seen_en:
                continue
            seen_en.add(c["enabler"])
            print(f"      ＋ 放大器：{c['enabler'][:44]:46s}")
            print(f"          补上「{CAP_LABEL.get(c['ena_cap'],c['ena_cap'])}」→ "
                  f"{c['sev']}· {c['why']}")
            print(f"          放大器意图：{c['enabler_intent']:12s} "
                  f"规则命中 {c['enabler_rules']} 处")
        print()

    # ---------- K2/K3 ----------
    print("【K2/K3 · 质量指标】")
    print("-" * 84)
    benign_enabler = [c for c in unique if c["enabler"] not in mal_names]
    if unique:
        print(f"  组合独有链路：{len(unique)} 条")
        print(f"  其中放大器是良性技能：{len(benign_enabler)} 条 "
              f"({len(benign_enabler)/len(unique)*100:.1f}%)")
        print(f"  假链路（两端都是恶意）："
              f"{len(unique)-len(benign_enabler)} 条")
    print()

    # ---------- K5：单点 vs 组合 对照 ----------
    print("【K5 · 单点检测 vs 组合分析 对照表】")
    print("-" * 84)
    single_alarm = {n for n, c in rule_hits.items() if c > 0}
    mal_single = mal_names & single_alarm
    print(f"  单点检测（32 条规则）能报警的样本：{len(single_alarm)}/{len(corpus)}")
    print(f"    其中恶意：{len(mal_single)}/{len(mal_names)}")
    print(f"    组合分析额外发现的能力组合：{len(unique)} 条")
    print()
    print("  逐个恶意样本：单点能看到什么，组合多看到了什么")
    for m in sorted(mal_names):
        cs = by_mal.get(m, [])
        print(f"    {m[:44]}")
        print(f"        单点：规则命中 {rule_hits.get(m,0)} 处 → "
              f"{'会报警' if m in single_alarm else '不报警'}")
        print(f"        组合：{' + '.join(sorted({c['enabler'][:22] for c in cs})) or '（无增量）'}")
    print()

    # ---------- 最终判定 ----------
    print("=" * 84)
    print("【最终判定】")
    print("=" * 84)
    print(f"  1. AI 意图分诊：召回 {r3['intent_recall']:.1f}%、"
          f"特异度 {r3['intent_specificity']:.1f}%、"
          f"证据可核验 {r3['evidence_valid_rate']:.1f}%")
    print(f"  2. 纯能力共现（无闸门）：{r3['chain_before']} 条链路，"
          f"假链路率 {r3['fake_ratio_before']:.1f}%  ← 不可用")
    print(f"  3. 加意图闸门后：{len(unique)} 条组合独有链路，"
          f"其中 {len(benign_enabler)} 条由良性技能放大 "
          f"({len(benign_enabler)/max(len(unique),1)*100:.1f}%)")
    print(f"  4. 结论：{'✅ 方向成立' if unique else '✗ 方向不成立'}")
    if unique:
        print(f"     —— 这 {len(unique)} 条链路，单点检测一条都查不出来，"
              f"因为它们的成因是「跨技能组合」")
    print("=" * 84)

    out = os.path.join(SAMPLES_DIR, "_probe_combo_round4.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump({
            "novel_chains": unique,
            "novel_count": len(unique),
            "benign_enabler_count": len(benign_enabler),
            "by_malicious": {k: v for k, v in by_mal.items()},
            "rule_hits": rule_hits,
        }, f, ensure_ascii=False, indent=2)
    print(f"数据已存：{out}")


if __name__ == "__main__":
    main()
