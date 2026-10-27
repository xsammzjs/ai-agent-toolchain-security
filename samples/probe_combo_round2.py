"""
生死点验证 · 第二轮探针：组合分析到底有没有增量价值（2026-10-26）
==================================================================
【第一轮探针暴露的问题】
现有 attack_chain 的能力提取，只吃「规则已命中」的 findings。
结果：107 个样本里 103 个完全不带能力原子，6 条链路全部由 5 个恶意样本内部产生。
→ 组合分析没有比单点检测多抓出任何东西，只是在复述。

【本轮要验证的核心假设】
「组合风险」的真实模型不是「两个危险技能凑一起」，而是：

    同一个 Agent 运行环境里，多个技能共享同一份凭据与网络出口。
    技能 A 能读凭据（自己看，只是「中危」）
    技能 B 能出网（自己看，只是「中危」）
    → 装在一起：凭据就能被读出来再送出去 = 严重

所以增量价值应该体现在：**单看每个技能都不报警，装到同一个 Agent 里才报警。**

【本轮产出三组数字】
Q1. 放宽阈值（低门槛行为特征）后，107 个样本各带哪些能力？
Q2. 「安装集模型」在 107 样本上产出多少条链路？
    - 真实语料 102 个良性 skill 同时装一起，会不会爆出几百条假链路？
Q3. 关键区分：恶意样本的链路 vs 纯良性样本的链路，特征差异在哪？
    → 如果没有差异，说明「组合分析」本身不可靠，方向要改；
       如果有差异，就是 AI 意图分诊的用武之地。

【只做静态分析，不执行任何样本内容】
"""
import io
import json
import os
import re
import sys
from collections import Counter, defaultdict

if __name__ == "__main__":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules import skill_scanner as ss

SAMPLES_DIR = os.path.dirname(os.path.abspath(__file__))

# ==========================================================
# 一、低门槛能力特征（比安全规则宽得多，模拟"AI 意图识别"能看到的东西）
#    设计原则：只要文本里出现了该行为的"动作意图"，就认为具备该能力。
#    这不是安全判定，只回答"这个技能能干什么"。
# ==========================================================
CAP_PATTERNS = {
    "READ_CRED": [
        (r"\.env\b", "读取 .env 配置文件"),
        (r"os\.environ|getenv\(|process\.env|\$ENV\{", "读取环境变量"),
        (r"~/\.ssh|id_rsa|id_ed25519|known_hosts", "访问 SSH 密钥"),
        (r"~/\.aws|\.aws/credentials", "访问 AWS 凭据"),
        (r"\.npmrc|\.pypirc|\.netrc", "访问软件包仓库凭据"),
        (r"api[_-]?key|apikey|access[_-]?token|secret[_-]?key|credential",
         "涉及 API 密钥/令牌/凭据"),
        (r"password|passwd|密码", "涉及密码"),
    ],
    "EXFIL": [
        (r"https?://", "包含外部网址"),
        (r"requests\.(post|put|patch)|fetch\(|axios\.|urllib", "发起网络请求"),
        (r"webhook|discord\.com/api/webhooks|hooks\.slack", "Webhook 通道"),
        (r"curl\s+-|wget\s+", "命令行下载/传输"),
        (r"pastebin\.com|transfer\.sh|0x0\.st|termbin", "临时粘贴站"),
        (r"upload|post to|send to|report to|上报|上报到|发送到", "上传/发送动作"),
    ],
    "EXEC": [
        (r"subprocess\.|os\.system|os\.popen|child_process|exec\(|eval\(|spawn\(",
         "执行命令/动态执行"),
        (r"\bbash\b|\bsh -c\b|powershell", "调用 shell"),
        (r"rm -rf|chmod \+x|sudo ", "危险系统命令"),
    ],
    "EVADE": [
        (r"base64|atob\(|btoa\(|codecs\.decode|rot13|charmap", "编码/混淆"),
        (r"\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){3,}", "十六进制转义串"),
        (r"chr\(|\\u[0-9a-f]{4}", "字符编码构造"),
    ],
    "PERSIST": [
        (r"crontab|systemd|\.bashrc|\.zshrc|LaunchAgents|Startup", "开机自启"),
        (r"\.git/hooks|pre-commit|post-install|postinstall", "钩子/安装脚本"),
        (r"~/.config|settings\.json|memory|CLAUDE\.md|AGENTS\.md", "改写 Agent 配置/记忆"),
    ],
    "CONTROL": [
        (r"ignore\s+(all\s+)?(previous|above)|disregard\s+(the\s+)?(previous|above)",
         "忽略既有指令"),
        (r"忽略(以上|之前|所有|上述)?(的)?(指令|命令|规则|提示)", "中文忽略指令"),
        (r"you are now|act as|pretend to be|system prompt", "劫持 AI 角色"),
        (r"do not (tell|inform|mention|ask)|不要(告诉|询问|提及)", "隐瞒行为"),
    ],
}

CAP_LABEL = {
    "READ_CRED": "读取敏感凭据", "EXFIL": "向外传输数据",
    "EXEC": "执行任意命令", "EVADE": "规避检测",
    "PERSIST": "长期驻留", "CONTROL": "劫持 AI 行为",
}

# 安装集模型下的链路模板：两个能力同时存在即可成链
PAIR_TEMPLATES = [
    ("CRED_EXFIL", ["READ_CRED", "EXFIL"], "严重",
     "读取到的凭据可被送出，密钥直接泄露"),
    ("EXEC_EXFIL", ["EXEC", "EXFIL"], "严重",
     "执行结果可被实时送出，等价于远程 shell 回传"),
    ("PERSIST_EXFIL", ["PERSIST", "EXFIL"], "严重",
     "长期驻留 + 出网 = 持续泄露通道"),
    ("CONTROL_READ", ["CONTROL", "READ_CRED"], "高危",
     "先劫持 AI 再让它去读凭据"),
    ("EVADE_EXEC", ["EVADE", "EXEC"], "高危",
     "编码隐藏后执行，对抗静态检测"),
    ("PERSIST_CONTROL", ["PERSIST", "CONTROL"], "高危",
     "写入持久配置后长期劫持 Agent"),
]


def load_corpus():
    """加载全部语料，返回 [(name, text, truth)]。"""
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


def extract_caps(text):
    """低门槛提取能力原子，返回 {cap: [(行号, 证据片段, 命中描述)]}。"""
    caps = {}
    lines = text.split("\n")
    for cap, pats in CAP_PATTERNS.items():
        for pat, desc in pats:
            rx = re.compile(pat, re.IGNORECASE)
            for i, line in enumerate(lines, 1):
                m = rx.search(line)
                if m:
                    caps.setdefault(cap, []).append(
                        (i, line.strip()[:110], desc))
                    break          # 每条模式只取第一处命中，避免刷屏
    return caps


def main():
    corpus = load_corpus()
    print("=" * 80)
    print("生死点验证 · 第二轮：组合分析的增量价值")
    print("=" * 80)
    mal = [c for c in corpus if c[2] == "malicious"]
    ben = [c for c in corpus if c[2] != "malicious"]
    print(f"样本 {len(corpus)}（恶意 {len(mal)} / 良性 {len(ben)}）")
    print()

    # ---------- Q1 ----------
    print("【Q1 · 低门槛能力特征覆盖情况】")
    print("-" * 80)
    caps_of = {}
    rule_hits = {}
    for name, text, truth in corpus:
        caps_of[name] = extract_caps(text)
        rule_hits[name] = len(ss.scan_skill_text(name, text)["findings"])

    all_caps = Counter()
    for c in caps_of.values():
        all_caps.update(c.keys())
    print("  能力原子被多少样本提供：")
    for cap, n in all_caps.most_common():
        holders = [nm for nm, c in caps_of.items() if cap in c]
        n_mal = sum(1 for nm in holders
                    if nm in {m[0] for m in mal})
        print(f"    {cap:11s} {CAP_LABEL[cap]:12s} {n:4d} 个样本"
              f"（恶意 {n_mal}，良性 {n - n_mal}）")
    zero = sum(1 for c in caps_of.values() if not c)
    print(f"  无任何能力的样本：{zero}/{len(corpus)}")
    print(f"  平均每样本能力数："
          f"{sum(len(c) for c in caps_of.values()) / len(corpus):.2f}")
    print()

    # ---------- Q2：安装集模型 ----------
    print("【Q2 · 安装集模型：把 107 个样本当成同一个 Agent 的安装集】")
    print("-" * 80)
    chains = []
    for tid, need, sev, why in PAIR_TEMPLATES:
        providers = {cap: [nm for nm, c in caps_of.items() if cap in c]
                     for cap in need}
        if any(not v for v in providers.values()):
            continue
        a, b = providers[need[0]], providers[need[1]]
        # 同一技能内部同时具备两个能力 → 单技能链路
        for nm in set(a) & set(b):
            chains.append({"tid": tid, "sev": sev, "scope": "单技能",
                           "path": [nm]})
        # 跨技能：不同技能提供两步
        for x in a:
            for y in b:
                if x != y:
                    chains.append({"tid": tid, "sev": sev, "scope": "跨技能",
                                   "path": [x, y]})
    print(f"  链路总数：{len(chains)}")
    print(f"  其中跨技能：{sum(1 for c in chains if c['scope'] == '跨技能')}")
    by_tid = Counter(c["tid"] for c in chains)
    for tid, need, sev, why in PAIR_TEMPLATES:
        print(f"    {tid:16s} {sev}  {by_tid.get(tid, 0):5d} 条")
    print()

    # ---------- Q3：真假区分 ----------
    print("【Q3 · 链路里有多少是真信号？】")
    print("-" * 80)
    mal_names = {m[0] for m in mal}
    involve_mal = [c for c in chains if set(c["path"]) & mal_names]
    pure_benign = [c for c in chains if not (set(c["path"]) & mal_names)]
    print(f"  涉及恶意样本的链路：{len(involve_mal)}")
    print(f"  纯良性样本凑出的链路：{len(pure_benign)}")
    if chains:
        print(f"  → 假链路占比：{len(pure_benign) / len(chains) * 100:.1f}%")
    print()

    # 关键：纯良性链路长什么样
    print("  纯良性链路样例（前 8 条）：")
    for c in pure_benign[:8]:
        print(f"    [{c['tid']}] {c['scope']:4s} "
              f"{' + '.join(x[:34] for x in c['path'])}")
    print()

    print("  涉及恶意的链路样例（前 8 条）：")
    for c in involve_mal[:8]:
        print(f"    [{c['tid']}] {c['scope']:4s} "
              f"{' + '.join(x[:34] for x in c['path'])}")
    print()

    # ---------- Q4：区分特征分析 ----------
    print("【Q4 · 恶意链路 vs 良性链路，特征差异】")
    print("-" * 80)
    print("  这是决定「组合分析能不能用」的关键。")
    print()

    # 4.1 能力组合的"稀有度"：良性组合里，能力对是否到处都是
    combo_count = Counter()
    for nm, c in caps_of.items():
        for i in range(len(c)):
            for j in range(i + 1, len(c)):
                combo_count[tuple(sorted((list(c)[i], list(c)[j])))] += 1
    print("  能力对在语料中的普遍度（出现在多少个样本里）：")
    for pair, n in combo_count.most_common():
        holders = [nm for nm, c in caps_of.items()
                   if set(pair) <= set(c)]
        n_mal = sum(1 for nm in holders if nm in mal_names)
        print(f"    {pair[0]:11s}+{pair[1]:11s} {n:4d} 个样本"
              f"（恶意 {n_mal}）")
    print()

    # 4.2 恶意样本 vs 良性样本的规则命中对比
    mal_rule = [rule_hits[m[0]] for m in mal]
    ben_rule = [rule_hits[b[0]] for b in ben]
    mal_with = sum(1 for x in mal_rule if x > 0)
    ben_with = sum(1 for x in ben_rule if x > 0)
    print(f"  规则命中（单点检测）：")
    print(f"    恶意样本命中数：{mal_with}/{len(mal)}")
    print(f"    良性样本命中数：{ben_with}/{len(ben)}")
    print()

    # 4.3 能力数与规则命中数的联合分布
    print("  样本按（能力数, 规则命中数）分组：")
    grid = defaultdict(lambda: [0, 0])
    for nm, c in caps_of.items():
        key = (len(c), min(rule_hits[nm], 3))
        if nm in mal_names:
            grid[key][1] += 1
        else:
            grid[key][0] += 1
    print(f"    {'能力数':>6s} {'规则命中':>10s} {'良性':>6s} {'恶意':>6s}")
    for key in sorted(grid):
        b, m = grid[key]
        flag = "  ← 恶意集中区" if m and b == 0 else ""
        print(f"    {key[0]:6d} {'0' if key[1] == 0 else '1-3' if key[1] == 3 else str(key[1]):>10s}"
              f" {b:6d} {m:6d}{flag}")
    print()

    # ---------- 结论判定 ----------
    print("=" * 80)
    print("【判定】")
    print("=" * 80)
    fake_ratio = len(pure_benign) / len(chains) * 100 if chains else 0
    if fake_ratio > 50:
        print("  ✗ 假链路占比过高 → 单纯靠能力共现做组合，会被良性语料淹没")
        print("    → 必须引入「意图分诊」：AI 判断每个技能的行为意图，")
        print("      只在「意图确实指向恶意」时才成链")
        print(f"    → 实测：{len(pure_benign)}/{len(chains)} = {fake_ratio:.1f}% 假链路")
    else:
        print(f"  ✓ 假链路占比 {fake_ratio:.1f}%，组合信号可用")
        print(f"    → 实测：{len(pure_benign)}/{len(chains)} 假链路")

    # 落盘
    out = os.path.join(SAMPLES_DIR, "_probe_combo_round2.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump({
            "total": len(corpus),
            "malicious": len(mal),
            "capability_holders": {cap: [nm for nm, c in caps_of.items()
                                         if cap in c]
                                   for cap in all_caps},
            "chain_count": len(chains),
            "involve_malicious": len(involve_mal),
            "pure_benign": len(pure_benign),
            "rule_hits": rule_hits,
            "caps": {nm: {k: [list(x) for x in v] for k, v in c.items()}
                     for nm, c in caps_of.items()},
        }, f, ensure_ascii=False, indent=2)
    print(f"  数据已存：{out}")
    print("=" * 80)


if __name__ == "__main__":
    main()
