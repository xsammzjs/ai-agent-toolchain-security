"""
生死点验证 · 第六轮（收敛轮）：能力粒度收紧 + 真实语料复测
==========================================================
【前五轮走过的路】
R1 纯规则能力共现    → 103/107 无能力，组合只复述单点，无增量
R2 放宽能力阈值      → 19,108 条链路，假链路率 92.5%（噪声爆炸）
R3 加 AI 意图闸门    → 召回 100% / 特异度 100% / 证据可核验 100%（闸门有效）
R4 恶意×任意放大器   → 104 条链路，但绝大多数是噪声（良性科研 skill 全能当放大器）
R5 AI 判数据流关系   → 4/6，AI 判得过严（找不到显式交接点就判 FAKE）

【R4 噪声爆炸的根因】
能力粒度太粗：「文本含 https://」就算「具备外发能力」。
但科研 skill 里的网址绝大多数是**下载**（GET 拉数据），
不是**外发**（把本地数据送出去）。方向搞反了。

【本轮方案：区分「数据流向」】
  DOWNLOAD  入站：从外部拉数据（科研 skill 的正常行为，不构成威胁）
  EXFIL     出站：把本地数据送出去（这才是威胁）
  只保留 EXFIL 参与成链，DOWNLOAD 不算

同时收紧其他能力：
  READ_CRED  只有「明确读取密钥/凭据文件或环境变量」才算（不是泛泛的 api_key 字样）
  EXEC       只有「执行被内联/下载的代码或命令」才算

【要验证的】
L1. 收紧后，102 个良性科研 skill 还剩多少「外发能力」？（应该极少）
L2. 收紧后 + AI 意图闸门，真实语料上的链路质量
L3. 关键指标：假链路率必须 < 10%，同时恶意样本的链路一条不能丢
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

import config  # noqa: F401
from modules import skill_scanner as ss

SAMPLES_DIR = os.path.dirname(os.path.abspath(__file__))

# ==========================================================
# 收紧后的能力特征：区分数据流向，去掉泛化字样
# ==========================================================
CAP_PATTERNS = {
    # ---- 出站：把本地数据送出去 ----
    "EXFIL": [
        # 明确的上传接口
        (r"webhook|hooks\.slack\.com|discord\.com/api/webhooks|"
         r"pastebin\.com/api|transfer\.sh|0x0\.st|termbin|"
         r"webhook\.site|requestbin|pipedream\.net|ngrok",
         "第三方收集/中转端点"),
        # 主动 POST 本地数据
        (r"requests\.post\s*\(|requests\.put\s*\(|axios\.post\s*\(|"
         r"fetch\([^)]*method\s*:\s*['\"]POST|urllib\.request\.urlopen\([^)]*data\s*=",
         "主动 POST 本地数据"),
        # 命令行上传
        (r"curl\s+[^\n]*(-d\s|--data|-F\s|--upload-file|-T\s)|"
         r"wget\s+[^\n]*--post-|"
         r"scp\s+[^\n]*\s\w+@|rsync\s+[^\n]*\s\w+@",
         "命令行上传/传输"),
        # 上传动作 + 目标
        (r"(upload|上传|post|发送|上报|同步|镜像|备份)[^\n]{0,30}"
         r"(https?://|webhook|服务器|远端|云端|外部)",
         "上传动作带外部目标"),
    ],
    # ---- 入站：从外部拉数据（不构成威胁，仅用于对照）----
    "DOWNLOAD": [
        (r"requests\.get\s*\(|curl\s+-[a-zA-Z]*\s*https?://|wget\s+https?://|"
         r"pip\s+install|git\s+clone|npm\s+install|"
         r"ftp\.|/pub/|releases/download",
         "从外部拉取"),
    ],
    # ---- 读取凭据：必须明确指向凭据源 ----
    "READ_CRED": [
        (r"\.env\b", "读取 .env 文件"),
        (r"os\.environ\[|os\.getenv\(|process\.env\.|getenv\(", "读取环境变量"),
        (r"~/\.ssh[/\\]|id_rsa|id_ed25519|authorized_keys", "SSH 密钥/授权文件"),
        (r"~/\.aws[/\\]|\.aws/credentials|aws_secret", "云厂商凭据"),
        (r"\.npmrc|\.pypirc|\.netrc|\.git-credentials", "仓库凭据文件"),
        (r"aws_secret_access_key|access_token\s*=|api_key\s*=|"
         r"password\s*=\s*['\"]|bearer\s+[a-zA-Z0-9]{20,}",
         "硬编码/明文凭据值"),
    ],
    # ---- 执行：执行外部来源的代码或命令 ----
    "EXEC": [
        (r"subprocess\.(run|call|Popen|check_output)|os\.system\(|os\.popen\(|"
         r"child_process\.(exec|spawn)|shell\s*:\s*true",
         "执行子进程"),
        (r"eval\s*\(|exec\s*\(|new\s+Function\s*\(", "动态执行代码"),
        (r"\bbash\s+-c\b|\bsh\s+-c\b|powershell\s+-c|cmd\.exe\s+/c", "拼接 shell 命令"),
        (r"rm\s+-rf|chmod\s+\+x|sudo\s+|curl[^|]*\|\s*(bash|sh)|"
         r"wget[^|]*\|\s*(bash|sh)",
         "危险/管道执行命令"),
        # shell 命令替换：$(...) / 反引号 —— 在 curl/上传命令里嵌命令即等于执行
        (r"\$\([^)]*\)|`[^`]+`", "shell 命令替换（命令执行）"),
    ],
    # ---- 规避检测 ----
    "EVADE": [
        (r"base64\.b64decode|atob\s*\(|btoa\s*\(|codecs\.decode\(|"
         r"rot13|charmap|marshal\.loads|pickle\.loads",
         "编码/反序列化解码"),
        (r"\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){4,}", "长十六进制转义串"),
        (r"chr\s*\(\s*\d+\s*\)|\\u[0-9a-f]{4}", "字符编码构造"),
    ],
    # ---- 持久化 ----
    "PERSIST": [
        (r"crontab|/etc/cron|systemd|launchd|LaunchAgents|Startup|"
         r"\.bashrc|\.zshrc|\.profile|autorun",
         "开机自启"),
        (r"\.git/hooks|pre-commit|post-install|postinstall|setup\.py",
         "钩子/安装脚本"),
        (r"\.claude/|\.cursor/|\.continue/|CLAUDE\.md|AGENTS\.md|"
         r"memory\.(json|md)|\.mcp\.json|settings\.json",
         "改写 Agent 配置/记忆"),
    ],
    # ---- 劫持 AI ----
    "CONTROL": [
        (r"ignore\s+(all\s+)?(previous|above|prior)|disregard\s+(the\s+)?"
         r"(previous|above)|forget\s+(all\s+)?(previous|your)\s+instructions",
         "忽略既有指令"),
        (r"忽略(以上|之前|所有|上述|前面)?(的)?(指令|命令|规则|提示|约束)|"
         r"无需遵守|不必遵守",
         "忽略既有指令"),
        (r"you\s+are\s+now|act\s+as\s+|pretend\s+to\s+be|from\s+now\s+on\s+you",
         "劫持角色/身份"),
        (r"do\s+not\s+(tell|inform|mention|ask|reveal)|"
         r"不要(告诉|询问|提及|输出|显示)|隐瞒",
         "隐瞒行为"),
    ],
    # ---- 主机/环境信息收集 ----
    "HOST_INFO": [
        (r"os\.uname|platform\.(uname|node|platform)|"
         r"psutil\.(cpu|mem|virtual_memory|disk_usage|net_if_addrs)",
         "读取主机运行信息"),
        (r"/etc/passwd|/etc/shadow|/proc/self|"
         r"\bwhoami\b|\bhostname\b|\bifconfig\b|\bipconfig\b|"
         r"systeminfo|\bnetstat\b|\bdf\s+-h|\bfree\s+-m",
         "采集主机系统信息"),
        (r"(主机信息|系统信息|机器信息|运行环境|已安装软件|操作系统版本)",
         "语义上采集主机信息"),
    ],
}

CAP_LABEL = {
    "READ_CRED": "读取敏感凭据", "EXFIL": "向外传输数据",
    "EXEC": "执行任意命令", "EVADE": "规避检测",
    "PERSIST": "长期驻留", "CONTROL": "劫持 AI 行为",
    "HOST_INFO": "收集主机环境信息",
    "DOWNLOAD": "从外部拉取数据（入站，不构成威胁）",
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
    ("HOSTINFO_EXFIL", ["HOST_INFO", "EXFIL"], "严重",
     "采集主机环境信息 + 无结构外发 = 主机侦察与信息外传"),
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


def extract_caps(text):
    caps = {}
    lines = text.split("\n")
    for cap, pats in CAP_PATTERNS.items():
        for pat, desc in pats:
            rx = re.compile(pat, re.IGNORECASE)
            for i, line in enumerate(lines, 1):
                if rx.search(line):
                    caps.setdefault(cap, []).append((i, line.strip()[:110], desc))
                    break
    return caps


def main():
    r3_path = os.path.join(SAMPLES_DIR, "_probe_combo_round3.json")
    judgements = {}
    if os.path.isfile(r3_path):
        judgements = {j["name"]: j
                      for j in json.load(open(r3_path, encoding="utf-8"))["judgements"]}

    corpus = load_corpus()
    mal_names = {c[0] for c in corpus if c[2] == "malicious"}
    caps = {n: extract_caps(t) for n, t, _ in corpus}

    print("=" * 84)
    print("生死点验证 · 第六轮：能力粒度收紧后复测")
    print("=" * 84)
    print(f"样本 {len(corpus)}（恶意 {len(mal_names)}）")
    print()

    # ---------- L1 ----------
    print("【L1 · 收紧后的能力分布】")
    print("-" * 84)
    holders = {}
    for cap in CAP_PATTERNS:
        hs = [n for n, c in caps.items() if cap in c]
        holders[cap] = hs
        n_mal = sum(1 for n in hs if n in mal_names)
        print(f"  {cap:11s} {CAP_LABEL[cap][:18]:20s} {len(hs):4d} 个样本"
              f"（恶意 {n_mal}，良性 {len(hs)-n_mal}）")
    print()

    # 良性样本里还有谁具备外发能力
    ben_exfil = [n for n in holders.get("EXFIL", []) if n not in mal_names]
    print(f"  ★ 收紧后仍具备「外发」能力的良性样本：{len(ben_exfil)} 个")
    for n in ben_exfil[:15]:
        caps_n = caps[n]
        print(f"      {n[:48]:50s} 依据：{caps_n['EXFIL'][0][2]}")
        print(f"          原文行 {caps_n['EXFIL'][0][0]}: "
              f"{caps_n['EXFIL'][0][1][:88]}")
    print()

    # ---------- L2 ----------
    print("【L2 · 收紧后组合链路质量】")
    print("-" * 84)
    mal_pool = {n for n, j in judgements.items() if j["verdict"] == "MALICIOUS"}
    if not mal_pool:
        mal_pool = mal_names

    # 建模：恶意方（AI确认）提供 cap_a，另一方提供 cap_b
    chains = []
    for tid, need, sev, why in PAIR_TEMPLATES:
        cap_a, cap_b = need
        for m in sorted(mal_pool):
            if cap_a not in caps.get(m, {}):
                continue
            if cap_b in caps.get(m, {}):
                chains.append({"tid": tid, "sev": sev, "scope": "单技能",
                               "path": [m], "mal": m, "other": m,
                               "mal_cap": cap_a, "other_cap": cap_b,
                               "other_intent": judgements.get(m, {}).get("verdict", "?"),
                               "other_rules": 0})
                continue
            for other, oc in caps.items():
                if other == m or cap_b not in oc:
                    continue
                chains.append({"tid": tid, "sev": sev, "scope": "跨技能",
                               "path": [m, other], "mal": m, "other": other,
                               "mal_cap": cap_a, "other_cap": cap_b,
                               "other_intent": judgements.get(other, {}).get("verdict", "?"),
                               "other_rules": 0})

    if not chains:
        print("  （无链路）")
    else:
        fake = [c for c in chains if c["other"] not in mal_names]
        print(f"  链路总数：{len(chains)}")
        print(f"  涉恶意：{len(chains)-len(fake)}   假链路：{len(fake)}"
              f"   假链路率 {len(fake)/len(chains)*100:.1f}%")
        print()
        print("  按模板：")
        by_tid = Counter(c["tid"] for c in chains)
        for tid, need, sev, why in PAIR_TEMPLATES:
            print(f"    {tid:16s} {sev}  {by_tid.get(tid,0):4d} 条")
        print()
        print("  链路明细：")
        seen = set()
        for c in chains:
            key = (c["tid"], c["mal"], c["other"])
            if key in seen:
                continue
            seen.add(key)
            other_desc = caps[c["other"]][c["other_cap"]][2] if c["other_cap"] in caps[c["other"]] else ""
            print(f"    [{c['tid']:14s}] {c['scope']}")
            print(f"        恶意方：{c['mal'][:48]}")
            print(f"          提供「{CAP_LABEL.get(c['mal_cap'],c['mal_cap'])}」")
            print(f"        另一方：{c['other'][:48]}")
            print(f"          提供「{CAP_LABEL.get(c['other_cap'],c['other_cap'])}」"
                  f"（{other_desc}）意图 {c['other_intent']}")
    print()

    # ---------- L3 ----------
    print("【L3 · 与单点检测的对照】")
    print("-" * 84)
    rule_hits = {n: len(ss.scan_skill_text(n, t)["findings"])
                 for n, t, _ in corpus}
    single = {n for n, c in rule_hits.items() if c > 0}
    print(f"  单点（32 条规则）报警：{len(single)}/{len(corpus)} 个样本")
    print(f"    恶意 {len(mal_names & single)}/{len(mal_names)}")
    print(f"  组合分析（收紧+闸门）链路：{len(chains)} 条")
    print(f"    其中跨技能：{sum(1 for c in chains if c['scope']=='跨技能')} 条")
    print()
    print("  逐个恶意样本：")
    for m in sorted(mal_names):
        j = judgements.get(m, {})
        cs = [c for c in chains if c["mal"] == m]
        others = sorted({c["other"] for c in cs if c["other"] != m})
        print(f"    {m[:44]}")
        print(f"        规则命中 {rule_hits[m]:3d} 处 → "
              f"{'单点会报警' if m in single else '单点不报警'}"
              f" | AI 判定 {j.get('verdict','-')}")
        print(f"        组合链路 {len(cs)} 条，与 {len(others)} 个其他技能组成链")
        for o in others[:4]:
            print(f"            ＋ {o[:50]}")
    print()

    print("=" * 84)
    print("【第六轮判定】")
    print("=" * 84)
    if chains:
        fake = [c for c in chains if c["other"] not in mal_names]
        rate = len(fake) / len(chains) * 100
        print(f"  链路 {len(chains)} 条，假链路率 {rate:.1f}%")
        print(f"  {'✅ 收紧有效' if rate < 20 else '⚠️ 仍偏高'}"
              f"（阈值 < 20%）")
    else:
        print("  ✗ 收紧过头，链路归零")
    print("=" * 84)

    out = os.path.join(SAMPLES_DIR, "_probe_combo_round6.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump({
            "cap_holders": {k: v for k, v in holders.items()},
            "chains": chains,
            "chain_count": len(chains),
            "benign_exfil_holders": ben_exfil,
            "rule_hits": rule_hits,
        }, f, ensure_ascii=False, indent=2)
    print(f"数据已存：{out}")


if __name__ == "__main__":
    main()
