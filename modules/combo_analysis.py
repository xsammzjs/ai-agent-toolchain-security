# -*- coding: utf-8 -*-
"""组合分析层（三段式架构 · 阶段C 的能力提取与成链逻辑）

【来源与定位】
本模块的 CAPABILITY_PATTERNS / extract_caps / PAIR_TEMPLATES / build_chains
均从验证探针 samples/probe_combo_round6.py 与 samples/probe_final_eval.py
原样迁移。探针实测（数字见 samples/_probe_final.json，可复现）：
13 个多技能场景 13/13 全对（TP 6 / TN 7）；107 个真实语料产出 139 条
组合链路，恶意端全部落在 5 个已知恶意样本内，其中 135 条集中在
gemini__skills__vercel__SKILL 一个样本的 1×N 配对。
本模块是纯函数层：只做文本 → 能力原子 → 攻击链的推导，除读入参数文本外
不做任何 IO，也不调用任何大模型（AI 意图分诊在 modules/adjudicator.py）。

【三段式架构中的位置】
  阶段A 规则快筛  → modules/skill_scanner.py（32 条规则，单点检测）
  阶段B AI 分诊   → modules/adjudicator.py 的 judge_skill_combined()
  阶段C 组合判定  → 本模块 extract_caps() + build_chains()

【三要素成链逻辑（build_chains 的判定依据）】
单点检测回答不了「这些技能凑在一起会怎样」。两个技能单独看都可能人畜无害，
组合起来却能凑齐一条完整攻击链。成链必须同时满足三要素：

  1. 能力互补 —— 两个技能（或同一技能内部）凑齐模板要求的两项危险能力
     （如「读取凭据」+「向外传输」= 凭据外泄链）。
  2. 意图闸门 —— 至少一方被 AI 分诊判为 MALICIOUS / SUSPICIOUS。
     唯一例外是 HOSTINFO_EXFIL：两端都正常时，「采集主机信息 + 无结构外发」
     本身就是需要人看一眼的组合（软闸门 soft）。
  3. 外发闸门 —— 提供外发（EXFIL）能力的一方，其外发范围必须是 GENERIC。
     STRUCTURED 通道只发固定字段（如搜索词、耗时毫秒数），带不走凭据；
     GENERIC 通道发的是"处理好的结果""收集到的数据"这类无边界内容，
     会把会话里的一切（含其他技能刚读出的密钥）打包带走。

  注意：能力角色不固定。危险方可能提供「读凭据」，也可能提供「外发」，
  两边都要试（x 提供 cap_a / y 提供 cap_b 与对调两种方向都会检查）。
"""
import re

# ==========================================================
# 一、能力原子特征（来自 probe_combo_round6 的 CAP_PATTERNS）
# ==========================================================
# 收紧后的能力特征：区分数据流向（DOWNLOAD 入站不算威胁，EXFIL 出站才算），
# 去掉泛化字样（不是文本含 https:// 就算具备外发能力）。
# 每条为 (正则, 依据说明)；同一能力下任一正则命中即认定具备该能力。
CAPABILITY_PATTERNS = {
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

# 能力原子的中文标签（界面展示用）
CAPABILITY_LABELS = {
    "READ_CRED": "读取敏感凭据", "EXFIL": "向外传输数据",
    "EXEC": "执行任意命令", "EVADE": "规避检测",
    "PERSIST": "长期驻留", "CONTROL": "劫持 AI 行为",
    "HOST_INFO": "收集主机环境信息",
    "DOWNLOAD": "从外部拉取数据（入站，不构成威胁）",
}

# ==========================================================
# 二、跨技能链路模板（来自 probe_combo_round6 的 PAIR_TEMPLATES）
# ==========================================================
# 每条为 (模板ID, [能力A, 能力B], 严重度, 成链依据)。
# 能力A/B 只是模板槽位：成链时两个方向都会尝试（见 build_chains）。
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


# ==========================================================
# 三、能力提取（阶段A → 阶段C 的桥）
# ==========================================================
def extract_caps(text: str) -> dict:
    """从技能正文提取危险能力原子。

    返回 {能力名: [{"line": 行号, "text": 原文截断, "why": 依据}]}。
    每条正则只记录首个命中行（与探针 extract_caps 保持一致，
    避免同一模式在长文里刷屏，行号足够人工核验）。
    """
    caps: dict = {}
    lines = text.split("\n")
    for cap, pats in CAPABILITY_PATTERNS.items():
        for pat, desc in pats:
            rx = re.compile(pat, re.IGNORECASE)
            for i, line in enumerate(lines, 1):
                if rx.search(line):
                    caps.setdefault(cap, []).append(
                        {"line": i, "text": line.strip()[:110], "why": desc})
                    break
    return caps


# ==========================================================
# 四、组合判定（阶段C：三要素成链）
# ==========================================================
def build_chains(skills, caps: dict, intents: dict) -> list:
    """按「能力互补 × 意图闸门 × 外发闸门」三要素成链。

    参数:
        skills  —— 技能名列表（参与组合判定的范围）
        caps    —— {技能名: extract_caps() 的返回值}
        intents —— {技能名: AI 分诊结果 dict}，用到 verdict / reason / scope
                   三个字段；缺技能视为无 AI 意图（过不了意图闸门）

    返回链路列表，每条含:
        tid（模板ID）/ sev（严重度）/ why（依据）/ scope（单技能|跨技能）/
        mal（意图更恶劣一方）/ other（另一方）/ mal_cap / other_cap /
        other_scope / mal_reason / other_reason
    """
    chains = []
    for tid, need, sev, why in PAIR_TEMPLATES:
        cap_a, cap_b = need
        soft = (tid == "HOSTINFO_EXFIL")
        for x in skills:
            x_caps = caps.get(x, {})
            if cap_a not in x_caps:
                continue
            xi = intents.get(x, {})
            # x 提供 cap_a，y 提供 cap_b
            for y in skills:
                y_caps = caps.get(y, {})
                if cap_b not in y_caps:
                    continue
                yi = intents.get(y, {})
                if x == y:
                    # 单技能内部同时具备两项能力
                    if cap_b == "EXFIL" and yi.get("scope") != "GENERIC":
                        continue
                    if not soft and xi.get("verdict") not in ("MALICIOUS",
                                                             "SUSPICIOUS"):
                        continue
                    chains.append({
                        "tid": tid, "sev": sev, "why": why, "scope": "单技能",
                        "mal": x, "other": x,
                        "mal_cap": cap_a, "other_cap": cap_b,
                        "other_scope": yi.get("scope", "?"),
                        "mal_reason": xi.get("reason", ""),
                        "other_reason": yi.get("reason", ""),
                    })
                    continue
                # 意图闸门：至少一方恶意/可疑
                x_bad = xi.get("verdict") in ("MALICIOUS", "SUSPICIOUS")
                y_bad = yi.get("verdict") in ("MALICIOUS", "SUSPICIOUS")
                if not (x_bad or y_bad) and not soft:
                    continue
                # 外发闸门
                if cap_b == "EXFIL" and yi.get("scope") != "GENERIC":
                    continue
                # 危险方 = 意图更恶劣的一方
                mal, oth = (x, y) if x_bad else (y, x)
                mal_cap = cap_a if mal == x else cap_b
                oth_cap = cap_b if oth == y else cap_a
                chains.append({
                    "tid": tid, "sev": sev, "why": why, "scope": "跨技能",
                    "mal": mal, "other": oth,
                    "mal_cap": mal_cap, "other_cap": oth_cap,
                    "other_scope": yi.get("scope", "?"),
                    "mal_reason": intents.get(mal, {}).get("reason", ""),
                    "other_reason": intents.get(oth, {}).get("reason", ""),
                })
    return chains
