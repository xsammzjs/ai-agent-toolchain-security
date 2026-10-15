"""
离线演示模式（2026-10-15 新增）
=================================
解决答辩现场断网/ 限流导致演示失败的问题。

【实测背景】
11 个真实项目重测耗时 1035 秒，且几乎每个项目都出现
`github6/osv9` 查询失败标记 —— 说明四源查询在受限网络下会大面积失败。
若答辩现场断网，界面会显示零漏洞 + 一片红字，直接导致演示失败。

【三层设计】
L1 预置数据集：4 个场景，完全离线可跑完整流程
L2 自动降级：   缓存 → 预置集 → 明确标注降级状态（绝不显示"0 漏洞"）
L3 状态披露：   界面顶部明确显示当前数据来源与降级状态（诚实，反而加分）

【关键原则】
降级时必须明确告知用户"当前为预置演示数据"，而不是伪装成正常结果。
评委看到"数据源不可用 + 已降级到预置集"会认为系统健壮；
看到"零漏洞"却不知道发生了什么，会认为系统坏了。
"""
import json
import os

# ==========================================
# 预置演示数据集（4 个场景）
# ==========================================
# 场景设计原则：每个场景演示一个明确的叙事，构成完整的答辩故事线
DEMO_SCENARIOS = {
    "scenario_1_vuln": {
        "name": "场景1 · 传统依赖漏洞检测",
        "desc": "展示四源交叉验证 + 权威置信度评级 + 修复优先级排序",
        "narration": "面对传统依赖漏洞，本系统用 OSV/NVD/GitHub 三源交叉验证，"
                     "按权威性加权评级，避免单一来源误判",
        "deps": [
            {"package": "django", "version": "3.2.1", "ecosystem": "PyPI"},
            {"package": "requests", "version": "2.25.0", "ecosystem": "PyPI"},
            {"package": "flask", "version": "2.0.0", "ecosystem": "PyPI"},
        ],
        "vulns": [
            {"cve_id": "CVE-2021-35042", "package": "django", "version": "3.2.1",
             "severity": "严重", "cvss_score": 9.8, "score_source": "NVD",
             "confidence": {"level": "高", "badge": "🟢", "detail": "NVD官方库 + 第二数据源交叉验证"},
             "fix_priority": {"priority": 1, "label": "🔴 立即修复", "urgency": "24小时内"},
             "fixed_version": "3.2.5", "cwe_id": "CWE-89",
             "summary": "Django 存在 SQL 注入漏洞，攻击者可通过特制查询窃取数据库内容",
             "evidence_links": ["https://nvd.nist.gov/vuln/detail/CVE-2021-35042"],
             "vuln_source": "OSV+NVD"},
            {"cve_id": "CVE-2023-32681", "package": "requests", "version": "2.25.0",
             "severity": "中危", "cvss_score": 6.5, "score_source": "OSV",
             "confidence": {"level": "中", "badge": "🟡", "detail": "仅 NVD 官方库确认"},
             "fix_priority": {"priority": 3, "label": "🟠 关注即可", "urgency": "近期更新"},
             "fixed_version": "2.31.0", "cwe_id": "CWE-295",
             "summary": "requests 在特定证书配置下可能绕过证书验证",
             "evidence_links": ["https://nvd.nist.gov/vuln/detail/CVE-2023-32681"],
             "vuln_source": "OSV"},
        ],
    },
    "scenario_2_malicious_skill": {
        "name": "场景2 · 恶意 Skill 静态检测",
        "desc": "展示 23 条规则 + 隐藏 Unicode 检测 + 跨行组合规则",
        "narration": "对 AI Agent 技能包做纯静态规则检测，"
                     "每条结论都给出原文行号，可直接核验，不依赖任何外部模型",
        "use_demo_skill": True,
    },
    "scenario_3_attack_chain": {
        "name": "场景3 · 跨技能攻击链关联",
        "desc": "展示本项目核心创新：把分散的单点风险连成完整攻击链",
        "narration": "传统工具只能逐个判定风险等级，无法发现「多个无害行为串成攻击链」。"
                     "本模块建立能力图，在图上搜索攻击路径——"
                     "国奖作品名单中无同类实现",
        "use_chain_demo": True,
    },
    "scenario_4_degraded": {
        "name": "场景4 · 数据源不可用时的降级",
        "desc": "展示断网/限流时系统如何优雅降级，而不是显示零漏洞",
        "narration": "答辩现场若断网，系统会明确告知『数据源不可用，已降级到预置数据集』，"
                     "而不是伪装成正常结果——诚实性本身是系统健壮性的证明",
        "force_offline": True,
    },
}


# ==========================================
# 离线数据存取
# ==========================================
DEMO_CACHE_FILE = "demo_cache.json"


def save_demo_cache(scenarios: dict, cache_file: str = DEMO_CACHE_FILE) -> str:
    """把扫描结果缓存到本地，供离线演示时读取。"""
    with open(cache_file, "w", encoding="utf-8") as f:
        json.dump(scenarios, f, ensure_ascii=False, indent=2)
    return cache_file


def load_demo_cache(cache_file: str = DEMO_CACHE_FILE) -> dict:
    """读取本地缓存；不存在返回空 dict。"""
    if not os.path.isfile(cache_file):
        return {}
    try:
        with open(cache_file, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def get_demo_scenario(key: str) -> dict:
    """按key 取预置场景。"""
    return DEMO_SCENARIOS.get(key, {})


def list_demo_scenarios() -> list:
    """列出全部预置场景，供界面下拉框使用。"""
    return [{"key": k, "name": v["name"], "desc": v.get("desc", "")}
            for k, v in DEMO_SCENARIOS.items()]


# ==========================================
# 三层降级逻辑
# ==========================================
# 数据源健康状态
SOURCE_HEALTH = {"status": "unknown", "checked_at": "", "degraded": False}


def probe_network(timeout: int = 3) -> bool:
    """探测外网连通性。返回 True/False，不抛异常。"""
    import socket
    try:
        socket.setdefaulttimeout(timeout)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("api.osv.dev", 443))
        s.close()
        return True
    except OSError:
        return False


def report_query_status(query_errors: dict) -> dict:
    """
    根据查询失败统计生成数据源健康状态，供界面披露。
    """
    if not query_errors:
        return {"status": "正常", "degraded": False, "detail": "全部数据源可用"}
    total_fail = sum(query_errors.values())
    sources = ", ".join(f"{k}×{v}" for k, v in query_errors.items())
    return {
        "status": "降级",
        "degraded": True,
        "detail": f"{sources} 查询失败（共 {total_fail} 次）",
    }


def get_offline_vulns(scenario_key: str = "scenario_1_vuln") -> dict:
    """
    离线模式获取漏洞数据：只读预置集，不发起任何网络请求。

    返回结构与在线扫描保持一致，保证界面代码无需分支。
    """
    sc = get_demo_scenario(scenario_key)
    if not sc:
        return {"dep_list": [], "vulns": [], "offline": True, "scenario": "未知场景"}
    return {
        "dep_list": sc.get("deps", []),
        "vulns": sc.get("vulns", []),
        "offline": True,
        "scenario": sc["name"],
        "narration": sc.get("narration", ""),
    }


def get_offline_skill_result(skill_root: str) -> dict:
    """
    离线模式下的 Skill 扫描 —— 本来就是纯静态规则，无需网络。
    这里只做统一封装，让界面调用方式一致。
    """
    from modules import skill_scanner
    return skill_scanner.scan_skill_package(skill_root)


def get_offline_chain_result(base_dir: str) -> dict:
    """离线模式下生成攻击链分析结果。"""
    from modules import skill_scanner
    from modules import attack_chain

    roots = attack_chain.make_attack_chain_demo(base_dir)
    results = [skill_scanner.scan_skill_package(r) for r in roots]
    chain = attack_chain.analyze_attack_chains(results)
    chain["offline"] = True
    chain["skill_results"] = results
    return chain


# ==========================================
# 界面提示文案
# ==========================================
BANNER_NORMAL = ""
BANNER_OFFLINE = (
    "⚠️ **离线演示模式** —— 当前展示的是预置数据集，"
    "用于现场断网时保证演示流程完整。系统不会显示零漏洞，"
    "因为那会误导判断。"
)
BANNER_DEGRADED = (
    "⚠️ **数据源降级** —— 部分外部查询失败，系统已切换到本地缓存与预置数据。"
    "此为设计行为：宁可明确告知降级，也不伪装成正常结果。"
)
