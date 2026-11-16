"""
资产图谱构建（2026-10-15 新增）
================================
把「依赖包」「Skill」「MCP 工具」统一建模为资产节点，把它们之间的
关系建成边。这是攻击链分析的存储载体，也是赛题 1 要求 RDS 承载的对象。

【为什么要有这一层】
赛题 1 要求「关联 RDS、REDIS」，但「存什么」必须先想清楚。
如果只是把扫描结果存成一张结果表，那是「日志存储」不是「资产认知」——
跟赛题 1 强调的「多模态异构数据资产统一识别与资产标识」不匹配。

本模块的定位：**把异构资产统一成一张图。**
- 传统依赖包（PyPI/npm）→ node_type = "依赖"
- AI Agent 技能包（SKILL.md）→ node_type = "技能"
- MCP 工具服务 → node_type = "工具"

三者共用一套节点/边 schema，因此可以在同一张图上做关联分析——
这正是「把传统依赖与 AI 技能统一到一张图上」的数据基础。

【与 attack_chain 的关系】
attack_chain.py 关注「单个技能包内部的能力链」（规则级），
本模块关注「跨资产的图结构」（资产级）。
两者互补：前者回答「这个技能怎么作案」，后者回答「整个系统的资产图长什么样、
哪些资产是关键节点」。
"""
from __future__ import annotations

import hashlib
import re
from typing import Optional

# ==========================================================
# 节点类型与关系类型定义
# ==========================================================
NODE_TYPES = {
    "依赖": {"icon": "📦", "desc": "传统软件供应链中的依赖包"},
    "技能": {"icon": "🧩", "desc": "AI Agent 技能包（SKILL.md）"},
    "工具": {"icon": "🔧", "desc": "MCP 工具服务 / 外部 API"},
}

EDGE_TYPES = {
    "依赖": {"weight": 1.0, "desc": "A 依赖 B（包管理关系）"},
    "调用": {"weight": 1.5, "desc": "A 在运行时调用 B（更危险）"},
    "引用": {"weight": 0.5, "desc": "A 引用了 B 的内容但未执行"},
    "共用": {"weight": 0.8, "desc": "A 与 B 共用同一外部通道（如同一外带站）"},
}


def _nid(node_type: str, name: str, version: str = "") -> str:
    """稳定的节点 ID：同样的资产在多次扫描中必须得到同一个 ID。"""
    raw = f"{node_type}|{name}|{version}"
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


# ==========================================================
# 技能正文 → 第三方依赖名（纯本地正则，不联网）
# ==========================================================
_DEP_PATTERNS = [
    re.compile(r"pip3?\s+install\s+([^\n&|;]+)", re.I),
    re.compile(r"npm\s+(?:install|i)\s+([^\n&|;]+)", re.I),
    re.compile(r"(?:apt|apt-get)\s+install\s+([^\n&|;]+)", re.I),
]

# 英文说明用词 —— 出现在依赖声明同一行里，但不是包名。
# 典型场景：SKILL.md 里写
#   `uv pip install "aeon==1.6.0" stumpy`. Range precision/recall/F-score
#   depend on `prts`, whose current NumPy<2 requires ...
# 旧实现按空格切词，把这句说明里的每个单词都当成了依赖包。
_DEP_STOPWORDS = frozenset("""
on with whose whom whose depend depends depending dependency dependencies
requirement requirements require requires required current currently conflicts conflict
and or the for from to in of is are be been being as at by not no but can could will
would shall should may might must use used using uses need needs needed please see
also when then than that this these those it its if so all any only more most much
such which while via etc into over under after before between both each few other
some own same too very just now here there what where who whom how why did does done
""".split())

# 常见「首字母大写」的第三方库名（小写形式）。
# 首字母大写的词只有在表里才算包名 —— 这样 NumPy/TensorFlow 保留，
# 而说明文字里的 Range、Recall 这类词会被排除。
_DEP_KNOWN_UPPER = frozenset("""
numpy pandas sklearn scipy torch tensorflow matplotlib seaborn requests pillow flask
django pytorch polars statsmodels networkx pyvis sqlalchemy fastapi uvicorn pytest
setuptools wheel pip keras jupyter tabutils six attrs
""".split())


def _looks_like_dep_pkg(tok: str) -> bool:
    """判断一个 token 是否像第三方包名（而不是正文说明里的英文词）。

    PyPI / npm 包名规范：字母或数字开头，可含 . _ -，不含 /；
    多数为小写，或属于已知的大写库名。
    """
    if not tok or len(tok) < 3:
        return False
    if tok.lower() in _DEP_STOPWORDS:
        return False
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*$", tok):
        return False
    if tok.replace(".", "").replace("-", "").isdigit():
        return False
    if tok[0].isupper():
        return tok.lower() in _DEP_KNOWN_UPPER
    return bool(re.search(r"[-_.]", tok)) or len(tok) >= 3


def _extract_dep_names(text: str) -> list:
    """从技能正文提取「声称安装」的第三方包名（去版本号，纯本地、不联网）。

    只为「技能 → 依赖」建模用；不查 PyPI、不查 CVE——线上网络波动不影响建图。

    切分策略（2026-11-16 修正）：
      1) 先按标点把捕获段切成「片段」——说明文字通常被逗号/句号隔开；
      2) 再按空格切词；
      3) 每个词过包名合法性校验（停用词 / 纯数字 / 含 / / 首字母大写需在白名单）。
    旧实现直接按空格切整段，会把说明文字里的每个单词当成依赖包，
    导致关系图出现 on / with / whose / current 等假节点。
    """
    out: list = []
    for rx in _DEP_PATTERNS:
        for m in rx.finditer(text or ""):
            for frag in re.split(r"[,;、，；:：]+", m.group(1)):
                for tok in frag.split():
                    tok = tok.strip().strip("'\"`")
                    if not tok or tok.startswith(("-", ".", "http")):
                        continue
                    pkg = re.split(r"[<>=!~\[\]`'\"]", tok)[0].strip().rstrip(".,;:")
                    if pkg and _looks_like_dep_pkg(pkg) and pkg not in out:
                        out.append(pkg)
    return out


# ==========================================================
# 构建
# ==========================================================
def build_graph(dep_list: Optional[list] = None,
                skill_results: Optional[list] = None,
                chain_result: Optional[dict] = None,
                skill_texts: Optional[dict] = None,
                vulns: Optional[list] = None) -> dict:
    """
    构建资产图谱。

    参数:
        dep_list     —— 依赖列表 [{"package","version","ecosystem"}, ...]
        skill_results—— scan_skill_package() 的结果列表
        chain_result —— analyze_attack_chains() 的结果，用于补充攻击链边

    返回: {"nodes": [...], "edges": [...], "stats": {...}}
          node 结构：{"node_id","node_type","name","version","severity",
                      "risk_count","meta"}
          edge 结构：{"src","dst","relation","weight","meta"}
    """
    nodes: dict = {}
    edges: list = []
    seen_edge: set = set()

    def _add_node(node_type: str, name: str, version: str = "",
                  severity: str = "安全", risk_count: int = 0,
                  meta: Optional[dict] = None) -> str:
        nid = _nid(node_type, name, version)
        if nid not in nodes:
            nodes[nid] = {
                "node_id": nid,
                "node_type": node_type,
                "name": name,
                "version": version,
                "severity": severity,
                "risk_count": risk_count,
                "meta": meta or {},
            }
        else:
            # 同名资产再次出现，合并风险信息（取更严重的）
            prev = nodes[nid]
            if risk_count > prev["risk_count"]:
                prev["risk_count"] = risk_count
                prev["severity"] = severity
        return nid

    def _add_edge(src: str, dst: str, relation: str, meta: Optional[dict] = None):
        key = (src, dst, relation)
        if key in seen_edge or src == dst:
            return
        seen_edge.add(key)
        edges.append({
            "src": src, "dst": dst, "relation": relation,
            "weight": EDGE_TYPES.get(relation, {}).get("weight", 1.0),
            "meta": meta or {},
        })

    # ---------- 1. 依赖节点 ----------
    dep_nodes: dict = {}
    for d in dep_list or []:
        name = d.get("package") or d.get("name") or ""
        if not name:
            continue
        ver = d.get("version", "")
        nid = _add_node("依赖", name, ver,
                        meta={"ecosystem": d.get("ecosystem", "PyPI"),
                              "is_transitive": d.get("is_transitive", False)})
        dep_nodes[f"{name}|{ver}"] = nid

    # ---------- 2. 依赖内部关系（同包不同版本视为升级关系） ----------
    by_name: dict = {}
    for d in dep_list or []:
        nm = (d.get("package") or "").lower()
        if nm:
            by_name.setdefault(nm, []).append(
                (_add_node("依赖", d.get("package", ""), d.get("version", ""),
                           meta={"ecosystem": d.get("ecosystem", "PyPI")}),
                 d.get("version", "")))
    for nm, items in by_name.items():
        if len(items) > 1:
            # 同名多版本 → 建立「依赖」边（升级/并存关系）
            items_sorted = sorted(items, key=lambda x: x[1])
            for i in range(len(items_sorted) - 1):
                _add_edge(items_sorted[i][0], items_sorted[i + 1][0], "依赖",
                          {"reason": "同名不同版本并存"})

    # ---------- 3. Skill 节点 ----------
    skill_nodes: dict = {}
    for r in skill_results or []:
        name = r.get("skill_name", "unknown")
        nid = _add_node("技能", name, "",
                        severity=r.get("verdict", "安全"),
                        risk_count=len(r.get("findings", [])),
                        meta={"files": r.get("files", 0)})
        skill_nodes[name] = nid

        # Skill → 依赖边：技能使用到的凭据/外带通道视为关联依赖
        for f in r.get("findings", []):
            cat = f.get("category")
            ev = (f.get("evidence") or "")
            if cat == "凭证窃取":
                # 抽取出被读取的凭据类型作为依赖节点
                for key, label in ((".env", "环境变量文件"), ("credentials", "云凭据"),
                                   (".aws", "AWS凭据"), ("id_rsa", "SSH私钥"),
                                   ("API_KEY", "API密钥"), ("TOKEN", "访问令牌")):
                    if key.lower() in ev.lower():
                        cred = _add_node("依赖", f"凭据:{label}", "",
                                         meta={"is_credential": True})
                        _add_edge(nid, cred, "调用",
                                  {"rule": f.get("rule"),
                                   "line": f.get("line"),
                                   "reason": f"技能会读取{label}"})
                        break
            elif cat == "数据外发":
                for host in ("pastebin", "interact.sh", "ngrok", "requestbin",
                             "rentry.co", "webhook.site", "hastebin", "0x0.st"):
                    if host in ev.lower():
                        ext = _add_node("工具", f"外带通道:{host}", "",
                                        meta={"is_exfil_channel": True})
                        _add_edge(nid, ext, "调用",
                                  {"rule": f.get("rule"),
                                   "line": f.get("line"),
                                   "reason": f"技能通过{host} 外发数据"})
                        break

    # ---------- 3b. 技能 → 依赖 边（从 SKILL.md 提取，纯本地、不联网） ----------
    if skill_texts:
        for name, text in skill_texts.items():
            sn = skill_nodes.get(name)
            if not sn or not text:
                continue
            for pkg in _extract_dep_names(text):
                dn = _add_node("依赖", pkg, "",
                               meta={"ecosystem": "PyPI", "declared_by": name})
                _add_edge(sn, dn, "依赖",
                          {"reason": f"技能声明依赖 {pkg}", "ecosystem": "PyPI"})

    # ---------- 3c. 依赖 → CVE 边（来自依赖漏洞扫描结果；纯本地推断，不联网） ----------
    for v in vulns or []:
        pkg = v.get("package") or ""
        cve = v.get("cve_id") or ""
        if not pkg or not cve:
            continue
        dep_nid = dep_nodes.get(f"{pkg}|{v.get('version', '')}")
        if dep_nid is None:
            dep_nid = _add_node("依赖", pkg, v.get("version", ""),
                                meta={"ecosystem": "PyPI"})
        cve_nid = _add_node("工具", f"CVE:{cve}", "",
                            severity=v.get("severity", "中危"),
                            meta={"is_cve": True, "cvss": v.get("cvss_score", 0)})
        _add_edge(dep_nid, cve_nid, "引用",
                  {"cve_id": cve, "severity": v.get("severity", "")})

    # ---------- 4. 攻击链边（跨资产的实际攻击路径） ----------
    if chain_result:
        for ch in chain_result.get("chains", []):
            steps = ch.get("steps", [])
            for i in range(len(steps) - 1):
                a = skill_nodes.get(steps[i].get("skill", ""))
                b = skill_nodes.get(steps[i + 1].get("skill", ""))
                if a and b:
                    _add_edge(a, b, "调用", {
                        "chain_id": ch.get("chain_id"),
                        "chain_name": ch.get("chain_name"),
                        "severity": ch.get("severity"),
                        "via": steps[i].get("cap_label"),
                        "at_line": steps[i].get("line"),
                    })

    # ---------- 5. 统计 ----------
    node_list = list(nodes.values())
    by_type: dict = {}
    by_sev: dict = {}
    for n in node_list:
        by_type[n["node_type"]] = by_type.get(n["node_type"], 0) + 1
        by_sev[n["severity"]] = by_sev.get(n["severity"], 0) + 1

    # 关键节点：被引用次数最多（可能是被依赖最多的资产）
    in_degree: dict = {}
    for e in edges:
        in_degree[e["dst"]] = in_degree.get(e["dst"], 0) + 1
    top_nodes = sorted(node_list,
                       key=lambda n: (-in_degree.get(n["node_id"], 0),
                                      -n["risk_count"]))[:10]

    return {
        "nodes": node_list,
        "edges": edges,
        "stats": {
            "total_nodes": len(node_list),
            "total_edges": len(edges),
            "by_type": by_type,
            "by_severity": by_sev,
            "high_risk_nodes": [n for n in node_list
                                if n["severity"] in ("严重", "高危")],
            "key_nodes": [
                {"name": n["name"], "type": n["node_type"],
                 "in_degree": in_degree.get(n["node_id"], 0),
                 "risk_count": n["risk_count"]}
                for n in top_nodes
            ],
        },
    }


if __name__ == "__main__":
    import sys, os, tempfile, shutil
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    from modules.skill_scanner import scan_skill_package, make_demo_package
    from modules.attack_chain import make_attack_chain_demo, analyze_attack_chains

    print("=" * 68)
    print("资产图谱构建自检")
    print("=" * 68)

    deps = [
        {"package": "django", "version": "3.2.1", "ecosystem": "PyPI"},
        {"package": "requests", "version": "2.25.0", "ecosystem": "PyPI"},
        {"package": "django", "version": "4.2.0", "ecosystem": "PyPI"},
    ]

    d = tempfile.mkdtemp()
    try:
        roots = make_attack_chain_demo(d)
        results = [scan_skill_package(r) for r in roots]
        chain = analyze_attack_chains(results)
        g = build_graph(deps, results, chain)

        st = g["stats"]
        print(f"\n节点 {st['total_nodes']} 个 | 边 {st['total_edges']} 条")
        print(f"按类型: {st['by_type']}")
        print(f"按严重度: {st['by_severity']}")

        print("\n--- 高风险节点 ---")
        for n in st["high_risk_nodes"]:
            icon = NODE_TYPES[n["node_type"]]["icon"]
            print(f"  {icon} [{n['severity']}] {n['name']}"
                  f"（风险点 {n['risk_count']}）")

        print("\n--- 关键节点（被引用最多）---")
        for n in st["key_nodes"][:6]:
            print(f"  {NODE_TYPES[n['type']]['icon']} {n['name']}"
                  f" (入度 {n['in_degree']})")

        print("\n--- 跨技能攻击边 ---")
        for e in g["edges"]:
            if e["meta"].get("chain_id"):
                src = next(n["name"] for n in g["nodes"] if n["node_id"] == e["src"])
                dst = next(n["name"] for n in g["nodes"] if n["node_id"] == e["dst"])
                print(f"  {src} ──{e['relation']}──> {dst}"
                      f"（{e['meta'].get('chain_name')}）")
    finally:
        shutil.rmtree(d, ignore_errors=True)
    print("=" * 68)
