# -*- coding: utf-8 -*-
"""首页：上传即体检 · 一屏看结果。

布局（上→下）：
  ① 单入口：上传技能包 / 用内置示例 → 一键体检（自动跑完整条流水线）
  ② 结论卡 + 导出报告（同一行，一眼可见）
  ③ 数据看板（13/13 · 107 · 0/268 · 3/3）
  ④ 标签页：总览 / 关系图 / 依赖漏洞 / 合规对照（点击切换，不用滚动）
  ⑤ 底部：断网备用（离线演示）

界面用词取向：**主标题说人话**（本事就是给不懂行的人看），
专业术语放进附注或小字（如把「行为意图」标注成「AI 判断」的维度）。
措辞纪律：界面与材料不出现「图计算 / 图神经网络 / GNN / 图算法」。
数据看板数字唯一来源：docs/材料写作规格_数字与口径红线.md。
"""
import os
import shutil
import tempfile

import pandas as pd
import streamlit as st

from views import combo_view, demo_view
from views.common import esc, extract_skill_zip

_BOARD = [
    ("13/13", "多技能组合场景 判断全对", "📊"),
    ("107", "真实样本 检出 100% · 误报 2.0%", "🧪"),
    ("0/268", "SCR-Bench 良性组合 零误报", "🎯"),
    ("3/3", "CompoSkill 官方案例 3/3 一致", "✅"),
]


# ==========================================================
# 入口
# ==========================================================
def _read_upload(files) -> dict:
    """从上传的 .zip / .md 读出 {技能名: 正文}。"""
    skills: dict = {}
    tmp = tempfile.mkdtemp(prefix="ov_up_")
    try:
        for f in files or []:
            data = f.getvalue()
            nm = f.name
            if nm.endswith(".md"):
                skills[nm[:-3]] = data.decode("utf-8", errors="ignore")
            elif nm.endswith(".zip"):
                try:
                    root = extract_skill_zip(data, os.path.join(tmp, nm))
                    for fn in os.listdir(root):
                        if fn.endswith(".md"):
                            with open(os.path.join(root, fn),
                                      encoding="utf-8", errors="ignore") as fh:
                                skills[fn[:-3]] = fh.read()
                except Exception:
                    continue
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return skills


def _one_click_demo(do_deps: bool = True) -> None:
    """内置真链路场景，一键出结果。"""
    opts = combo_view._load_scenario_options()
    pick = next((o for o in opts if "假链路" not in o), None)
    if not pick:
        st.error("未找到内置示例场景（samples/scenarios/_truth.json）。")
        return
    skills = combo_view._load_scenario_skills(pick)
    if not skills:
        st.error(f"示例场景 {pick} 内无 SKILL.md。")
        return
    st.session_state.combo_skills = skills
    combo_view._run_pipeline(skills, do_deps=do_deps)


def _run_upload(files, do_deps: bool = True) -> None:
    skills = _read_upload(files)
    if not skills:
        st.warning("没读到任何 SKILL.md，请确认上传的是技能包（zip 内含 SKILL.md）。")
        return
    st.session_state.combo_skills = skills
    combo_view._run_pipeline(skills, do_deps=do_deps)


# ==========================================================
# 结论卡 / 看板
# ==========================================================
def _decision_html(title: str, cls: str, res: dict) -> str:
    chains = res["chains"]
    intents = res["intents"]
    crit = sum(1 for c in chains if c["sev"] == "严重")
    total = len(intents)
    ok = sum(1 for j in intents.values()
             if not (j.get("degraded") or j.get("verdict") == "PARSE_FAIL"
                     or j.get("scope") == "PARSE_FAIL"))
    conf = f"{ok}/{total}" if total else "—"
    ptr = "—"
    if chains:
        c = chains[0]
        n = c["mal"]
        ev = [str(x) for x in (list(intents.get(n, {}).get("ev_intent", []))
                               + list(intents.get(n, {}).get("ev_scope", [])))]
        ptr = f"{esc(n + ':行 ' + ev[0]) if ev else esc(n)} → 组合风险 {esc(c['tid'])}"
    return f"""
    <div class="decision-card {cls}">
      <div class="decision-verdict">{esc(title)}</div>
      <div class="decision-meta">
        <span>组合风险 <b>{len(chains)}</b> 条（严重 <b>{crit}</b>）</span>
        <span>AI 判断 <b>{conf}</b></span>
        {_dep_line(res)}
      </div>
      <div class="decision-pointer">证据位置：{ptr}</div>
    </div>
    """


def _dep_line(res: dict) -> str:
    """结论卡里的依赖研判一行：状态如实反映，不把「未完成」当「无漏洞」。"""
    stt = res.get("dep_status")
    if stt == "ok":
        vs = (res.get("dep_result") or {}).get("vulns") or []
        hi = sum(1 for v in vs if v.get("severity") in ("严重", "高危"))
        return f"<span>依赖漏洞 <b>{len(vs)}</b>（严重/高危 <b>{hi}</b>）</span>"
    if stt == "error":
        return "<span>依赖检查 <b>未完成</b>（需联网）</span>"
    if stt == "none":
        return "<span>技能未声明依赖</span>"
    return ""


def _board() -> None:
    for col, (v, label, icon) in zip(st.columns(4), _BOARD):
        with col:
            st.markdown(f"""<div class="metric-card"><div class="metric-icon">{icon}</div>
            <div class="metric-value">{v}</div>
            <div class="metric-label">{label}</div></div>""",
                        unsafe_allow_html=True)


# ==========================================================
# 标签页
# ==========================================================
def _tab_overview(res) -> None:
    if not res:
        st.info("先在上方点「一键体检」。")
        return
    intents = res["intents"]
    st.markdown("**AI 判断明细**（每条结论都能定位到原文行号，可当场翻原文核对）")
    rows = []
    for n, j in intents.items():
        rows.append({
            "技能": n,
            "行为意图（AI 判断）": j.get("verdict", "—"),
            "外发范围（AI 判断）": j.get("scope", "—"),
            "意图证据行号": "、".join(str(x) for x in j.get("ev_intent", [])) or "—",
            "外发证据行号": "、".join(str(x) for x in j.get("ev_scope", [])) or "—",
        })
    if rows:
        st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
    st.markdown("**组合风险**（单个技能都正常，凑在一起才出现的问题）")
    chains = res["chains"]
    if chains:
        st.dataframe(pd.DataFrame([{
            "组合风险": c["tid"], "严重度": c["sev"], "作用域": c["scope"],
            "关键技能": c["mal"], "为什么危险": c["why"]} for c in chains]),
            width="stretch", hide_index=True)
    else:
        st.success("未发现组合风险（能力互补 / 意图 / 外发 三要素没有同时满足）。")


def _tab_graph(res) -> None:
    if not res:
        st.info("先在上方点「一键体检」。")
        return
    g = st.session_state.get("ov_graph")
    if not g:
        from modules import asset_graph as ag
        from modules import attack_chain as ac
        from modules import skill_scanner as ss
        srs = [ss.scan_skill_text(n, t) for n, t in res["skills"].items()]
        ch = ac.analyze_attack_chains(srs)
        g = ag.build_graph(
            skill_results=srs, chain_result=ch, skill_texts=res["skills"],
            vulns=(res.get("dep_result") or {}).get("vulns") or [])
        st.session_state.ov_graph = g
    from modules import graph_viz as gv

    # ① 默认：静态 SVG —— 本地生成、体积小、秒出
    #    （交互版那 680KB 内联 HTML 首次要等十几二十秒，答辩现场很难看）
    svg_path = st.session_state.get("ov_svg")
    if not svg_path or not os.path.isfile(svg_path):
        svg_path = gv.to_static_svg(g, os.path.join("reports", "relation_graph.svg"))
        st.session_state.ov_svg = svg_path
    if svg_path and os.path.isfile(svg_path):
        import base64
        try:
            with open(svg_path, "rb") as fh:
                b64 = base64.b64encode(fh.read()).decode("ascii")
            st.markdown(
                '<div class="card" style="padding:10px;">'
                f'<img src="data:image/svg+xml;base64,{b64}" style="width:100%;"/></div>',
                unsafe_allow_html=True)
        except Exception as e:
            st.info(f"静态关系图读取失败：{e}")
    else:
        st.info("未安装 matplotlib / networkx，跳过关系图渲染。")

    # ② 交互版：默认收起，点开才生成（结果缓存进 session_state，不重复算）
    with st.expander("🖱️ 展开交互图（可拖拽 / 缩放）", expanded=False):
        html = st.session_state.get("ov_html")
        if html is None:
            with st.spinner("正在生成交互图…"):
                html = gv.to_pyvis_html(g) or ""
            st.session_state.ov_html = html
        if html:
            try:
                import streamlit.components.v1 as components
                components.html(html, height=520, scrolling=False)
            except Exception as e:
                st.info(f"交互图渲染跳过：{e}")
        else:
            st.info("未安装 pyvis，跳过交互图。")

    if st.button("🖼️ 导出关系图（SVG，供 PPT）", key="ov_svg_btn"):
        p = gv.to_static_svg(g, os.path.join("reports", "relation_graph.svg"))
        st.success(f"已导出：`{p}`") if p else st.warning("导出需要 matplotlib / networkx。")
    st.markdown("**涉及的资产**（技能 / 依赖包 / 外部工具，谁和谁有关）")
    st.dataframe(pd.DataFrame([{
        "类型": n["node_type"], "名称": n["name"], "版本": n["version"] or "—",
        "判定": n["severity"], "风险点": n["risk_count"]} for n in g["nodes"]]),
        width="stretch", hide_index=True)


_DEMO_SKILL_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "samples", "demo_skills", "sales-report-helper")


def _render_dep_demo() -> None:
    """用**真实示例技能包**跑一次依赖漏洞检查（真查 OSV/NVD/GitHub/EPSS，需联网）。

    示例包是仓库里的 ``samples/demo_skills/sales-report-helper``（自建，不属评测语料），
    声明了两个**真实存在已知漏洞的旧版依赖**，用来演示依赖检查的完整输出形态。
    """
    if st.button("🎬 用依赖示例跑一次（真实查询）", key="ov_dep_demo_btn"):
        path = os.path.join(_DEMO_SKILL_DIR, "SKILL.md")
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except OSError as e:
            st.error(f"读不到示例技能包：{e}")
            return
        with st.spinner("正在查四个官方漏洞库（约十几秒到 1 分钟）…"):
            st.session_state.ov_dep_demo_result = combo_view._run_dep_stage(
                {"sales-report-helper": text}, ["sales-report-helper"])
        st.rerun()

    st.caption("示例技能包 `samples/demo_skills/sales-report-helper` 里声明了 "
               "`requests==2.25.0` 与 `pyyaml==5.3.1` 两个真实的旧版依赖——"
               "点一次就能看到「四个官方漏洞库交叉核对 → 置信度评级 → 修复优先级」"
               "的完整输出（需联网）。")

    dep = st.session_state.get("ov_dep_demo_result")
    if not dep:
        return
    stt = dep.get("status")
    if stt == "error":
        st.error(f"查询未完成（多为断网或数据源不可达）：{dep.get('msg')}。"
                 "失败不等于「无漏洞」，联网后重试。")
        return
    if stt == "none":
        st.warning("示例技能包里没解析到依赖声明。")
        return
    r = dep.get("result") or {}
    vulns = r.get("vulns") or []
    summary = r.get("summary") or {}
    st.success(f"已解析到依赖：{'、'.join(dep.get('pkgs') or [])}（**真实查询结果**）")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("依赖总数", summary.get("total_dependencies",
                                     len(dep.get("pkgs") or [])))
    m2.metric("漏洞总数", summary.get("total_vulnerabilities", len(vulns)))
    m3.metric("严重/高危", summary.get("critical_count", 0))
    m4.metric("需立即修复", summary.get("priority_1_count", 0))
    if vulns:
        rows = [{
            "依赖": v.get("package", ""),
            "版本": v.get("version", "") or "—",
            "CVE": v.get("cve_id", ""),
            "严重度": v.get("severity", "未知"),
            "CVSS": v.get("cvss_score", 0),
            "EPSS%": round((v.get("epss_score") or 0) * 100, 1),
            "置信度": (v.get("confidence") or {}).get("level", "—"),
            "修复优先级": (v.get("fix_priority") or {}).get("label", "—"),
        } for v in vulns]
        st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
    else:
        st.info("这两个版本的依赖在四个漏洞库里没有查到已知漏洞。")
    if summary.get("query_error_total"):
        st.warning(f"⚠️ 本次有 {summary['query_error_total']} 次数据源查询失败，"
                   "「零漏洞」不可全信，请联网后重试。")


def _tab_deps(res) -> None:
    if not res:
        st.info("先在上方点「一键体检」。")
        st.markdown("**或者：直接跑一次依赖示例**")
        _render_dep_demo()
        return
    stt = res.get("dep_status")
    if stt == "skipped":
        st.info("本次未启用依赖检查（可在入口处勾选后重新体检）。")
        _render_dep_demo()
        return
    if stt == "none":
        st.info("技能正文里没有 `pip / npm / apt install` 形式的依赖声明，未触发依赖检查。")
        _render_dep_demo()
        return
    if stt == "error":
        st.error(f"依赖检查未完成（多为断网或数据源不可达）：{res.get('dep_msg')}。"
                 "失败不等于「无漏洞」，联网后请重新体检。")
        _render_dep_demo()
        return
    d = res.get("dep_result") or {}
    vulns = d.get("vulns") or []
    summary = d.get("summary") or {}
    st.caption("依赖来源：技能正文声明的 `pip / npm / apt install` 包名（纯本地提取）；"
               "漏洞来自 OSV / NVD / GitHub / EPSS 四个官方漏洞库的交叉核对。")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("依赖总数", summary.get("total_dependencies", len(res.get("dep_pkgs") or [])))
    m2.metric("漏洞总数", summary.get("total_vulnerabilities", len(vulns)))
    m3.metric("严重/高危", summary.get("critical_count", 0))
    m4.metric("需立即修复", summary.get("priority_1_count", 0))
    if vulns:
        rows = [{
            "依赖": v.get("package", ""),
            "版本": v.get("version", "") or "—",
            "CVE": v.get("cve_id", ""),
            "严重度": v.get("severity", "未知"),
            "CVSS": v.get("cvss_score", 0),
            "EPSS%": round((v.get("epss_score") or 0) * 100, 1),
            "置信度": (v.get("confidence") or {}).get("level", "—"),
            "修复优先级": (v.get("fix_priority") or {}).get("label", "—"),
        } for v in vulns]
        st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
    else:
        st.success("本次依赖未命中任何已知漏洞。")
    if summary.get("query_error_total"):
        st.warning(f"⚠️ 本次有 {summary['query_error_total']} 次数据源查询失败，"
                   "「零漏洞」不可全信，请联网后重试。")


def _tab_compliance(res) -> None:
    if not res:
        st.info("先在上方点「一键体检」。")
        return
    from modules import compliance_map as cm
    from modules import skill_scanner as ss
    rows = []
    for n, t in res["skills"].items():
        for cat, cnt in cm.summary(ss.scan_skill_text(n, t)["findings"]).items():
            rows.append({"技能": n, "风险类型": cat, "命中数": cnt,
                         "OWASP 条目": cm.owasp_label(cm.owasp_for(cat)) or "—",
                         "官方证据": cm.evidence_for(cm.owasp_for(cat)) or "—"})
    if rows:
        st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
        st.caption("**OWASP 条目**与**官方证据**均取自 OWASP Agentic Skills Top 10 官方总表"
                   "（`owasp.github.io/www-project-agentic-skills-top-10`，"
                   "Summary Table 的 Real-World Evidence 列）；"
                   "「风险类型 → 条目」为**依据官方条目名的语义对照，非官方认证映射**。"
                   "MITRE ATLAS 条目编号待官方核实后回填。")
    else:
        st.success("未命中任何风险类型。")


# ==========================================================
# 主入口
# ==========================================================
def render() -> None:
    res = st.session_state.get("combo_result")

    # ① 单入口
    st.markdown('<div class="section-title">🩺 一键体检</div>', unsafe_allow_html=True)
    c1, c2 = st.columns([4, 1])
    with c1:
        files = st.file_uploader("上传技能包（.zip / .md，可多选）",
                                 type=["zip", "md"], accept_multiple_files=True,
                                 key="ov_up", label_visibility="collapsed")
        do_deps = st.checkbox(
            "顺带检查技能声明的依赖有没有已知漏洞"
            "（OSV / NVD / GitHub / EPSS 四库，需联网，约 1–2 分钟）",
            value=True, key="ov_do_deps",
            help="内置示例没有依赖声明、秒出；上传带依赖的包会多等 1–2 分钟。")
    with c2:
        if st.button("▶ 一键体检", type="primary", key="ov_run", width="stretch"):
            st.session_state.pop("ov_graph", None)
            st.session_state.pop("ov_svg", None)
            st.session_state.pop("ov_html", None)
            st.session_state.pop("ov_dep_demo_result", None)
            _run_upload(files, do_deps=do_deps)
        if st.button("用内置示例", key="ov_demo_btn", width="stretch"):
            st.session_state.pop("ov_graph", None)
            st.session_state.pop("ov_svg", None)
            st.session_state.pop("ov_html", None)
            st.session_state.pop("ov_dep_demo_result", None)
            _one_click_demo(do_deps=do_deps)
    st.caption("上传一个技能包就自动跑完整条流水线（规则快筛 → AI 判断 → "
               "组合判定 → 依赖漏洞检查）；或点「用内置示例」直接出结果。"
               "只查**单个技能**也可以——上传 1 个 `.md` 即可"
               "（多个技能才会看「组合风险」）。")

    # ② 结论卡 + 导出
    if res:
        chains = res["chains"]
        failed = combo_view._degraded_count(res["intents"])
        if any(c["sev"] == "严重" for c in chains):
            title, cls = "❌ 不可直接安装", "dec-block"
        elif chains:
            title, cls = "⚠️ 需复核（存在高危链路）", "dec-review"
        elif failed:
            title, cls = "⚠️ 不可用于放行（分诊未完成）", "dec-review"
        elif any(j.get("verdict") in ("MALICIOUS", "SUSPICIOUS")
                 for j in res["intents"].values()):
            title, cls = "⚠️ 需人工复核", "dec-review"
        elif res.get("ai_ok"):
            title, cls = "✅ 可安装", "dec-pass"
        else:
            title, cls = "🟡 规则侧未发现组合风险", "dec-review"
        d1, d2 = st.columns([4, 1])
        with d1:
            st.markdown(_decision_html(title, cls, res), unsafe_allow_html=True)
        with d2:
            st.write("")
            if st.button("📄 导出报告", key="ov_rep_btn", width="stretch"):
                from modules import skill_rating as sr
                from modules import skill_scanner as ss
                from modules.report import generate_skill_report
                srs = [ss.scan_skill_text(n, t) for n, t in res["skills"].items()]
                sm = {n: sr.skill_score(ss.scan_skill_text(n, t)["findings"])
                      for n, t in res["skills"].items()}
                p = generate_skill_report(srs, res, title, sm)
                st.success(f"已导出：`{p}`")
    else:
        st.markdown('<div class="decision-card dec-idle">'
                    '<div class="decision-verdict">尚未体检</div>'
                    '<div class="decision-meta"><span>上传技能包或点「用内置示例」</span></div>'
                    '</div>', unsafe_allow_html=True)

    # ③ 数据看板
    _board()

    # ④ 标签页
    t1, t2, t3, t4 = st.tabs(["总览", "关系图", "依赖漏洞", "合规对照"])
    with t1:
        _tab_overview(res)
    with t2:
        _tab_graph(res)
    with t3:
        _tab_deps(res)
    with t4:
        _tab_compliance(res)

    # ⑤ 断网备用
    with st.expander("🌐 断网备用（离线演示）", expanded=False):
        demo_view.render()