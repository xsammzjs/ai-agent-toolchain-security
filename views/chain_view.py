# -*- coding: utf-8 -*-
"""视图 3：资产关联分析

把 AI 技能、传统依赖、MCP 工具统一建成一张资产图谱，
在图上做路径搜索，找出单点检测发现不了的跨资产组合风险。

这是本作品区别于所有同赛道工具的核心能力：
单点检测回答「哪个技能危险」，资产关联分析回答
「这些资产凑在一起会造成什么后果」。
"""
import os
import shutil
import tempfile

import pandas as pd
import streamlit as st

from views.common import esc, extract_skill_zip


def render():
    """渲染本视图"""
    # ==========================================
    st.divider()
    st.markdown('<div id="chain-section"></div>', unsafe_allow_html=True)
    st.markdown('<div class="section-title">🔗 资产关联分析</div>',
                unsafe_allow_html=True)
    st.caption(
        "传统工具只能逐个判定单点风险等级。本功能建立「能力图」，"
        "把分散在不同技能中的危险动作连成完整攻击链——"
        "例如「读取 .env 凭据」单看只是中危，"
        "但若另一技能同时具备「向外传输数据」能力，即构成凭据外泄链路。"
    )

    if "chain_result" not in st.session_state:
        st.session_state.chain_result = None


    def _run_chain_demo():
        """运行跨技能攻击链演示（完全离线）"""
        from modules import attack_chain as ac
        from modules import skill_scanner as ss

        tmp_dir = tempfile.mkdtemp(prefix="chain_demo_")
        try:
            roots = ac.make_attack_chain_demo(tmp_dir)
            results = [ss.scan_skill_package(r) for r in roots]
            chain = ac.analyze_attack_chains(results)
            chain["skill_results"] = results
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        st.session_state.chain_result = chain
        st.rerun()


    def _run_chain_from_zip(zip_list: list):
        """对用户上传的多个技能包做资产关联分析"""
        from modules import attack_chain as ac
        from modules import skill_scanner as ss

        tmp_dir = tempfile.mkdtemp(prefix="chain_multi_")
        try:
            results = []
            for idx, zb in enumerate(zip_list):
                sub = os.path.join(tmp_dir, f"skill_{idx}")
                os.makedirs(sub, exist_ok=True)
                try:
                    root = extract_skill_zip(zb, sub)
                    results.append(ss.scan_skill_package(root))
                except Exception:
                    continue
            if not results:
                st.error("未能读取任何技能包，请确认 zip 内含 SKILL.md")
                return
            chain = ac.analyze_attack_chains(results)
            chain["skill_results"] = results
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        st.session_state.chain_result = chain
        st.rerun()


    chain_col1, chain_col2 = st.columns(2)

    with chain_col1:
        with st.container(border=True):
            st.markdown("**🎬 演示：三个「无害」技能如何组成攻击链**")
            st.caption("三个技能单看判定分别为低危 / 中危 / 高危，"
                       "传统工具到此为止；关联后识别出完整的凭据外泄链路。")
            if st.button("🔗 运行资产关联分析演示", type="primary",
                         key="chain_demo_btn", width="stretch"):
                _run_chain_demo()
            st.caption("💡 答辩建议：先点左边的演示，再指出页面下方的"
                       "「① 单点视角 vs ② 攻击链视角」对比——这是差异化的直观证据。")

    with chain_col2:
        with st.container(border=True):
            st.markdown("**📦 方式二：上传多个技能包做真实关联**")
            chain_zips = st.file_uploader(
                "选择技能包（可多选）", type=["zip"], key="chain_zips",
                accept_multiple_files=True, label_visibility="collapsed")
            if st.button("🔗 分析技能间攻击链", key="chain_zip_btn",
                         disabled=not chain_zips, width="stretch"):
                _run_chain_from_zip([z.getvalue() for z in chain_zips])

    # ---- 攻击链结果展示 ----
    if st.session_state.chain_result:

        cr = st.session_state.chain_result
        chains = cr["chains"]
        skill_results = cr.get("skill_results", [])

        st.divider()
        st.markdown("### 🔗 攻击链分析结果")

        # ---- 能力分布（先看这几个技能各自会什么） ----
        if cr["capability_map"]:
            cap_items = "".join(
                f'<span class="cap-cloud-item">{esc(cap)} <b>{len(sks)}</b></span>'
                for cap, sks in cr["capability_map"].items()
            )
            st.markdown(
                f'<div style="font-size:0.82rem;color:#5a6f85;margin-top:4px;">'
                f'识别到的危险能力分布：</div><div class="cap-cloud">{cap_items}</div>',
                unsafe_allow_html=True,
            )

        # 单点视角 vs 链路视角 对比双栏（答辩最有说服力的部分）
        if chains and skill_results:
            rows_html = "".join(
                f'<tr><td>{esc(r["skill_name"])}</td>'
                f'<td><b>{esc(r["verdict"])}</b></td>'
                f'<td>{len(r["findings"])}</td></tr>'
                for r in skill_results
            )
            chain_names = "、".join(f'<b>{esc(c["chain_name"])}</b>' for c in chains[:3])
            st.markdown(f"""
            <div class="compare-row">
                <div class="compare-col traditional">
                    <h4>① 单点检测视角（传统工具的结论）</h4>
                    <table style="width:100%;border-collapse:collapse;font-size:0.86rem;">
                      <tr style="color:#5a6f85;border-bottom:1px solid #dde3ec;">
                        <th style="text-align:left;padding:5px 4px;">技能</th>
                        <th style="text-align:left;padding:5px 4px;">判定</th>
                        <th style="text-align:left;padding:5px 4px;">风险点</th>
                      </tr>
                      {rows_html}
                    </table>
                    <div style="margin-top:10px;font-size:0.84rem;color:#5a6f85;line-height:1.6;">
                      最严重的也只是「高危」。<b>传统工具到此为止</b>——
                      它只能告诉你哪个技能危险，无法回答「这些技能凑在一起会怎样」。
                    </div>
                </div>
                <div class="compare-col advanced">
                    <h4>② 攻击链视角（本项目的结论）</h4>
                    <div style="font-size:1.5rem;font-weight:bold;color:#c0392b;margin:6px 0;">
                      🔗 命中 {len(chains)} 条攻击链路
                    </div>
                    <div style="font-size:0.9rem;color:#7d241a;line-height:1.7;">
                      识别出：{chain_names}
                    </div>
                    <div style="margin-top:10px;font-size:0.84rem;color:#7d241a;line-height:1.6;">
                      把分散在<b>不同技能</b>里的危险动作连成完整路径，
                      给出<b>可核验的真实危害</b>与处置建议。
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

        # ---- 攻击链卡片（可视化路径） ----
        for ch in chains:
            sev = ch["severity"]
            scope_tag = ("跨技能协同" if ch["scope"] == "跨技能" else "单技能内组合")

            # 拼接步骤节点
            steps_html = []
            for i, s in enumerate(ch["steps"]):
                if i > 0:
                    steps_html.append('<div class="chain-arrow">➜</div>')
                src = esc(s.get("skill", ch["path"][0] if ch["path"] else ""))
                steps_html.append(f"""
                <div class="chain-step">
                  <div class="chain-step-cap">{esc(s['cap_label'])}</div>
                  <div class="chain-step-src">📦 {src}</div>
                  <div class="chain-step-loc">📄 {esc(s['file'])}:{s['line']}</div>
                  <span class="chain-step-rule">{esc(s['rule'])}</span>
                </div>""")

            st.markdown(f"""
            <div class="chain-card">
              <div class="chain-card-head sev-{sev}">
                <span>🔗 {esc(ch['chain_name'])}</span>
                <span style="font-size:0.82rem;font-weight:500;opacity:0.95;">
                  {esc(sev)} · {esc(scope_tag)} · 风险分 {ch['risk_score']}
                </span>
              </div>
              <div class="chain-card-body">
                <div class="chain-steps">{"".join(steps_html)}</div>
                <div class="chain-impact">
                  <b>真实危害</b>：{esc(ch['impact'])}
                </div>
                <div class="chain-advice">
                  <b>处置建议</b>：{esc(ch['advice'])}
                </div>
              </div>
            </div>
            """, unsafe_allow_html=True)

        if chains:
            st.markdown("""
            <div class="demo-hint">
                <b>💡 一句话讲清差异化</b><br>
                单点检测回答「<b>哪个技能危险</b>」；
                攻击链分析回答「<b>这些技能凑在一起会造成什么后果</b>」。<br>
                每条链路都能追溯到原文行号与命中规则，评委可当场核验——
                这是「<b>确定性证据</b>」而非模型推测。
            </div>
            """, unsafe_allow_html=True)

            # ===== AI 研判（跨技能视角）=====
            from modules import adjudicator as adj_c

            with st.container(border=True):
                st.markdown("**🤖 AI 研判 · 威胁评估与应急处置**")
                st.caption("基于已确认的攻击链路生成。AI 不参与链路判定，"
                           "只做跨步骤汇总与处置建议，每步都点明来源技能与行号。")
                worst = chains[0]
                a1, a2 = st.columns([1, 3])
                with a1:
                    if st.button("生成 AI 研判", key="adj_chain_btn",
                                 type="primary", width="stretch"):
                        st.session_state.chain_adj = adj_c.adjudicate_chain(worst)
                        st.rerun()
                with a2:
                    cadj = st.session_state.get("chain_adj")
                    if not cadj:
                        st.info("将针对最严重的一条链路生成研判"
                                + ("（MaaS 已配置）" if adj_c.is_available()
                                   else "（未配置 MaaS，使用本地模板）"))
                cadj = st.session_state.get("chain_adj")
                if cadj:
                    tag = "🌐 华为云 MaaS" if not cadj.degraded else "📋 本地模板（未调用大模型）"
                    st.markdown(
                        f'<div style="display:inline-block;background:{"#eaf4fb" if not cadj.degraded else "#fdf6e3"};'
                        f'color:{"#1a6fa8" if not cadj.degraded else "#8a6d1a"};'
                        f'border-radius:999px;padding:3px 12px;font-size:0.8rem;'
                        f'margin-bottom:8px;">研判来源：{esc(tag)}'
                        + (f' ｜ 模型 {esc(cadj.model)}' if cadj.model else "")
                        + f'</div>', unsafe_allow_html=True)
                    st.markdown(esc(cadj.content).replace("\n", "  \n"))
        else:
            st.success(
                "🎉 未发现攻击链：各技能虽有危险能力，但未形成完整链路。"
                "（若各技能都只有 1 类能力，属正常情况）"
            )

        # ===== 资产图谱可视化 =====
        if skill_results:
            from modules import asset_graph as ag

            with st.container(border=True):
                st.markdown("**🕸️ 资产图谱 · 统一资产视图**")
                st.caption("把传统依赖包、AI Agent 技能、MCP 工具统一建模为资产节点，"
                           "关系建成边。这是赛题 1 要求 RDS 承载的数据模型，"
                           "也是把传统依赖与 AI 技能统一到一张图上的数据基础。")
                if st.button("生成资产图谱", key="graph_btn",
                             width="stretch"):
                    st.session_state.asset_graph = ag.build_graph(
                        dep_list=st.session_state.get("dep_list") or [],
                        skill_results=skill_results,
                        chain_result=cr,
                    )
                    st.rerun()

                g = st.session_state.get("asset_graph")
                if g:
                    gs = g["stats"]
                    gc1, gc2, gc3 = st.columns(3)
                    with gc1:
                        st.markdown(f"""
                        <div class="metric-card">
                            <div class="metric-icon">🔷</div>
                            <div class="metric-value">{gs['total_nodes']}</div>
                            <div class="metric-label">资产节点</div>
                        </div>
                        """, unsafe_allow_html=True)
                    with gc2:
                        st.markdown(f"""
                        <div class="metric-card metric-card-orange">
                            <div class="metric-icon">🔗</div>
                            <div class="metric-value">{gs['total_edges']}</div>
                            <div class="metric-label">关系边</div>
                        </div>
                        """, unsafe_allow_html=True)
                    with gc3:
                        st.markdown(f"""
                        <div class="metric-card metric-card-red">
                            <div class="metric-icon">⚠️</div>
                            <div class="metric-value">{len(gs['high_risk_nodes'])}</div>
                            <div class="metric-label">高风险资产</div>
                        </div>
                        """, unsafe_allow_html=True)

                    type_desc = "｜".join(
                        f"{ag.NODE_TYPES[k]['icon']}{k} {v}"
                        for k, v in gs["by_type"].items())
                    st.caption(f"资产构成：{esc(type_desc)}")

                    st.markdown("**资产节点清单**")
                    node_rows = [{
                        "类型": ag.NODE_TYPES[n["node_type"]]["icon"] + " " + n["node_type"],
                        "名称": n["name"],
                        "版本": n["version"] or "—",
                        "判定": n["severity"],
                        "风险点": n["risk_count"],
                    } for n in g["nodes"]]
                    st.dataframe(pd.DataFrame(node_rows),
                                 width="stretch", height=260,
                                 column_config={
                                     "类型": st.column_config.TextColumn(width="small"),
                                     "判定": st.column_config.TextColumn(width="small"),
                                     "版本": st.column_config.TextColumn(width="small"),
                                     "风险点": st.column_config.NumberColumn(width="small"),
                                 })

                    chain_edges = [e for e in g["edges"]
                                   if e["meta"].get("chain_id")]
                    if chain_edges:
                        name_of = {n["node_id"]: n["name"] for n in g["nodes"]}
                        st.markdown("**⚔️ 跨资产攻击路径（资产级视角）**")
                        for e in chain_edges:
                            st.markdown(
                                f'<div class="chain-impact">'
                                f'🔗 <b>{esc(name_of.get(e["src"], "?"))}</b> '
                                f'──{esc(e["relation"])}──▶ '
                                f'<b>{esc(name_of.get(e["dst"], "?"))}</b>'
                                f'<br><span style="font-size:0.84rem;">'
                                f'经由「{esc(e["meta"].get("via", ""))}」，'
                                f'构成「{esc(e["meta"].get("chain_name"))}」'
                                f'（{esc(e["meta"].get("severity"))}）</span></div>',
                                unsafe_allow_html=True,
                            )



    # ---- 依赖侧证据（可选附加）----
    # 原「依赖漏洞扫描」独立视图降级而来。传统依赖漏洞不再作为并列功能，
    # 而是作为资产图谱里的「依赖侧节点」，与技能、工具节点合流参与组合分析。
    with st.expander("📎 依赖侧证据：该项目的传统依赖漏洞（可选附加）",
                     expanded=bool(st.session_state.get("scan_done"))):
        if st.session_state.get("scan_done") and st.session_state.get("result"):
            # 复用依赖视图的结果渲染，避免两处代码各写一份
            from views.dep_scan import render_results
            render_results()
        else:
            st.info("尚未扫描依赖侧证据。请切到「📦 依赖漏洞检测」上传项目包并"
                    "扫描，扫描结果会显示在这里，并作为资产图谱的依赖侧节点。")

