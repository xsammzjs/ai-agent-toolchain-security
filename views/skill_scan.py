# -*- coding: utf-8 -*-
"""视图 1：AI 技能安全检测

用静态规则引擎检测 AI Agent 技能包（SKILL.md）中的恶意行为：
32 条规则覆盖 8 类威胁，每条结论都带原文行号和命中规则名，可当场核验。
"""
import re
import sys
import os

import pandas as pd
import streamlit as st

from views.common import esc, run_skill_scan, metric_card, section_title


def _build_markdown_report(sr: dict) -> str:
    """把检测结果拼成 Markdown 报告（可下载作为审计凭证）"""
    from datetime import datetime

    lines = [
        f"# AI 技能安全检测报告 · {sr['skill_name']}",
        "",
        f"- 生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"- 整体判定：**{sr['verdict']}**",
        f"- 扫描文件数：{sr['files']}",
        f"- 命中风险点：{len(sr['findings'])}",
        f"- 检测规则数：{sr['stats'].get('rule_count', '—')}",
        "",
        "## 风险明细",
        "",
        "| 等级 | 类别 | 规则 | 位置 | 证据 | 说明 | 处置建议 |",
        "|---|---|---|---|---|---|---|",
    ]
    for f in sr["findings"]:
        cells = [
            f.get("severity", ""), f.get("category", ""), f.get("rule", ""),
            f"{f.get('file', '')}:{f.get('line', '')}",
            (f.get("evidence", "") or "").replace("|", "\\|").replace("\n", " "),
            (f.get("description", "") or "").replace("|", "\\|"),
            (f.get("suggestion", "") or "").replace("|", "\\|"),
        ]
        lines.append("| " + " | ".join(cells) + " |")
    lines += [
        "",
        "---",
        "",
        "> 本报告由 AI 技能组合风险体检站生成：规则快筛侧纯离线、零模型调用；"
        "AI 意图分诊按需启用（命中本地缓存时同样零调用）。"
        "结论可重复、可审计。每条风险均带原文行号与命中规则名，可当场核验。",
    ]
    return "\n".join(lines)


def render():
    """渲染本视图"""
    # ==========================================
    if "skill_result" not in st.session_state:
        st.session_state.skill_result = None
    if "skill_benchmark" not in st.session_state:
        st.session_state.skill_benchmark = False

    st.divider()
    st.markdown('<div id="skill-section"></div>', unsafe_allow_html=True)
    section_title("🛡️ AI 技能安全检测")
    st.caption(
        "Agent Skills 已成为新型软件供应链攻击面——2026 年 ClawHavoc 事件中 1,184 个恶意技能"
        "造成 24.7 万次安装，Snyk 审计发现 36.82% 的技能含提示注入。"
        "本功能基于静态规则引擎对技能包做确定性检测，命中即给出原文行号作为证据。"
    )

    # ---- 系统引导（2026-10-26 聚焦化：原依赖视图的引导页移到这里并重写）----
    intro_col1, intro_col2 = st.columns([1.25, 1])

    with intro_col1:
        with st.container(border=True):
            st.markdown('<div class="viz-title">🔍 本系统解决什么问题</div>',
                        unsafe_allow_html=True)
            st.markdown("""
            Agent Skills 已成为新型软件供应链攻击面。传统工具只做**单点**判定——
            告诉你「这个技能有提示注入」，却答不出「**这些技能凑在一起会怎样**」。

            本系统两步走：

            | 步骤 | 做什么 | 怎么验证 |
            |------|--------|----------|
            | 1️⃣ 单点检测 | 32 条规则扫技能包，命中即给原文行号 | 对照 SKILL.md 逐行核对 |
            | 2️⃣ 组合分析 | 把技能拆成 8 类危险能力，找跨技能攻击链 | 每条链路可回溯到行号 |
            """)

    with intro_col2:
        with st.container(border=True):
            st.markdown('<div class="viz-title">✨ 和普通工具有什么不同</div>',
                        unsafe_allow_html=True)
            st.markdown("""
            - ❌ 普通工具：列一堆命中项，不知道真实危害
            - ✅ 本系统：**给出可核验的攻击链 + 真实危害 + 处置建议**
            - 🔗 还能把传统依赖漏洞作为**依赖侧节点**接入同一张资产图谱
            - 📐 判定分层：能力由**规则**判定（确定性、可复现）；
              **AI 判行为意图与外发范围**，是组合判定两道闸门的来源
            """)

    skill_col1, skill_col2 = st.columns(2)

    with skill_col1:
        with st.container(border=True):
            section_title("📤 上传技能包")
            st.markdown("**方式一：上传技能包（zip）**")
            skill_zip = st.file_uploader("zip上传", type=["zip"], key="skill_zip",
                                         label_visibility="collapsed")
            sc1, sc2 = st.columns([1, 1])
            with sc1:
                if st.button("🛡️ 检测技能包", type="primary", key="skill_zip_btn",
                             disabled=not skill_zip, width="stretch"):
                    run_skill_scan(zip_bytes=skill_zip.getvalue())
            with sc2:
                if st.button("🎬 演示样例", key="skill_demo_btn", width="stretch"):
                    run_skill_scan(demo=True)
            st.caption("支持从 GitHub 下载的技能包 zip，自动定位 SKILL.md；"
                       "「演示样例」为故意构造的恶意技能，仅用于功能演示。")

    with skill_col2:
        with st.container(border=True):
            st.markdown("**方式二：粘贴 SKILL.md 内容**")
            skill_text = st.text_area("内容", key="skill_text", height=170,
                                      label_visibility="collapsed",
                                      placeholder="粘贴 SKILL.md 的完整内容……")
            if st.button("🛡️ 检测文本", key="skill_text_btn",
                         disabled=not skill_text.strip(), width="stretch"):
                run_skill_scan(text=skill_text)

    # ---- 恶意样本检测率演示（内置样本库，回应"与grep有何区别"的质疑） ----
    with st.container(border=True):
        bench_col1, bench_col2 = st.columns([1, 3])
        with bench_col1:
            if st.button("📊 运行样本检测率测试", key="skill_bench_btn",
                         width="stretch"):
                st.session_state.skill_benchmark = True
        with bench_col2:
            st.caption("内置样本库：30 个恶意技能（基于 ClawHavoc/Snyk/ToxicSkills 等公开披露的"
                       "恶意模式构造）+ 20 个正常技能对照。纯本地规则引擎，毫秒级完成，零费用。")

    if st.session_state.skill_benchmark:
        import subprocess
        # 🔴 基准脚本在**项目根**的 samples/ 下，不在 views/ 下。
        #    这里必须 dirname 两次才能从 views/ 回到项目根；
        #    原来只 dirname 一次，拼出 views/samples/…（该目录不存在），
        #    导致「运行样本检测率测试」按钮 100% 报「samples 目录不完整」。
        #    正确写法参照 views/combo_view.py 的 _SCENARIO_DIR。
        _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        _bench_path = os.path.join(_ROOT, "samples", "run_skill_benchmark.py")
        try:
            _bench_out = subprocess.run(
                [sys.executable, _bench_path], capture_output=True,
                text=True, encoding="utf-8", errors="replace", timeout=60,
            ).stdout
        except Exception:
            _bench_out = ""
        if _bench_out:
            m = re.search(r"恶意样本检出率: (\d+)/(\d+)\s+正常样本无误报: (\d+)/(\d+)\s+总耗时: (\d+)ms", _bench_out)
            if m:
                b1, b2, b3 = st.columns(3)
                with b1:
                    st.markdown(f"""
                    <div class="metric-card {'metric-card-green' if m.group(1) == m.group(2) else 'metric-card-red'}">
                        <div class="metric-icon">🎯</div>
                        <div class="metric-value">{m.group(1)}/{m.group(2)}</div>
                        <div class="metric-label">恶意样本检出率</div>
                    </div>
                    """, unsafe_allow_html=True)
                with b2:
                    st.markdown(f"""
                    <div class="metric-card {'metric-card-green' if m.group(3) == m.group(4) else 'metric-card-red'}">
                        <div class="metric-icon">✅</div>
                        <div class="metric-value">{m.group(3)}/{m.group(4)}</div>
                        <div class="metric-label">正常样本无误报</div>
                    </div>
                    """, unsafe_allow_html=True)
                with b3:
                    st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-icon">⚡</div>
                        <div class="metric-value">{m.group(5)}ms</div>
                        <div class="metric-label">50 个样本总耗时（本地规则引擎）</div>
                    </div>
                    """, unsafe_allow_html=True)
            st.code(_bench_out, language=None)
        else:
            st.error("样本检测率测试运行失败，请检查 samples/ 目录是否完整。")

    # ---- 检测结果展示 ----
    if st.session_state.skill_result:
        from modules import skill_scanner as ss_mod
        from modules import adjudicator as adj_mod

        sr = st.session_state.skill_result
        findings = sr["findings"]
        verdict = sr["verdict"]
        vcolor = ss_mod.SEV_COLOR[verdict]

        st.divider()
        section_title(f"📊 扫描总览 · {sr['skill_name']}")
        m1, m2, m3, m4 = st.columns(4)
        with m1:
            st.markdown(f"""
            <div class="metric-card metric-card-red">
                <div class="metric-icon">🎯</div>
                <div class="metric-value" style="color:{vcolor}">{verdict}</div>
                <div class="metric-label">整体判定</div>
            </div>
            """, unsafe_allow_html=True)
        with m2:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-icon">📁</div>
                <div class="metric-value">{sr['files']}</div>
                <div class="metric-label">扫描文件数</div>
            </div>
            """, unsafe_allow_html=True)
        with m3:
            n = len(findings)
            st.markdown(f"""
            <div class="metric-card {'metric-card-red' if n else 'metric-card-green'}">
                <div class="metric-icon">⚠️</div>
                <div class="metric-value">{n}</div>
                <div class="metric-label">命中风险点</div>
            </div>
            """, unsafe_allow_html=True)
        with m4:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-icon">📜</div>
                <div class="metric-value">{sr['stats']['rule_count']}</div>
                <div class="metric-label">检测规则数</div>
            </div>
            """, unsafe_allow_html=True)

        # ===== AI 研判（赛题1 要求的「人工智能（必选）」能力入口）=====
        with st.container(border=True):
            st.markdown("**🤖 AI 研判 · 风险态势与处置建议**")
            st.caption(
                "检测结论由上方的确定性规则给出（可核验）；"
                "本页的 AI 研判把分散的检测结果综合起来回答「最该先处理什么、为什么、怎么做」，"
                "每条引用都可追溯到规则名与行号。"
            )
            ai_c1, ai_c2 = st.columns([1, 3])
            with ai_c1:
                if st.button("生成 AI 研判", key="adj_skill_btn",
                             type="primary", width="stretch"):
                    st.session_state.skill_adj = adj_mod.adjudicate_skill(sr)
                    st.rerun()
            with ai_c2:
                src = st.session_state.get("skill_adj")
                if not src:
                    if adj_mod.is_available():
                        st.info(f"✅ 华为云 MaaS 已配置（模型：{adj_mod.MAAS_MODEL}），"
                                "点击左侧按钮生成研判")
                    else:
                        st.info("ℹ️未配置华为云 MaaS，点击后将使用**本地模板**生成研判"
                                "（功能完整，界面会明确标注非AI 输出）")

            adj = st.session_state.get("skill_adj")
            if adj:
                tag = ("🌐 华为云 MaaS" if not adj.degraded
                       else "📋 本地模板（未调用大模型）")
                color = "#1a6fa8" if not adj.degraded else "#8a6d1a"
                st.markdown(
                    f'<div style="display:inline-block;background:{"#eaf4fb" if not adj.degraded else "#fdf6e3"};'
                    f'color:{color};border-radius:999px;padding:3px 12px;'
                    f'font-size:0.8rem;margin-bottom:8px;">研判来源：{esc(tag)}'
                    + (f' ｜ 模型 {esc(adj.model)}' if adj.model else "")
                    + f'</div>', unsafe_allow_html=True)
                st.markdown(esc(adj.content).replace("\n", "  \n"))
                if adj.evidence_refs:
                    st.caption(f"引用证据 {len(adj.evidence_refs)} 条："
                               + "；".join(esc(r) for r in adj.evidence_refs[:5])
                               + ("…" if len(adj.evidence_refs) > 5 else ""))

        # ===== 📈 可视化仪表盘：威胁分类分布 =====
        if findings:
            st.markdown('<div class="section-title">📈 可视化仪表盘</div>',
                        unsafe_allow_html=True)

            # 4.1 威胁类别分布（横向条形）
            cat_count = {}
            for f in findings:
                cat_count[f["category"]] = cat_count.get(f["category"], 0) + 1
            max_cat = max(cat_count.values()) if cat_count else 1
            cat_rows = []
            for cat, cnt in sorted(cat_count.items(), key=lambda x: -x[1]):
                bar = "█" * max(1, round(cnt / max_cat * 22))
                cat_rows.append(
                    f'<tr><td style="padding:3px 10px 3px 0;white-space:nowrap;">{esc(cat)}</td>'
                    f'<td style="padding:3px 8px;color:var(--accent);font-family:monospace;">{bar}</td>'
                    f'<td style="padding:3px 0;font-weight:600;">{cnt}</td></tr>'
                )
            st.markdown(
                f'<div class="demo-hint"><b>威胁类别分布</b>'
                f'（共 {len(findings)} 个风险点，覆盖 {len(cat_count)} 类威胁）'
                f'<table style="width:100%;border-collapse:collapse;margin-top:8px;'
                f'font-size:0.86rem;">{"".join(cat_rows)}</table></div>',
                unsafe_allow_html=True)

            # 4.2 严重度分布（指标卡）+ 规则命中 TOP
            sev_count = {}
            for f in findings:
                sev_count[f["severity"]] = sev_count.get(f["severity"], 0) + 1
            rule_count = {}
            for f in findings:
                rule_count[f["rule"]] = rule_count.get(f["rule"], 0) + 1
            top_rules = sorted(rule_count.items(), key=lambda x: -x[1])[:5]

            dash_c1, dash_c2 = st.columns([1, 1.4])
            with dash_c1:
                st.markdown("**严重度构成**")
                sev_order = ["严重", "高危", "中危", "低危"]
                sev_cols = {"严重": "metric-card-red", "高危": "metric-card-orange",
                            "中危": "metric-card-orange", "低危": "metric-card"}
                for sev in sev_order:
                    if sev_count.get(sev):
                        metric_card(sev_count[sev], f"{sev}风险点",
                                    color=sev_cols[sev], icon="⚠️")
            with dash_c2:
                st.markdown("**命中最多的规则 TOP5**")
                st.dataframe(
                    pd.DataFrame([{"规则": r, "命中次数": c} for r, c in top_rules]),
                    width="stretch", hide_index=True, height=230,
                    column_config={"规则": st.column_config.TextColumn(width="medium"),
                                   "命中次数": st.column_config.TextColumn(width="small")},
                )

            # 4.3 受影响文件分布
            file_count = {}
            for f in findings:
                file_count[f["file"]] = file_count.get(f["file"], 0) + 1
            if len(file_count) > 1:
                st.markdown("**受影响文件分布**")
                st.dataframe(
                    pd.DataFrame([{"文件": k, "风险点数": v}
                                  for k, v in sorted(file_count.items(),
                                                     key=lambda x: -x[1])]),
                    width="stretch", hide_index=True,
                    column_config={"文件": st.column_config.TextColumn(width="medium")},
                )

        # ===== 🔍 详情与证据溯源 =====
        if findings:
            sev_icon = {"严重": "🔴", "高危": "🟠", "中危": "🟡", "低危": "🟢"}
            rows = []
            for f in findings:
                rows.append({
                    "等级": sev_icon.get(f["severity"], "⚪") + " " + f["severity"],
                    "类别": f["category"],
                    "规则": f["rule"],
                    "位置": f"{f['file']}:{f['line']}",
                    "证据": f["evidence"],
                    "说明": f["description"],
                    "处置建议": f["suggestion"],
                })
            st.dataframe(pd.DataFrame(rows), width="stretch", height=380,
                         column_config={
                             "等级": st.column_config.TextColumn(width="small"),
                             "类别": st.column_config.TextColumn(width="small"),
                             "位置": st.column_config.TextColumn(width="small"),
                         })
            st.markdown("""
            <div class="demo-hint">
                <b>📌 可核验性说明</b>：每条结论都附带<b>原文行号 + 命中规则名</b>，
                可直接在技能包源文件中定位核对。规则快筛侧纯离线、零模型调用，
                因此规则结论<b>可重复、可审计、不随模型版本变化</b>。
            </div>
            """, unsafe_allow_html=True)

            # ===== 📄 导出检测报告 =====
            st.markdown("### 📄 导出检测报告")
            st.caption("导出的报告包含每条风险的规则名、行号、证据原文与处置建议，"
                       "可直接作为审计凭证交给评审。")
            export_c1, export_c2 = st.columns([1, 1])
            with export_c1:
                _csv = pd.DataFrame(rows).to_csv(index=False).encode("utf-8-sig")
                st.download_button(
                    "📥 下载 CSV 明细", _csv,
                    f"{sr['skill_name']}_findings.csv", "text/csv", width="stretch",
                )
            with export_c2:
                _md = _build_markdown_report(sr)
                st.download_button(
                    "📥 下载 Markdown 报告", _md.encode("utf-8"),
                    f"{sr['skill_name']}_report.md", "text/markdown", width="stretch",
                )
        else:
            st.success("🎉 未发现风险，该技能通过静态规则引擎全部检测。")


    # ==========================================

