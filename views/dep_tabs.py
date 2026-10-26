# -*- coding: utf-8 -*-
"""依赖漏洞检测视图的四个 Tab 渲染。

拆出来的原因：dep_scan.py 原本 649 行，四个 tab 的渲染全部堆在一个函数里，
既难定位也难维护。拆成四个独立函数后每个都在 100 行以内。

每个函数的签名一致：(result, summary, vulns, dep_list)
"""
import os

import pandas as pd
import streamlit as st

from views.common import build_fixed_requirements



def render_results_tab(result, summary, vulns, dep_list):
    """📊 漏洞研判结果"""
    if vulns:
        st.markdown(f"### 共检测到 {len(vulns)} 个已知漏洞")

        # 筛选器
        filt_col1, filt_col2, filt_col3 = st.columns(3)
        with filt_col1:
            sev_filter = st.multiselect(
                "风险等级", ["严重", "高危", "中危", "低危", "未知"],
                default=["严重", "高危", "中危"]
            )
        with filt_col2:
            conf_filter = st.multiselect(
                "置信度", ["高", "中", "低"],
                default=["高", "中"]
            )
        with filt_col3:
            priority_filter = st.multiselect(
                "修复优先级",
                ["🔴 立即修复", "🟠 尽快修复", "🟡 计划修复", "🟢 关注即可", "⚪ 低优先"],
                default=["🔴 立即修复", "🟠 尽快修复"]
            )

        # 过滤
        filtered = vulns
        if sev_filter:
            filtered = [v for v in filtered if v["severity"] in sev_filter]
        if conf_filter:
            filtered = [v for v in filtered if v.get("confidence", {}).get("level") in conf_filter]
        if priority_filter:
            filtered = [v for v in filtered if v.get("fix_priority", {}).get("label") in priority_filter]

        st.caption(f"当前显示 {len(filtered)} / {len(vulns)} 条（按修复优先级排序）")

        # 表格
        df_data = []
        for v in filtered:
            conf = v.get("confidence", {})
            conf_badge = {
                "高": "🟢 高",
                "中": "🟡 中",
                "低": "🔴 低"
            }.get(conf.get("level", ""), "⚪ 未知")

            epss = v.get("epss_score", 0)
            epss_str = f"**{epss:.1%}**" if epss > 0.1 else (f"{epss:.1%}" if epss > 0 else "N/A")

            df_data.append({
                "优先级": v.get("fix_priority", {}).get("label", "未知"),
                "CVE 编号": v["cve_id"],
                "组件": v["package"],
                "版本": v["version"],
                "版本依据": "⚠️ 下限推断" if v.get("version_basis") == "lower_bound" else "精确锁定",
                "层级": "🔸 间接" if v.get("is_transitive") else "🔹 直接",
                "生态": v.get("ecosystem", "PyPI"),
                "风险等级": v["severity"],
                "CVSS": v["cvss_score"],
                "置信度": conf_badge,
                "EPSS": epss_str,
                "修复版本": v.get("fixed_version", "未知"),
            })

        st.dataframe(
            pd.DataFrame(df_data),
            width="stretch",
            height=450,
            column_config={
                "优先级": st.column_config.TextColumn(width="small"),
                "CVSS": st.column_config.NumberColumn(width="small"),
                "层级": st.column_config.TextColumn(width="small"),
                "版本依据": st.column_config.TextColumn(width="small"),
                "置信度": st.column_config.TextColumn(width="small"),
                "EPSS": st.column_config.TextColumn(width="small"),
            }
        )
    else:
        st.success("🎉 未检测到已知漏洞，项目依赖安全状况良好。")


def render_evidence_tab(result, summary, vulns, dep_list):
    """🔍 漏洞详情与证据"""
    if vulns:
        st.markdown("### 🔍 漏洞详情与证据溯源")
        st.caption("展开查看每个漏洞的完整证据链，包括 NVD/GitHub 官方链接")

        # 只显示前 20 条高危/高置信度的
        display_vulns = sorted(vulns, key=lambda v: (
            v.get("fix_priority", {}).get("priority", 5),
            -v["cvss_score"]
        ))[:20]

        for i, v in enumerate(display_vulns, 1):
            conf = v.get("confidence", {})
            fp = v.get("fix_priority", {})
            epss = v.get("epss_score", 0)
            is_exploited = v.get("is_actively_exploited")

            # 展开面板标题
            dep_layer = "🔸间接" if v.get("is_transitive") else "🔹直接"
            exp_title = (
                f"{fp.get('label', '')} | {v['cve_id']} | "
                f"{v['package']} {v['version']} [{dep_layer}] | "
                f"CVSS {v['cvss_score']} | "
                f"置信度 {conf.get('level', '?')}"
            )

            with st.expander(exp_title, expanded=(i <= 3)):
                detail_col1, detail_col2 = st.columns([1, 1])

                with detail_col1:
                    st.markdown(f"**CVE 编号**: {v['cve_id']}")
                    st.markdown(f"**组件**: {v['package']} ({v.get('ecosystem', 'PyPI')})")
                    if v.get("is_transitive"):
                        st.markdown(
                            f"**依赖层级**: 🔸 间接依赖（一层推断"
                            f"{'，来自 ' + v['transitive_from'] if v.get('transitive_from') else ''}）"
                        )
                    else:
                        st.markdown("**依赖层级**: 🔹 直接依赖")
                    if v.get("version_basis") == "lower_bound":
                        st.markdown(
                            f"**当前版本**: {v['version']} ⚠️（声明下限，实际可能更高）"
                        )
                    else:
                        st.markdown(f"**当前版本**: {v['version']}")
                    st.markdown(f"**修复版本**: {v.get('fixed_version', '未知')}")
                    st.markdown(f"**CWE 类型**: {v.get('cwe_id', '未知')}")

                    st.divider()
                    st.markdown("**评分详情**")
                    st.markdown(f"- CVSS 分数: **{v['cvss_score']}** ({v.get('score_source', '')})")
                    st.markdown(f"- 分数类型: {'✅ 精确' if v.get('score_type') == 'exact' else '⚠️ 估算'}")
                    st.markdown(f"- EPSS 利用概率: **{epss:.2%}**")
                    if is_exploited:
                        st.warning("⚠️ 该漏洞存在活跃野外利用风险！")
                    st.markdown(f"- EPSS 百分位: 前 {v.get('epss_percentile', 0):.1f}%")

                with detail_col2:
                    st.markdown("**置信度评估**")
                    st.markdown(f"{conf.get('badge', '')} **{conf.get('level', '')}** 级置信度")
                    st.caption(conf.get('detail', ''))
                    if v.get("divergent"):
                        st.warning("⚠️ 源间分歧：多个漏洞库评分差异较大，本结果分数已采信 NVD。")

                    st.divider()
                    st.markdown("**修复建议**")
                    st.markdown(f"优先级: {fp.get('label', '')}")
                    st.markdown(f"紧急程度: {fp.get('urgency', '')}")
                    if v.get('fixed_version', '未知') != '未知':
                        st.markdown(f"升级到: `{v['package']}=={v['fixed_version']}`")

                    st.divider()
                    st.markdown("**📎 证据来源**")
                    for link in v.get("evidence_links", []):
                        st.markdown(f"- [{link['label']}]({link['url']})")

                # 漏洞描述
                if v.get("summary"):
                    st.caption(f"描述: {v['summary'][:250]}")

    else:
        st.success("无漏洞记录")


def render_fix_tab(result, summary, vulns, dep_list):
    """🔧 修复方案"""
    st.markdown("### 🔧 一键修复方案")
    st.caption("自动汇总所有可修复漏洞，生成升级后的 requirements.txt，一个包多个修复版本冲突时取最高。")

    if not vulns:
        st.success("🎉 未检测到漏洞，无需修复。")
    elif st.button("⚙️ 生成修复方案", type="primary"):
        from modules.vulnerability import generate_fix_plan

        fix_plan = generate_fix_plan(vulns)
        fix_map = fix_plan["fix_map"]
        unfixable = fix_plan["unfixable"]

        if fix_map:
            st.markdown(f"#### 📋 升级清单（{len(fix_map)} 个包）")
            plan_df = pd.DataFrame([
                {
                    "包名": pkg,
                    "当前版本": info["current"],
                    "升级到": f"≥ {info['target']}",
                    "关联漏洞": ", ".join(info["cve_ids"]),
                    "最高风险": info["severity"],
                }
                for pkg, info in fix_map.items()
            ])
            st.dataframe(plan_df, width="stretch", height=min(420, 36 + 35 * len(plan_df)))

            # 生成修改后的 requirements.txt
            req_path = st.session_state.get("req_file_path")
            fixed_content = build_fixed_requirements(req_path, fix_map, dep_list)

            st.markdown("#### 📥 下载修改后的 requirements.txt")
            st.caption("直接依赖已按修复版本升级（`>=修复版本`），间接依赖版本为推断值、不写入生成文件。")
            st.download_button(
                "📥 下载 requirements_fixed.txt",
                fixed_content.encode("utf-8"),
                "requirements_fixed.txt",
                "text/plain",
                width="stretch",
            )

            with st.expander("👀 预览修改后的 requirements.txt"):
                st.code(fixed_content, language="text")
        else:
            st.info("没有可自动修复的漏洞。")

        if unfixable:
            st.markdown(f"#### ⚠️ 暂无官方修复版本（{len(unfixable)} 个漏洞）")
            unfixable_df = pd.DataFrame([
                {
                    "CVE 编号": v["cve_id"],
                    "组件": v["package"],
                    "当前版本": v["version"],
                    "层级": "🔸 间接" if v.get("is_transitive") else "🔹 直接",
                    "风险等级": v["severity"],
                    "建议": "关注上游项目安全公告，等待官方补丁",
                }
                for v in unfixable
            ])
            st.dataframe(unfixable_df, width="stretch")


def render_report_tab(result, summary, vulns, dep_list):
    """📄 报告导出"""
    st.markdown("### 📄 生成审计报告")

    rep_col1, rep_col2 = st.columns(2)
    with rep_col1:
        report_format = st.radio("选择报告格式", ["DOCX (正式审计报告)", "PDF (精简报告)"])

    with rep_col2:
        st.info(
            "📋 报告包含：扫描摘要、漏洞清单（含置信度/EPSS/优先级）、"
            "证据溯源链接、修复建议"
        )

    if st.button("📝 生成并下载报告", type="primary"):
        with st.spinner("正在生成报告..."):
            from modules import report as report_gen

            if "DOCX" in report_format:
                try:
                    path = report_gen.generate_docx_report(result, result["sbom"])
                    mime = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                    with open(path, "rb") as f:
                        st.download_button(
                            "📥 下载 DOCX 审计报告", f.read(),
                            os.path.basename(path), mime, width="stretch"
                        )
                    st.success(f"✅ 报告已生成：`{path}`")
                except Exception as e:
                    st.error(f"DOCX 生成失败：{e}")

            if "PDF" in report_format:
                try:
                    path = report_gen.generate_pdf_report(result, result["sbom"])
                    mime = "application/pdf"
                    with open(path, "rb") as f:
                        st.download_button(
                            "📥 下载 PDF 报告", f.read(),
                            os.path.basename(path), mime, width="stretch"
                        )
                    st.success(f"✅ 报告已生成：`{path}`")
                except Exception as e:
                    st.error(f"PDF 生成失败：{e}")
