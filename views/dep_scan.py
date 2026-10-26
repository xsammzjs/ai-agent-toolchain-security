# -*- coding: utf-8 -*-
"""视图 2：依赖漏洞检测

上传项目包，解析出全部依赖，用 OSV / NVD / GitHub Advisory 四个权威漏洞库
交叉验证，给出带置信度评级和修复优先级的漏洞清单，并可生成 SBOM 与审计报告。
"""
import os

import pandas as pd
import streamlit as st

from views.common import section_title, build_fixed_requirements


def _start_scan(uploaded_file, mode_map_key, do_epss, use_nvd, do_transitive):
    """启动依赖漏洞扫描（后台线程 + 进度轮询）"""
    import shutil
    import threading

    from modules.engine import ScanEngine

    _scan_bridge = st.session_state.scan_bridge
    _sid = st.session_state.session_id

    TEMP_DIR = "temp_upload"
    if os.path.exists(TEMP_DIR):
        shutil.rmtree(TEMP_DIR)
    os.makedirs(TEMP_DIR, exist_ok=True)

    # 🔴 安全：上传文件名可能带路径分隔符或 '..'，必须只取basename，
    #    否则可以写到 temp_upload 之外的任意位置（路径穿越）。
    safe_name = os.path.basename(uploaded_file.name.replace("\\", "/")).strip() or "upload.txt"
    file_path = os.path.join(TEMP_DIR, safe_name)
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())

    mode = mode_map_key
    _scan_bridge[_sid] = {"stage": "正在解析依赖文件…", "percent": 0,
                          "done": False, "result": None, "error": None}
    st.session_state.scanning = True
    st.session_state.scan_file_path = file_path

    def _scan_worker():
        box = _scan_bridge[_sid]

        def _progress_cb(msg, percent=None):
            if percent is not None:
                box["percent"] = percent
            box["stage"] = msg

        try:
            engine = ScanEngine()
            r = engine.run_full_scan(
                uploaded_file_path=file_path,
                upload_mode=mode,
                project_name=safe_name.rsplit(".", 1)[0],
                include_transitive=do_transitive,
                use_nvd=use_nvd,
                do_epss=do_epss,
                progress_cb=_progress_cb,
            )
            box["result"] = r
        except Exception as e:
            box["error"] = str(e)
        box["done"] = True

    threading.Thread(target=_scan_worker, daemon=True).start()


def _render_upload():
    """上传区：放在主内容区，不占用侧边栏空间"""
    section_title("📤 上传项目文件")

    mode_map = {
        "requirements.txt": "requirements",
        "项目压缩包 (ZIP/RAR)": "archive",
        "package.json (npm)": "npm",
    }
    up_col1, up_col2 = st.columns([1, 1.2])

    with up_col1:
        upload_mode_label = st.radio(
            "选择上传方式",
            list(mode_map.keys()),
            key="dep_upload_mode",
        )
        uploaded_file = st.file_uploader(
            "选择文件",
            type=["txt", "zip", "rar", "json"],
            key="dep_file",
            help="支持 requirements.txt, .zip, .rar, package.json",
        )

    with up_col2:
        st.markdown("**⚙️ 扫描选项**")
        do_epss = st.checkbox("EPSS 利用预测", value=True, key="dep_epss",
                              help="查询 FIRST EPSS，评估漏洞30天内被利用的概率")
        use_nvd = st.checkbox("NVD 交叉验证", value=True, key="dep_nvd",
                              help="使用 NIST NVD 数据库进行交叉验证（需联网）")
        do_transitive = st.checkbox("间接依赖检测（一层推断）", value=False,
                                    key="dep_transitive",
                                    help="自动推断直接依赖的一层间接依赖并检测漏洞。"
                                         "扫描时间会显著增加，且版本为约束推断值，"
                                         "精确检测建议使用 pip freeze 完整清单")
        st.caption("💡 每个漏洞结论都有 NVD/GitHub 官方链接可验证")

    if st.button("🚀 开始安全扫描", type="primary", key="dep_scan_btn",
                 disabled=not uploaded_file, width="stretch"):
        _start_scan(uploaded_file, mode_map[upload_mode_label],
                    do_epss, use_nvd, do_transitive)
        st.rerun()


def render():
    """渲染本视图"""
    section_title("📦 依赖漏洞检测")
    st.caption(
        "上传项目包后自动解析出全部依赖，用 OSV / NVD / GitHub Advisory 四个"
        "权威漏洞库交叉验证，给出带置信度评级和修复优先级的漏洞清单。"
    )

    _render_upload()

    render_results()


def render_results():
    """渲染依赖漏洞扫描结果。

    被「依赖漏洞检测」视图和「资产关联分析」视图的依赖侧面板共用，
    保证两处展示完全一致。
    """
    if not (st.session_state.scan_done and st.session_state.result):
        return


    result = st.session_state.result
    summary = result["summary"]
    vulns = result["vulns"]
    dep_list = result["dep_list"]
    st.session_state.dep_list = dep_list  # 资产图谱读取依赖侧节点

    # 间接依赖截断提示（v3.1 新增）
    t_info = result.get("transitive_info") or {}
    if t_info.get("deps"):
        st.info(f"ℹ️ 本次推断出 {len(t_info['deps'])} 个一层间接依赖"
                f"（依赖总数中已计入）。间接依赖版本为约束推断值，仅供参考。")
    if t_info.get("truncated"):
        st.warning(f"⚠️ 间接依赖超过上限 {t_info.get('limit', 0)} 个，已截断。"
                   f"建议用 `pip freeze > requirements.txt` 导出完整清单后扫描。")

    # 查询失败披露：网络中断/限流时，"零漏洞"不再可信，必须明确告知
    qe_total = summary.get("query_error_total", 0)
    if qe_total:
        qe = summary.get("query_errors", {})
        st.error(
            f"⚠️ 本次扫描有 **{qe_total} 次数据源查询失败**"
            f"（{'、'.join(f'{k}×{v}' for k, v in qe.items() if v)}）。"
            f"失败的依赖**未被判定为安全**，漏洞数量可能偏低，请检查网络后重新扫描。"
        )

    # 检测覆盖度披露（原实现静默丢弃部分依赖，用户完全看不到，属于隐性漏检）
    if summary.get("skipped_count"):
        with st.expander(
            f"⚠️ 有 {summary['skipped_count']} 个依赖未纳入检测（点击查看）",
            expanded=True,
        ):
            st.caption(
                "以下依赖的版本声明无法定位实际安装版本，因此未查询漏洞库。"
                "用 `pip freeze > requirements.txt` 导出精确版本后可覆盖。"
            )
            st.dataframe(
                pd.DataFrame([
                    {"包名": d["package"], "声明版本": d["version"], "未检测原因": d["reason"]}
                    for d in summary.get("skipped_deps", [])
                ]),
                width="stretch",
                hide_index=True,
            )

    # 版本下限推断披露：>= / ~= 声明按最坏情况检查，结论偏保守，必须告知用户
    if summary.get("lower_bound_count"):
        st.info(
            f"ℹ️ 有 {summary['lower_bound_count']} 条结论基于版本下限推断"
            f"（依赖声明为 `>=` / `~=`，实际安装版本可能更高）。"
            f"这类结论偏保守，可能包含已在新版本中修复的漏洞；"
            f"用 `pip freeze` 导出精确版本可获得更准确结果。"
        )

    # ===== 顶部指标卡 =====
    st.markdown('<div class="section-title">📊 扫描总览</div>', unsafe_allow_html=True)
    col1, col2, col3, col4, col5, col6 = st.columns(6)

    with col1:
        dep_extra = f"（含间接 {summary.get('indirect_count', 0)}）" if summary.get('indirect_count') else ""
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-icon">📦</div>
            <div class="metric-value">{summary['total_dependencies']}</div>
            <div class="metric-label">依赖总数{dep_extra}</div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        critical = summary['critical_count']
        vuln_color = "#e74c3c" if critical > 0 else "#2e9e6b"
        st.markdown(f"""
        <div class="metric-card {'metric-card-red' if critical > 0 else 'metric-card-green'}">
            <div class="metric-icon">🐛</div>
            <div class="metric-value" style="color:{vuln_color}">{summary['total_vulnerabilities']}</div>
            <div class="metric-label">漏洞总数</div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div class="metric-card metric-card-red">
            <div class="metric-icon">🔥</div>
            <div class="metric-value" style="color:#e74c3c">{critical}</div>
            <div class="metric-label">严重/高危</div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown(f"""
        <div class="metric-card metric-card-green">
            <div class="metric-icon">✅</div>
            <div class="metric-value" style="color:#2e9e6b">{summary['high_confidence_count']}</div>
            <div class="metric-label">高置信度</div>
        </div>
        """, unsafe_allow_html=True)

    with col5:
        st.markdown(f"""
        <div class="metric-card metric-card-orange">
            <div class="metric-icon">⏰</div>
            <div class="metric-value" style="color:#e74c3c">{summary['priority_1_count']}</div>
            <div class="metric-label">需立即修复</div>
        </div>
        """, unsafe_allow_html=True)

    with col6:
        exploited = summary.get('actively_exploited_count', 0)
        exp_color = "#e74c3c" if exploited > 0 else "#8a97a8"
        st.markdown(f"""
        <div class="metric-card {'metric-card-red' if exploited > 0 else 'metric-card-gray'}">
            <div class="metric-icon">🎯</div>
            <div class="metric-value" style="color:{exp_color}">{exploited}</div>
            <div class="metric-label">活跃利用风险</div>
        </div>
        """, unsafe_allow_html=True)

    st.divider()

    # ===== 可视化仪表盘 =====
    if vulns:
        st.markdown('<div class="section-title">📈 可视化仪表盘</div>', unsafe_allow_html=True)

        # ---- 第一行：风险等级分布 + 置信度分布 ----
        viz_col1, viz_col2 = st.columns(2)

        with viz_col1:
            with st.container(border=True):
                st.markdown('<div class="viz-title">漏洞风险等级分布</div>', unsafe_allow_html=True)
                sev_counts = {"严重": 0, "高危": 0, "中危": 0, "低危": 0, "未知": 0}
                for v in vulns:
                    sev = v.get("severity", "未知")
                    if sev in sev_counts:
                        sev_counts[sev] += 1
                # 转置：每个等级一列，颜色就能一一对应
                sev_df = pd.DataFrame({
                    "严重": [sev_counts["严重"]],
                    "高危": [sev_counts["高危"]],
                    "中危": [sev_counts["中危"]],
                    "低危": [sev_counts["低危"]],
                    "未知": [sev_counts["未知"]],
                })
                st.bar_chart(sev_df, width="stretch",
                             color=["#c0392b", "#e74c3c", "#f39c12", "#27ae60", "#95a5a6"])

        with viz_col2:
            with st.container(border=True):
                st.markdown('<div class="viz-title">置信度评级分布</div>', unsafe_allow_html=True)
                conf_counts = {"高": 0, "中": 0, "低": 0}
                for v in vulns:
                    level = v.get("confidence", {}).get("level", "低")
                    if level in conf_counts:
                        conf_counts[level] += 1
                conf_df = pd.DataFrame({
                    "高": [conf_counts["高"]],
                    "中": [conf_counts["中"]],
                    "低": [conf_counts["低"]],
                })
                st.bar_chart(conf_df, width="stretch",
                             color=["#27ae60", "#f39c12", "#e74c3c"])

        # ---- 第二行：CVSS vs EPSS 散点图（关键图）----
        with st.container(border=True):
            st.markdown('<div class="viz-title">🎯 漏洞风险矩阵：CVSS 严重度 × EPSS 利用概率</div>', unsafe_allow_html=True)
            st.caption("右上角 = 又严重又容易被打，最危险 | 圆圈大小 = 置信度")

            scatter_data = []
            for v in vulns:
                cvss = v.get("cvss_score", 0)
                epss = v.get("epss_score", 0)
                if cvss > 0:
                    conf_w = {"高": 3, "中": 2, "低": 1}.get(v.get("confidence", {}).get("level", "低"), 1)
                    scatter_data.append({
                        "CVSS 分数": cvss,
                        "EPSS 利用概率": epss * 100,
                        "严重程度": v.get("severity", "未知"),
                        "置信权重": conf_w * 30,
                        "组件": v.get("package", ""),
                        "CVE": v.get("cve_id", ""),
                    })

            if scatter_data:
                scatter_df = pd.DataFrame(scatter_data)
                # 颜色映射
                color_map = {"严重": "#c0392b", "高危": "#e74c3c", "中危": "#f39c12", "低危": "#27ae60", "未知": "#95a5a6"}
                scatter_df["颜色"] = scatter_df["严重程度"].map(color_map)

                st.scatter_chart(
                    scatter_df,
                    x="CVSS 分数",
                    y="EPSS 利用概率",
                    x_label="CVSS 分数（越高越危险）",
                    y_label="EPSS 利用概率 %（越高越容易被攻击）",
                    size="置信权重",
                    color="颜色",
                    width="stretch",
                )

        # ---- 第三行：Top 依赖漏洞数 + 修复优先级分布 ----
        viz_col3, viz_col4 = st.columns(2)

        with viz_col3:
            with st.container(border=True):
                st.markdown('<div class="viz-title">🔝 漏洞最多的依赖包</div>', unsafe_allow_html=True)
                pkg_counts = {}
                for v in vulns:
                    pkg = v.get("package", "未知")
                    pkg_counts[pkg] = pkg_counts.get(pkg, 0) + 1
                top_pkgs = sorted(pkg_counts.items(), key=lambda x: x[1], reverse=True)[:8]
                # 转置为单行多列
                pkg_data = {p[0]: [p[1]] for p in top_pkgs}
                pkg_df = pd.DataFrame(pkg_data)
                st.bar_chart(pkg_df, width="stretch")

        with viz_col4:
            with st.container(border=True):
                st.markdown('<div class="viz-title">🔧 修复优先级分布</div>', unsafe_allow_html=True)
                priority_labels = ["立即修复", "尽快修复", "计划修复", "关注即可", "低优先"]
                pri_counts = {label: 0 for label in priority_labels}
                label_map = {
                    "🔴 立即修复": "立即修复", "🟠 尽快修复": "尽快修复",
                    "🟡 计划修复": "计划修复", "🟢 关注即可": "关注即可",
                    "⚪ 低优先": "低优先"
                }
                for v in vulns:
                    raw = v.get("fix_priority", {}).get("label", "低优先")
                    clean = label_map.get(raw, "低优先")
                    if clean in pri_counts:
                        pri_counts[clean] += 1
                pri_df = pd.DataFrame({
                    "立即修复": [pri_counts["立即修复"]],
                    "尽快修复": [pri_counts["尽快修复"]],
                    "计划修复": [pri_counts["计划修复"]],
                    "关注即可": [pri_counts["关注即可"]],
                    "低优先": [pri_counts["低优先"]],
                })
                st.bar_chart(pri_df, width="stretch",
                             color=["#c0392b", "#e74c3c", "#f39c12", "#27ae60", "#95a5a6"])

        st.divider()

    # ===== 标签页 =====
    tab1, tab2, tab3, tab4 = st.tabs([
        "📊 漏洞研判结果", "🔍 漏洞详情与证据", "🔧 修复方案", "📄 报告导出"
    ])

    # ===== Tab 1: 漏洞研判结果 =====
    with tab1:
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

    # ===== Tab 2: 漏洞详情与证据 =====
    with tab2:
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

    # ===== Tab 3: 一键修复方案（v3.1 新增）=====
    with tab3:
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

    # ===== Tab 4: 报告导出 =====
    with tab4:
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
