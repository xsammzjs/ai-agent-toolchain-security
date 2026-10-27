# -*- coding: utf-8 -*-
"""视图 5：离线演示模式

现场断网或外网被限流时，四源查询会失败。本视图预置 4 个演示场景，
宁可明确告知降级，也不伪装成正常结果 —— 答辩保命用。
"""
import pandas as pd
import streamlit as st



def render():
    """渲染本视图"""
    # ==========================================
    # 离线演示模式区（2026-10-15 新增 · 答辩保命）
    # ==========================================
    st.divider()
    st.markdown('<div id="demo-section"></div>', unsafe_allow_html=True)
    st.markdown('<div class="section-title">🎬 离线演示模式（答辩保障）</div>',
                unsafe_allow_html=True)
    st.caption(
        "现场断网或外网被限流时，四源查询会失败。传统做法是显示零漏洞——"
        "这会让评委误以为系统坏了。本模式预置4 个演示场景，"
        "**宁可明确告知降级，也不伪装成正常结果**。"
    )

    with st.container(border=True):
        net_col1, net_col2, net_col3 = st.columns([1, 1, 3])
        with net_col1:
            if st.button("🌐 检测网络连通性", key="net_probe_btn", width="stretch"):
                from modules import demo_mode as dm
                st.session_state.net_status = dm.probe_network()
                st.rerun()
        with net_col2:
            if st.button("🎬 加载演示数据集", key="demo_load_btn",
                         type="primary", width="stretch"):
                from modules import demo_mode as dm
                st.session_state.demo_data = dm.get_offline_vulns()
                st.rerun()
        with net_col3:
            if "net_status" in st.session_state:
                ok = st.session_state.net_status
                if ok:
                    st.success("✅ 网络正常，可使用在线模式（检出量更完整）")
                else:
                    st.warning(
                        "⚠️ **外网不可达** —— 建议切换到离线演示模式。"
                        "答辩现场若断网，这个提示会提前出现，避免演示失败。"
                    )

    if st.session_state.get("demo_data"):
        dd = st.session_state.demo_data
        with st.container(border=True):
            st.warning("⚠️ 当前为**离线演示数据**，非实时查询结果")
            st.markdown(f"**{dd.get('scenario', '')}**")
            st.caption(dd.get("narration", ""))
            st.dataframe(pd.DataFrame([
                {
                    "漏洞": v["cve_id"],
                    "依赖": f"{v['package']}=={v['version']}",
                    "严重度": v["severity"],
                    "CVSS": v["cvss_score"],
                    "置信度": f"{v['confidence']['level']}（{v['confidence']['detail'][:20]}）",
                    "修复优先级": v["fix_priority"]["label"],
                    "修复版本": v["fixed_version"],
                }
                for v in dd["vulns"]
            ]), width="stretch", height=260)



    # ==========================================
    # 辅助函数（已移至文件头部，见上）
    # ==========================================

