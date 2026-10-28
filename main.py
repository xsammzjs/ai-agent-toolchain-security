# -*- coding: utf-8 -*-
"""main.py —— 应用入口（单页应用）

AI 技能组合风险体检站
├── ★ 首页       views/overview.py   唯一入口：上传 → 一键体检 → 结论卡
│                                    + 标签页（总览 / 关系图 / 依赖漏洞 / 合规对照）
└── 离线演示     views/demo_view.py  首页底部「断网备用（离线演示）」展开区

本文件只负责三件事：页面配置、注入主题、把请求路由到首页。
所有业务逻辑都在 modules/ 与 views/ 里，不往这里堆。
"""
import streamlit as st

from views import overview
from views.theme import inject as _inject_theme

# ==========================================
# 页面配置
# ==========================================
st.set_page_config(
    page_title="AI 技能组合风险体检站",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ==========================================
# 主题样式（浅色 · 简洁商务风，统一定义在 views/theme.py）
# ==========================================
_inject_theme()

# ==========================================
# 侧边栏（只做品牌与提示，不放表单控件）
# ==========================================
with st.sidebar:
    st.markdown("""
    <div style="margin-bottom:4px;">
        <div style="font-size:1.05rem;font-weight:650;color:#111827;letter-spacing:-.2px;">
            AI 技能组合风险体检站</div>
        <div style="font-size:.72rem;color:#9aa3af;margin-top:3px;">
            技能组合风险 · 可核验 · 离线可复算</div>
    </div>
    """, unsafe_allow_html=True)

    st.divider()
    st.caption("💡 每条结论都能追溯到原文行号，当场可核验")
    st.caption("🔒 规则检测纯离线；AI 判断可选，命中缓存零调用")
    st.divider()
    st.caption("上传技能包 → 一键体检 → 出安装决定")
    st.caption("断网时用首页底部的「离线演示」")

# ==========================================
# 会话状态
# ==========================================
# 说明：AI 判断为**可选**能力，未配置 MaaS 时自动降级为本地模板并明确显示
# 「未调用大模型」。检测结论全部由确定性规则 + OSV/NVD/GitHub/EPSS 权威数据得出，
# 代码级约束见 modules/adjudicator.py 的 assert_ai_not_judging()。

# ==========================================
# 顶部标题区
# ==========================================
st.markdown("""
<div class="app-head">
    <div class="t">AI 技能组合风险体检站</div>
    <div class="s">上传一个技能包 → <b>一键体检</b> → 直接给出「能不能装」的结论。<br>
    不只看单个技能有没有问题，更看多个技能<b>凑在一起</b>会不会出事。</div>
    <div class="chips">
        <span class="chip">真实样本 检出 100% · 误报 2.0%</span>
        <span class="chip">规则检测纯离线 · 33 毫秒</span>
        <span class="chip">每条结论可追溯到原文行号</span>
        <span class="chip">OWASP Agentic Skills Top 10</span>
    </div>
</div>
""", unsafe_allow_html=True)

# ==========================================
# 路由
# ==========================================
overview.render()