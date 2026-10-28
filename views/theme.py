# -*- coding: utf-8 -*-
"""统一视觉主题（浅色 · 简洁商务风）。

设计取向：白底 + 单一主色 + 大留白 + 轻阴影，去渐变、去装饰，
让「结论」和「数字」成为视觉焦点（参考 Notion / Linear 的克制感）。

用法：
    from views.theme import inject
    inject()
放在 ``st.set_page_config`` 之后、任何正文渲染之前。
"""
import streamlit as st

THEME_CSS = """
<style>
:root {
    --bg: #ffffff;
    --bg-soft: #f8f9fb;
    --card: #ffffff;
    --text: #111827;
    --text-sub: #6b7280;
    --text-faint: #9aa3af;
    --border: #e9ebef;
    --border-strong: #d9dde4;
    --accent: #2563eb;
    --accent-soft: #eff5ff;
    --accent-line: #d6e3fd;
    --green: #059669;  --green-soft: #ecfdf5;
    --amber: #b45309;  --amber-soft: #fffaf0;
    --rose: #dc2626;   --red-soft: #fef2f2;
    --sh-1: 0 1px 2px rgba(17, 24, 39, .04);
    --sh-2: 0 6px 20px rgba(17, 24, 39, .07);
    --r: 12px;
}

/* ---------- 全局 ---------- */
.stApp {
    background: var(--bg);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", sans-serif;
    color: var(--text);
}
html, body, [class*="css"] { color: var(--text); }
.block-container { padding-top: 1.6rem; padding-bottom: 3rem; max-width: 1180px; }
#MainMenu, footer { visibility: hidden; }
h1, h2, h3, h4 { color: var(--text); font-weight: 650; letter-spacing: -.2px; }

/* ---------- 侧边栏 ---------- */
section[data-testid="stSidebar"] {
    background: var(--bg-soft);
    border-right: 1px solid var(--border);
}
section[data-testid="stSidebar"] .block-container { padding-top: 1.4rem; }

/* ---------- 顶部标题区 ---------- */
.app-head {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--r);
    padding: 26px 30px;
    margin: 0 0 20px;
    box-shadow: var(--sh-1);
}
.app-head .t { font-size: 1.8rem; font-weight: 700; letter-spacing: -.6px; }
.app-head .s { font-size: .95rem; color: var(--text-sub); margin-top: 9px; line-height: 1.75; }
.app-head .s b { color: var(--accent); font-weight: 600; }
.chips { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 16px; }
.chip {
    background: var(--bg-soft);
    border: 1px solid var(--border);
    border-radius: 999px;
    padding: 4px 12px;
    font-size: .78rem;
    color: var(--text-sub);
}

/* ---------- 分区标题 ---------- */
.section-title {
    font-size: 1.12rem;
    font-weight: 650;
    margin: 22px 0 12px;
    color: var(--text);
    letter-spacing: -.2px;
}

/* ---------- 指标卡 ---------- */
.metric-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--r);
    padding: 16px 18px;
    margin: 6px 0;
    box-shadow: var(--sh-1);
    transition: box-shadow .18s ease, transform .18s ease;
}
.metric-card:hover { box-shadow: var(--sh-2); transform: translateY(-2px); }
.metric-icon { font-size: 15px; margin-bottom: 6px; opacity: .7; }
.metric-value {
    font-size: 1.7rem;
    font-weight: 700;
    line-height: 1.15;
    letter-spacing: -.5px;
    color: var(--text);
}
.metric-label { font-size: .79rem; color: var(--text-sub); margin-top: 4px; }

/* ---------- 结论卡 ---------- */
.decision-card {
    border: 1px solid var(--border);
    border-left: 4px solid var(--accent);
    border-radius: var(--r);
    padding: 24px 28px;
    margin: 6px 0 16px;
    background: var(--card);
    box-shadow: var(--sh-1);
}
.decision-card.dec-block  { border-left-color: var(--rose);  background: var(--red-soft); }
.decision-card.dec-review { border-left-color: var(--amber); background: var(--amber-soft); }
.decision-card.dec-pass   { border-left-color: var(--green); background: var(--green-soft); }
.decision-card.dec-idle   { border-left-color: var(--accent); background: var(--accent-soft); }
.decision-verdict { font-size: 1.65rem; font-weight: 700; letter-spacing: -.5px; color: var(--text); }
.decision-meta {
    margin-top: 12px; font-size: .92rem; color: var(--text-sub);
    display: flex; flex-wrap: wrap; gap: 20px;
}
.decision-meta b { color: var(--text); }
.decision-pointer {
    margin-top: 12px;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: .83rem; color: var(--text-sub);
    background: rgba(17, 24, 39, .035); border-radius: 8px; padding: 8px 12px;
}

/* ---------- 按钮 ---------- */
.stButton > button {
    border-radius: 9px;
    border: 1px solid var(--border);
    font-weight: 550;
    background: var(--card);
    color: var(--text);
    transition: all .16s ease;
}
.stButton > button:hover { border-color: var(--accent-line); color: var(--accent); background: var(--accent-soft); }
.stButton > button[kind="primary"] { background: var(--accent); border-color: var(--accent); color: #fff; }
.stButton > button[kind="primary"]:hover { background: #1d4fd7; border-color: #1d4fd7; color: #fff; }

/* ---------- 标签页（下划线式，去掉胶囊底） ---------- */
[data-baseweb="tab-list"] { gap: 6px; background: transparent; border-bottom: 1px solid var(--border); padding: 0; }
[data-baseweb="tab"] {
    background: transparent; color: var(--text-sub);
    font-weight: 550; padding: 10px 14px; border-radius: 0;
    border-bottom: 2px solid transparent;
}
[data-baseweb="tab"]:hover { color: var(--text); }
[data-baseweb="tab"][aria-selected="true"] { color: var(--accent); border-bottom-color: var(--accent); background: transparent; }
[data-baseweb="tab-highlight"] { background: transparent; }
[data-baseweb="tab-border"] { background: transparent; }

/* ---------- 表格 ---------- */
[data-testid="stDataFrame"] {
    border: 1px solid var(--border);
    border-radius: 10px;
    overflow: hidden;
    box-shadow: var(--sh-1);
}
[data-testid="stDataFrame"] * { font-size: .84rem; }

/* ---------- 消息框 / 展开区 / 上传 ---------- */
.stAlert { border-radius: 10px; border: 1px solid var(--border); box-shadow: none; }
[data-testid="stExpander"] { border: 1px solid var(--border); border-radius: 10px; background: var(--card); }
[data-testid="stExpander"] summary { font-weight: 550; }
[data-testid="stFileUploader"] {
    background: var(--bg-soft);
    border: 1px dashed var(--border-strong);
    border-radius: 10px;
    padding: 6px;
}

/* ---------- 进度 ---------- */
[data-testid="stProgress"] > div > div > div { background-color: var(--accent); }

/* ---------- 严重度徽章 ---------- */
.badge-critical { background:#fef2f2; color:#b91c1c; padding:3px 10px; border-radius:999px; font-size:12px; border:1px solid #fecaca; }
.badge-high     { background:#ecfdf5; color:#047857; padding:3px 10px; border-radius:999px; font-size:12px; border:1px solid #a7f3d0; }
.badge-medium   { background:#fffbeb; color:#92400e; padding:3px 10px; border-radius:999px; font-size:12px; border:1px solid #fde68a; }
.badge-low      { background:#fef2f2; color:#b91c1c; padding:3px 10px; border-radius:999px; font-size:12px; border:1px solid #fecaca; }
</style>
"""


def inject() -> None:
    """把主题样式注入当前页面（幂等，可重复调用）。"""
    st.markdown(THEME_CSS, unsafe_allow_html=True)