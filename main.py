# -*- coding: utf-8 -*-
"""main.py —— 应用入口

AI 技能与依赖漏洞检测平台
├── 视图 1：AI 技能安全检测    views/skill_scan.py
├── 视图 2：组合体检            views/combo_view.py
├── 视图 3：依赖漏洞检测        views/dep_scan.py
├── 视图 4：资产关联分析        views/chain_view.py
└── 视图 5：离线演示模式        views/demo_view.py

本文件只负责三件事：页面配置与样式、侧边栏导航、把请求路由到对应视图。
所有业务逻辑都在 modules/ 与 views/ 里，不往这里堆。
"""
import streamlit as st

from views import chain_view, combo_view, dep_scan, demo_view, skill_scan

# ==========================================
# 页面配置
# ==========================================
st.set_page_config(
    page_title="AI 技能与依赖漏洞检测平台",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ==========================================
# 界面样式
# ==========================================
st.markdown("""
<style>
/* ==========================================================
   AI 技能与依赖漏洞检测平台 · 界面样式
   ========================================================== */
:root {
    --bg: #f6f8fb;
    --bg-card: #ffffff;
    --text: #16202e;
    --text-sub: #4a5b6e;
    --text-faint: #8395a8;
    --border: #e2e8f0;
    --accent: #2563eb;
    --accent-soft: #eff4ff;
    --accent-line: #c7d7fe;
    --violet: #7c3aed;
    --green: #059669;
    --green-soft: #ecfdf5;
    --amber: #d97706;
    --amber-soft: #fffbeb;
    --rose: #e11d48;
    --red-soft: #fff1f2;
    --shadow-sm: 0 1px 2px rgba(16, 24, 40, 0.05);
    --shadow-lg: 0 12px 28px rgba(16, 24, 40, 0.10);
}

.stApp {
    background:
        radial-gradient(circle at 18% 0%, rgba(37, 99, 235, 0.055), transparent 42%),
        radial-gradient(circle at 82% 4%, rgba(124, 58, 237, 0.045), transparent 38%),
        var(--bg);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", sans-serif;
}
.stApp::before {
    content: "";
    position: fixed;
    inset: 0;
    pointer-events: none;
    z-index: 0;
    background-image:
        linear-gradient(rgba(37, 99, 235, 0.028) 1px, transparent 1px),
        linear-gradient(90deg, rgba(37, 99, 235, 0.028) 1px, transparent 1px);
    background-size: 28px 28px;
}
.stMain, .stApp > div { position: relative; z-index: 1; }
html, body, [class*="css"] { color: var(--text); }

/* ---------- 主横幅 ---------- */
.hero-banner {
    background: linear-gradient(135deg, #1e3a8a 0%, #2563eb 52%, #7c3aed 100%);
    border-radius: 18px;
    padding: 26px 32px;
    margin: 14px 0 22px;
    color: #fff;
    box-shadow: var(--shadow-lg);
    position: relative;
    overflow: hidden;
}
.hero-banner::before {
    content: "";
    position: absolute;
    right: -70px; top: -70px;
    width: 260px; height: 260px;
    border-radius: 50%;
    background: rgba(255, 255, 255, 0.07);
}
.hero-banner::after {
    content: "";
    position: absolute;
    right: 70px; bottom: -100px;
    width: 200px; height: 200px;
    border-radius: 50%;
    background: rgba(255, 255, 255, 0.05);
}
.hero-title {
    font-size: 1.85rem;
    font-weight: 750;
    letter-spacing: -0.4px;
    position: relative; z-index: 1;
}
.hero-sub {
    font-size: 0.94rem;
    opacity: 0.92;
    margin-top: 8px;
    position: relative; z-index: 1;
}
.hero-sub b { color: #c7d7fe; font-weight: 600; }
.hero-badges { margin-top: 15px; display: flex; flex-wrap: wrap; gap: 6px; position: relative; z-index: 1; }
.hero-chip {
    background: rgba(255, 255, 255, 0.16);
    border: 1px solid rgba(255, 255, 255, 0.22);
    border-radius: 999px;
    padding: 4px 12px;
    font-size: 0.78rem;
}

/* ---------- 侧边栏 ---------- */
section[data-testid="stSidebar"] { border-right: 1px solid var(--border); }
section[data-testid="stSidebar"] .block-container { padding-top: 1.3rem; }
.sidebar-brand { margin-bottom: 6px; }
.sidebar-brand-title {
    font-size: 1.15rem;
    font-weight: 750;
    color: var(--text);
    letter-spacing: -0.3px;
}
.sidebar-brand-sub { font-size: 0.71rem; color: var(--text-faint); margin-top: 3px; }

/* ---------- 分区标题 ---------- */
.section-title {
    font-size: 1.22rem;
    font-weight: 700;
    margin: 18px 0 12px;
    padding-left: 12px;
    border-left: 4px solid var(--accent);
    color: var(--text);
    position: relative;
}
.section-title::before {
    content: "";
    position: absolute;
    left: -4px; top: 0; bottom: 0;
    width: 4px;
    border-radius: 2px;
    background: linear-gradient(180deg, var(--accent), var(--violet));
}

/* ---------- 指标卡 ---------- */
.metric-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 13px;
    padding: 14px 16px;
    margin: 8px 0;
    box-shadow: var(--shadow-sm);
    position: relative;
    overflow: hidden;
    transition: transform .16s ease, box-shadow .16s ease;
}
.metric-card:hover { transform: translateY(-2px); box-shadow: var(--shadow-lg); }
.metric-card::before {
    content: "";
    position: absolute;
    left: 0; top: 0; bottom: 0;
    width: 3px;
    background: var(--accent);
}
.metric-card-green::before   { background: linear-gradient(90deg, #10b981, var(--green)); }
.metric-card-orange::before { background: linear-gradient(90deg, #f59e0b, var(--amber)); }
.metric-card-red::before    { background: linear-gradient(90deg, #ef4444, var(--rose)); }
.metric-icon { font-size: 16px; margin-bottom: 5px; opacity: 0.75; }
.metric-value {
    font-size: 1.72rem;
    font-weight: 750;
    line-height: 1.15;
    color: var(--text);
    letter-spacing: -0.5px;
}
.metric-label {
    font-size: 0.78rem;
    color: var(--text-sub);
    margin-top: 4px;
}

/* ---------- 提示条 ---------- */
.demo-hint {
    background: linear-gradient(135deg, #f8fbff, #fcfaff);
    border: 1px solid var(--accent-line);
    color: var(--text-sub);
    border-radius: 13px;
    padding: 15px 19px;
    margin: 10px 0;
    box-shadow: var(--shadow-sm);
    line-height: 1.78;
}
.demo-hint b { color: var(--accent); font-weight: 650; }

/* ---------- 徽章 ---------- */
.badge-high {
    background: var(--green-soft); color: #047857;
    padding: 3px 11px; border-radius: 999px;
    font-size: 12px; font-weight: 550; border: 1px solid #a7f3d0;
}
.badge-medium {
    background: var(--amber-soft); color: #92400e;
    padding: 3px 11px; border-radius: 999px;
    font-size: 12px; font-weight: 550; border: 1px solid #fde68a;
}
.badge-low {
    background: var(--red-soft); color: #b91c1c;
    padding: 3px 11px; border-radius: 999px;
    font-size: 12px; font-weight: 550; border: 1px solid #fecaca;
}

/* ---------- 表格 ---------- */
[data-testid="stDataFrame"] {
    border: 1px solid var(--border);
    border-radius: 12px;
    overflow: hidden;
    box-shadow: var(--shadow-sm);
}
[data-testid="stDataFrame"] * { font-size: 0.84rem; }

/* ---------- 进度 ---------- */
.scan-progress {
    display: flex; align-items: center; gap: 13px;
    background: linear-gradient(135deg, #f8fbff, #fbfaff);
    border: 1px solid var(--border); border-left: 3px solid var(--accent);
    border-radius: 12px; padding: 14px 18px; margin: 9px 0;
    box-shadow: var(--shadow-sm);
}
.scan-progress-stage { color: var(--text-faint); font-size: 0.85rem; }
.scan-progress-spin { font-size: 16px; animation: scan-spin 1.2s linear infinite; }
@keyframes scan-spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
[data-testid="stProgress"] > div > div > div { background-color: var(--accent); }
[data-testid="stProgress"] > div > div > div > div { background-color: #a5b4fc; }
[data-testid="stProgress"] p { color: var(--text-sub); font-size: 0.88rem; }

/* ---------- 分隔线 ---------- */
hr, [data-testid="stDivider"] { border-color: var(--border) !important; }

/* ---------- 标签页 ---------- */
[data-baseweb="tab-list"] {
    background: #f1f3f5; border: 1px solid var(--border);
    border-radius: 11px; padding: 4px; gap: 3px;
}
[data-baseweb="tab"] {
    background: transparent; color: var(--text-sub);
    border-radius: 8px; font-weight: 550; padding: 8px 16px;
    transition: all .16s ease;
}
[data-baseweb="tab"]:hover { background: rgba(255,255,255,0.7); color: var(--text); }
[data-baseweb="tab"][aria-selected="true"] {
    background: var(--bg-card); color: var(--accent);
    box-shadow: var(--shadow-sm);
}
[data-baseweb="tab-highlight"] { background-color: var(--accent); }
[data-baseweb="tab-border"] { background-color: transparent; }

/* ---------- 消息框 ---------- */
.stAlert {
    background: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    border-radius: 12px !important;
    box-shadow: var(--shadow-sm) !important;
}
div[data-testid="stAlertContainer"] p { color: var(--text) !important; }
</style>
""", unsafe_allow_html=True)

# ==========================================
# 侧边栏（只做导航，不放表单控件）
# ==========================================
VIEW_SKILL = "🛡️ AI 技能安全检测"
VIEW_COMBO = "🧬 组合体检"
VIEW_DEP = "📦 依赖漏洞检测"
VIEW_CHAIN = "🔗 资产关联分析"
VIEW_DEMO = "🎬 离线演示"

with st.sidebar:
    st.markdown("""
    <div class="sidebar-brand">
        <div class="sidebar-brand-title">AI 技能与依赖漏洞检测平台</div>
        <div class="sidebar-brand-sub">Skill 安全 · 依赖漏洞 · 资产关联</div>
    </div>
    """, unsafe_allow_html=True)

    st.divider()

    current_view = st.radio(
        "功能选择",
        [VIEW_SKILL, VIEW_COMBO, VIEW_DEP, VIEW_CHAIN, VIEW_DEMO],
        label_visibility="collapsed",
        key="main_view",
    )

    st.divider()
    st.caption("💡 所有结论均可追溯到原文行号，当场可核验")
    st.caption("🔒 规则检测纯离线；AI 研判可选启用，命中本地缓存零调用")

# ==========================================
# 会话状态
# ==========================================
# 说明：AI 研判为**可选**能力，未配置 MaaS 时自动降级为本地模板并明确显示
# 「未调用大模型」。检测结论全部由确定性规则 + OSV/NVD/GitHub/EPSS 权威数据得出，
# 代码级约束见 modules/adjudicator.py 的 assert_ai_not_judging()。
if "scan_done" not in st.session_state:
    st.session_state.scan_done = False
if "result" not in st.session_state:
    st.session_state.result = None
if "scanning" not in st.session_state:
    st.session_state.scanning = False
if "scan_file_path" not in st.session_state:
    st.session_state.scan_file_path = None
if "scan_result_pending" not in st.session_state:
    st.session_state.scan_result_pending = None
if "scan_error" not in st.session_state:
    st.session_state.scan_error = None

# ==========================================
# 主横幅
# ==========================================
st.markdown("""
<div id="top" class="hero-banner">
    <div class="hero-title">AI 技能与依赖漏洞检测平台</div>
    <div class="hero-sub">AI 技能安全检测 · 依赖漏洞检测 · <b>资产关联分析</b> · 权威置信度评级 · 证据溯源</div>
    <div class="hero-badges">
        <span class="hero-chip">OWASP Agentic Skills Top10</span>
        <span class="hero-chip">真实样本 TPR 100% / FPR 2.0%</span>
        <span class="hero-chip">规则检测纯离线 · 33ms</span>
    </div>
</div>
""", unsafe_allow_html=True)

# ==========================================
# 依赖漏洞扫描的执行与进度（依赖视图用）
# ==========================================
# 线程写不了 st.session_state（它绑定脚本线程上下文），进度桥用 cache_resource：
# 它跨 rerun 返回同一对象，普通 dict 线程读写简单可靠。按 session_id 分箱隔离。
@st.cache_resource
def _get_scan_bridge() -> dict:
    """扫描线程与主线程之间的进度桥 {session_id: {stage, done, result, error}}"""
    return {}


def _current_session_id() -> str:
    try:
        from streamlit.runtime.scriptrunner import get_script_run_ctx
        ctx = get_script_run_ctx()
        return ctx.session_id if ctx else "default"
    except Exception:
        return "default"


_sid = _current_session_id()
_scan_bridge = _get_scan_bridge()
# 放进 session_state 供各视图模块取用（避免 views → main 的循环导入）
st.session_state.scan_bridge = _scan_bridge
st.session_state.session_id = _sid


@st.fragment(run_every=1.2)
def _scan_progress_ui():
    """只负责画进度条。结果交接由主脚本负责（见下方 _collect_scan_result）。"""
    box = _scan_bridge.get(_sid, {})
    percent = box.get("percent", 0)
    stage = box.get("stage", "准备中…")
    st.progress(percent / 100,
                text=f"正在执行多源漏洞研判… {stage}（{percent}%）")
    # 🔴 扫描完成必须主动触发整页 rerun。
    #    fragment 的定时重跑只刷新自己这一小块，主脚本不会跟着跑；
    #    而结果交接（_collect_scan_result）在主脚本里 —— 后台线程早就完成了，
    #    页面却永远停在最后一条进度消息上，用户以为「卡死」。
    #    （2026-10-27 修复：用户扫 22KB 的项目等了 6 分钟，实际 37 秒就扫完了。）
    if box.get("done"):
        st.rerun(scope="app")


def _collect_scan_result() -> bool:
    """从进度桥取回扫描结果。幂等 —— 每次 rerun 都可以安全调用。

    🔴 早期版本把交接逻辑放在 fragment 里，结果依赖 fragment 的定时重跑，
    某些场景下（后台线程已完成但 fragment 未再触发）结果永远回不来，
    页面一直卡在「扫描中」。改成主脚本每次 rerun 都拉一次，稳。
    """
    box = _scan_bridge.get(_sid, {})
    if not box.get("done"):
        return False
    if box.get("error"):
        st.session_state.scan_error = box["error"]
    else:
        st.session_state.scan_result_pending = box["result"]
    return True


# 每次 rerun 先尝试取回结果
_collect_scan_result()

if st.session_state.scanning:
    if st.session_state.scan_error is not None:
        err = st.session_state.scan_error
        st.session_state.scan_error = None
        st.session_state.scanning = False
        _scan_bridge.pop(_sid, None)
        st.error(f"❌ 扫描执行失败：{err}")
    elif st.session_state.scan_result_pending is not None:
        st.session_state.result = st.session_state.scan_result_pending
        st.session_state.scan_result_pending = None
        st.session_state.scan_done = True
        st.session_state.req_file_path = (
            st.session_state.scan_file_path
            if st.session_state.scan_file_path.endswith(".txt") else None
        )
        st.session_state.scanning = False
        _scan_bridge.pop(_sid, None)
        st.rerun()
    else:
        _scan_progress_ui()

# ==========================================
# 路由
# ==========================================
if current_view == VIEW_SKILL:
    skill_scan.render()
elif current_view == VIEW_COMBO:
    combo_view.render()
elif current_view == VIEW_DEP:
    dep_scan.render()
elif current_view == VIEW_CHAIN:
    chain_view.render()
elif current_view == VIEW_DEMO:
    demo_view.render()
