"""
双链——软件供应链安全检测系统
=======================================
Streamlit Web 界面
核心功能：精准漏洞检测 + 多源证据溯源 + 修复优先级排序
"""
import streamlit as st
import os
import sys
import re
import shutil
import pandas as pd
import zipfile
import io
import tempfile
import time
import threading
from datetime import datetime

from modules.engine import ScanEngine


def _safe_ai_markdown(text: str) -> str:
    """转义 AI 输出中会触发意外 Markdown 格式的字符（删除线/分隔线/链接/行内代码），保留加粗和列表。"""
    if not text:
        return text
    text = text.replace("~", "\\~")
    text = text.replace("[", "\\[").replace("]", "\\]")
    text = text.replace("`", "\\`")
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if line.strip() in ("---", "***", "___", "- - -", "* * *"):
            lines[i] = "—"
    return "\n".join(lines)


# ==========================================
# 辅助函数（定义在使用之前，避免 NameError）
# ==========================================
def _build_fixed_requirements(req_path: str | None, fix_map: dict, dep_list: list[dict]) -> str:
    """
    根据修复方案生成修改后的 requirements.txt 内容（v3.1 新增）。

    - 上传的是 requirements.txt：逐行替换有修复版本的包（保留注释和其他行）
    - 其他上传模式：按依赖清单生成（仅直接依赖，间接依赖为推断值不写入）
    """
    import re as _re

    lines = []
    if req_path and os.path.exists(req_path):
        with open(req_path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                stripped = line.strip()
                # 注释、空行、pip 指令行（-r / --index 等）原样保留
                if not stripped or stripped.startswith(("#", "-", "--")):
                    lines.append(line.rstrip("\n"))
                    continue
                m = _re.match(r"^([A-Za-z0-9_.-]+)", stripped)
                pkg = m.group(1).lower() if m else None
                if pkg and pkg in fix_map:
                    info = fix_map[pkg]
                    cves = ", ".join(info["cve_ids"][:3])
                    lines.append(f"{pkg}>={info['target']}  # 修复: {cves}")
                else:
                    lines.append(line.rstrip("\n"))
    else:
        lines.append("# 由双链软件供应链安全检测系统自动生成（已包含修复版本）")
        for dep in dep_list:
            if dep.get("is_transitive"):
                continue  # 间接依赖版本为推断值，不写入
            pkg = dep["package"]
            if pkg in fix_map:
                info = fix_map[pkg]
                lines.append(f"{pkg}>={info['target']}  # 修复: {', '.join(info['cve_ids'][:3])}")
            else:
                ver = dep.get("version", "")
                if not ver:
                    lines.append(pkg)
                elif ver.startswith((">", "<", "=", "~", "!")):
                    lines.append(f"{pkg}{ver}")
                else:
                    lines.append(f"{pkg}=={ver}")
    return "\n".join(lines) + "\n"


# ==========================================
# 页面配置
# ==========================================
st.set_page_config(
    page_title="双链·软件供应链安全检测系统",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==========================================
# 界面样式（v3.1 二版：深藏青横幅 + 点阵纹理 + 卡片化）
# ==========================================
st.markdown("""
<style>
    /* ---- 整体背景：浅灰蓝 + 极淡几何点阵（设计稿质感）---- */
    .stApp {
        background-color: #f6f8fb;
        background-image:
            radial-gradient(circle, #dbe3ee 1px, transparent 1.6px),
            linear-gradient(180deg, #edf1f7 0%, #f6f8fb 32%);
        background-size: 26px 26px, 100% 100%;
    }

    /* ---- 顶部横幅：深藏青渐变 + 几何圆环装饰 ---- */
    .hero-banner {
        background: linear-gradient(135deg, #16293f 0%, #1a3a5c 55%, #2a5784 100%);
        border-radius: 16px;
        padding: 28px 32px 26px;
        color: #ffffff;
        position: relative;
        overflow: hidden;
        box-shadow: 0 4px 16px rgba(26, 58, 92, 0.20);
        margin-bottom: 10px;
    }
    .hero-banner::before {
        content: "";
        position: absolute; right: -40px; top: -70px;
        width: 240px; height: 240px;
        border: 2px solid rgba(255, 255, 255, 0.10);
        border-radius: 50%;
    }
    .hero-banner::after {
        content: "";
        position: absolute; right: 36px; top: -24px;
        width: 140px; height: 140px;
        border: 2px solid rgba(255, 255, 255, 0.16);
        border-radius: 50%;
    }
    .hero-title {
        font-size: 1.85rem; font-weight: bold; color: #ffffff;
        letter-spacing: 2px; line-height: 1.25;
    }
    .hero-sub {
        color: rgba(255, 255, 255, 0.78);
        font-size: 0.92rem; margin-top: 8px; letter-spacing: 0.5px;
    }
    .hero-badges { margin-top: 14px; }
    .hero-chip {
        display: inline-block;
        background: rgba(255, 255, 255, 0.12);
        border: 1px solid rgba(255, 255, 255, 0.28);
        border-radius: 999px; padding: 3px 14px;
        font-size: 12px; color: rgba(255, 255, 255, 0.92);
        margin-right: 8px; letter-spacing: 0.5px;
    }

    /* ---- 分区标题：左色条 ---- */
    .section-title {
        font-size: 1.15rem; font-weight: bold; color: #1a3a5c;
        border-left: 4px solid #1a3a5c; border-radius: 2px;
        padding-left: 10px; margin: 8px 0 12px 0;
    }

    /* ---- 指标卡：白底 + 顶部色条 + hover 浮起 ---- */
    .metric-card {
        background: #ffffff;
        border: 1px solid #e3e8ef;
        border-top: none;
        border-radius: 12px;
        padding: 14px 12px 16px;
        text-align: center;
        box-shadow: 0 2px 6px rgba(26, 58, 92, 0.05);
        position: relative;
        overflow: hidden;
        transition: box-shadow .2s ease, transform .2s ease;
    }
    .metric-card:hover {
        box-shadow: 0 6px 16px rgba(26, 58, 92, 0.13);
        transform: translateY(-2px);
    }
    .metric-card::before {
        content: "";
        position: absolute; top: 0; left: 0; right: 0;
        height: 4px; background: #1a3a5c;
    }
    .metric-card-red::before    { background: #e74c3c; }
    .metric-card-green::before  { background: #2e9e6b; }
    .metric-card-orange::before { background: #f39c12; }
    .metric-card-gray::before   { background: #95a5a6; }
    .metric-icon { font-size: 15px; margin-bottom: 2px; }
    .metric-value { font-size: 30px; font-weight: bold; color: #1a3a5c; line-height: 1.15; }
    .metric-label { font-size: 11px; color: #8a97a8; margin-top: 5px; letter-spacing: 1px; }

    /* ---- 徽章：圆角精致化 ---- */
    .badge-high {
        background: #e8f6ee; color: #1d7a4f;
        padding: 3px 10px; border-radius: 999px;
        font-size: 12px; font-weight: 500; border: 1px solid #bfe6d0;
    }
    .badge-medium {
        background: #fdf6e3; color: #8a6d1a;
        padding: 3px 10px; border-radius: 999px;
        font-size: 12px; font-weight: 500; border: 1px solid #f0e0ac;
    }
    .badge-low {
        background: #fdecea; color: #b03a2e;
        padding: 3px 10px; border-radius: 999px;
        font-size: 12px; font-weight: 500; border: 1px solid #f2c4bd;
    }

    /* ---- 侧边栏：浅灰底 + 品牌卡 ---- */
    section[data-testid="stSidebar"] {
        background: #eef1f6;
        border-right: 1px solid #dde3ec;
    }
    .sidebar-brand {
        background: #ffffff; border: 1px solid #e3e8ef;
        border-radius: 12px; padding: 12px 14px; margin-bottom: 4px;
        box-shadow: 0 1px 4px rgba(26, 58, 92, 0.05);
    }
    .sidebar-brand-title { font-weight: bold; color: #1a3a5c; font-size: 1.05rem; }
    .sidebar-brand-sub { font-size: 0.75rem; color: #8a97a8; margin-top: 2px; }

    /* ---- 上传区：虚线框随主题 ---- */
    [data-testid="stFileUploaderDropzone"] {
        border: 2px dashed #c7d4e0; border-radius: 10px;
        background: #fbfcfe;
    }
    [data-testid="stFileUploaderDropzone"]:hover { border-color: #1a3a5c; }

    /* ---- 按钮：主按钮深藏青、次按钮白底描边 ---- */
    .stButton > button[kind="primary"] {
        background: #1a3a5c; color: #ffffff;
        border: none; border-radius: 8px;
        font-weight: 600; letter-spacing: 2px;
        transition: background .15s ease;
    }
    .stButton > button[kind="primary"]:hover { background: #244b75; }
    .stButton > button:not([kind="primary"]) {
        background: #ffffff; color: #1a3a5c;
        border: 1px solid #c7d4e0; border-radius: 8px;
    }
    .stButton > button:not([kind="primary"]):hover { border-color: #1a3a5c; }

    /* ---- 图表卡片内标题 ---- */
    .viz-title { font-weight: bold; color: #1a3a5c; font-size: 0.98rem; margin-bottom: 4px; }

    /* ---- 顶部导航条（2026-09-09 新增） ---- */
    .nav-strip {
        display: flex; gap: 10px; flex-wrap: wrap;
        margin: 6px 0 14px;
    }
    .nav-strip a {
        display: inline-block; padding: 7px 16px;
        background: #ffffff; color: #1a3a5c;
        border: 1px solid #c7d4e0; border-radius: 20px;
        text-decoration: none; font-size: 0.85rem; font-weight: 600;
        transition: all .15s ease;
    }
    .nav-strip a:hover {
        background: #1a3a5c; color: #ffffff; border-color: #1a3a5c;
    }

    /* ---- 扫描进度提示（2026-09-09 新增） ---- */
    .scan-progress {
        display: flex; align-items: center; gap: 12px;
        background: #ffffff; border: 1px solid #c7d4e0;
        border-left: 4px solid #1a3a5c;
        border-radius: 10px; padding: 14px 18px;
        margin: 8px 0; font-size: 0.95rem; color: #1a3a5c;
        box-shadow: 0 1px 4px rgba(26, 58, 92, 0.06);
    }
    .scan-progress-spin {
        display: inline-block; animation: scan-spin 1.2s linear infinite;
    }
    @keyframes scan-spin {
        from { transform: rotate(0deg); }
        to { transform: rotate(360deg); }
    }
    .scan-progress-stage { color: #5a6f85; font-size: 0.88rem; }

    /* ---- 扫描进度条配色（st.progress 原生元素套深藏青主题） ---- */
    [data-testid="stProgress"] > div > div > div {
        background-color: #1a3a5c;
    }
    [data-testid="stProgress"] > div > div > div > div {
        background-color: #7fa8cf;
    }
    [data-testid="stProgress"] p {
        color: #5a6f85; font-size: 0.9rem;
    }
</style>
""", unsafe_allow_html=True)

# ==========================================
# 侧边栏
# ==========================================
with st.sidebar:
    st.markdown("""
    <div class="sidebar-brand">
        <div class="sidebar-brand-title">🔍 漏洞智能研判系统</div>
        <div class="sidebar-brand-sub">精准检测 · 证据溯源 · 一键修复</div>
    </div>
    """, unsafe_allow_html=True)

    st.divider()

    st.markdown("### 📤 上传项目文件")
    upload_mode = st.radio(
        "选择上传方式",
        ["requirements.txt", "项目压缩包 (ZIP/RAR)", "package.json (npm)"]
    )
    uploaded_file = st.file_uploader(
        "选择文件",
        type=["txt", "zip", "rar", "json"],
        help="支持 requirements.txt, .zip, .rar, package.json"
    )

    st.divider()

    st.markdown("### ⚙️ 扫描选项")
    do_epss = st.checkbox("EPSS 利用预测", value=True,
                          help="查询 FIRST EPSS，评估漏洞30天内被利用的概率")
    use_nvd = st.checkbox("NVD 交叉验证", value=True,
                          help="使用 NIST NVD 数据库进行交叉验证（需联网）")
    do_transitive = st.checkbox("间接依赖检测（一层推断）", value=False,
                                help="自动推断直接依赖的一层间接依赖并检测漏洞。扫描时间会显著增加，"
                                     "且版本为约束推断值，精确检测建议使用 pip freeze 完整清单")

    st.divider()

    start_scan = st.button("🚀 开始安全扫描", type="primary", use_container_width=True)

    st.divider()
    st.caption("💡 每个漏洞结论都有 NVD/GitHub 官方链接可验证")

# ==========================================
# 状态管理
# ==========================================
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
# AI 辅助研判状态（AI 模块新增）
if "ai_judgements" not in st.session_state:
    st.session_state.ai_judgements = {}   # cve_id → 研判文本
if "ai_report_text" not in st.session_state:
    st.session_state.ai_report_text = ""  # 一键报告文本
if "ai_report_cost" not in st.session_state:
    st.session_state.ai_report_cost = ""  # 一键报告费用小字
if "ai_chat" not in st.session_state:
    st.session_state.ai_chat = []         # [{q, a, cost}] 问答历史

# ==========================================
# 主页面
# ==========================================
st.markdown("""
<div id="top" class="hero-banner">
    <div class="hero-title">🔍 双链——软件供应链安全检测系统</div>
    <div class="hero-sub">四源交叉验证 · 权威置信度评级 · EPSS 利用预测 · 修复优先级排序 · 证据溯源 · 一键修复 · AI 辅助研判 · Skill 安全检测</div>
    <div class="hero-badges">
        <span class="hero-chip">OSV</span>
        <span class="hero-chip">NVD</span>
        <span class="hero-chip">GitHub Advisory</span>
        <span class="hero-chip">FIRST EPSS</span>
        <span class="hero-chip">🤖 AI 辅助研判</span>
    </div>
</div>
""", unsafe_allow_html=True)

# ---- 顶部导航条（2026-09-09 新增：快速跳转） ----
st.markdown("""
<div class="nav-strip">
    <a href="#top">🔍 返回顶部</a>
    <a href="#skill-section">🛡️ 跳转到 Skill 安全检测</a>
</div>
""", unsafe_allow_html=True)

# ---- 执行扫描（2026-09-09 改为后台线程 + 进度轮询）----
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

if start_scan and uploaded_file:
    TEMP_DIR = "temp_upload"
    if os.path.exists(TEMP_DIR):
        shutil.rmtree(TEMP_DIR)
    os.makedirs(TEMP_DIR, exist_ok=True)

    file_path = os.path.join(TEMP_DIR, uploaded_file.name)
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())

    mode_map = {
        "requirements.txt": "requirements",
        "项目压缩包 (ZIP/RAR)": "archive",
        "package.json (npm)": "npm",
    }
    mode = mode_map.get(upload_mode, "requirements")

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
                project_name=uploaded_file.name.rsplit(".", 1)[0],
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

# ---- 扫描进行中：局部刷新进度（fragment 只重绘这一小块，页面其他部分不闪烁）----
@st.fragment(run_every=1.2)
def _scan_progress_ui():
    box = _scan_bridge.get(_sid, {})
    if box.get("done"):
        # 扫描结束：把结果交回主脚本（整页 rerun 一次渲染结果）
        if box.get("error"):
            st.session_state.scan_error = box["error"]
        else:
            st.session_state.scan_result_pending = box["result"]
        st.rerun(scope="app")
    percent = box.get("percent", 0)
    stage = box.get("stage", "准备中…")
    st.progress(percent / 100,
                text=f"正在执行多源漏洞研判… {stage}（{percent}%）")

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

# ---- 显示结果 ----
if st.session_state.scan_done and st.session_state.result:
    result = st.session_state.result
    summary = result["summary"]
    vulns = result["vulns"]
    dep_list = result["dep_list"]

    # 间接依赖截断提示（v3.1 新增）
    t_info = result.get("transitive_info") or {}
    if t_info.get("deps"):
        st.info(f"ℹ️ 本次推断出 {len(t_info['deps'])} 个一层间接依赖"
                f"（依赖总数中已计入）。间接依赖版本为约束推断值，仅供参考。")
    if t_info.get("truncated"):
        st.warning(f"⚠️ 间接依赖超过上限 {t_info.get('limit', 0)} 个，已截断。"
                   f"建议用 `pip freeze > requirements.txt` 导出完整清单后扫描。")

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
                use_container_width=True,
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
                st.bar_chart(sev_df, use_container_width=True,
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
                st.bar_chart(conf_df, use_container_width=True,
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
                    use_container_width=True,
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
                st.bar_chart(pkg_df, use_container_width=True)

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
                st.bar_chart(pri_df, use_container_width=True,
                             color=["#c0392b", "#e74c3c", "#f39c12", "#27ae60", "#95a5a6"])

        st.divider()

    # ===== 标签页 =====
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "📊 漏洞研判结果", "🔍 漏洞详情与证据", "🔧 修复方案", "📄 报告导出", "🤖 AI 辅助研判"
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
                use_container_width=True,
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

                    # ===== AI 研判（AI 模块新增）=====
                    st.divider()
                    st.markdown("**🤖 AI 研判**（大模型基于本漏洞的多源数据生成，只解读不检测）")
                    ai_prev = st.session_state.ai_judgements.get(v["cve_id"], "")
                    if ai_prev:
                        st.markdown(_safe_ai_markdown(ai_prev))
                        if st.button("🔄 重新研判", key=f"rejudge_{v['cve_id']}"):
                            st.session_state.ai_judgements.pop(v["cve_id"], None)
                            st.rerun()
                    elif st.button("🤖 AI 研判", key=f"judge_{v['cve_id']}"):
                        from modules import ai as ai_mod

                        gen, usage_box = ai_mod.judge_vulnerability(v)
                        parts = []
                        placeholder = st.empty()
                        try:
                            for chunk in gen:
                                parts.append(chunk)
                                placeholder.markdown("".join(parts))
                        except ai_mod.AIError as e:
                            placeholder.error(f"🤖 AI 研判失败：{e}")
                        else:
                            text = "".join(parts)
                            if text:
                                st.session_state.ai_judgements[v["cve_id"]] = text
                            tokens_str, cost = ai_mod.usage_cost(usage_box["usage"])
                            st.caption(f"⚡ 本次消耗 {tokens_str} tokens · 约 ¥{cost:.4f}")

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
                st.dataframe(plan_df, use_container_width=True, height=min(420, 36 + 35 * len(plan_df)))

                # 生成修改后的 requirements.txt
                req_path = st.session_state.get("req_file_path")
                fixed_content = _build_fixed_requirements(req_path, fix_map, dep_list)

                st.markdown("#### 📥 下载修改后的 requirements.txt")
                st.caption("直接依赖已按修复版本升级（`>=修复版本`），间接依赖版本为推断值、不写入生成文件。")
                st.download_button(
                    "📥 下载 requirements_fixed.txt",
                    fixed_content.encode("utf-8"),
                    "requirements_fixed.txt",
                    "text/plain",
                    use_container_width=True,
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
                st.dataframe(unfixable_df, use_container_width=True)

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
                                os.path.basename(path), mime, use_container_width=True
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
                                os.path.basename(path), mime, use_container_width=True
                            )
                        st.success(f"✅ 报告已生成：`{path}`")
                    except Exception as e:
                        st.error(f"PDF 生成失败：{e}")

    # ===== Tab 5: AI 辅助研判（AI 模块新增）=====
    with tab5:
        from config import config

        st.markdown("### 🤖 AI 辅助研判")
        st.caption(
            "大模型基于扫描结果生成中文研判：只解读数据、不编造漏洞。"
            f"当前模型：`{config.DEEPSEEK_MODEL or '未配置'}`"
            "（可在 .env 切换 deepseek-v4-flash / deepseek-v4-pro）"
        )

        if not config.DEEPSEEK_API_KEY:
            st.warning("⚠️ 未配置 DeepSeek API key，AI 功能不可用。"
                       "在 .env 中填写 DEEPSEEK_API_KEY 后重启即可。")

        # ---- AI 一键安全报告 ----
        st.markdown("#### 📑 AI 一键安全报告")
        st.caption("基于全部扫描结果生成完整中文安全评估报告，可下载。")

        if st.button("🤖 生成 AI 安全报告", type="primary", key="ai_report_btn"):
            from modules import ai as ai_mod

            gen, usage_box = ai_mod.generate_ai_report(result)
            parts = []
            placeholder = st.empty()
            try:
                for chunk in gen:
                    parts.append(chunk)
                    placeholder.markdown("".join(parts))
            except ai_mod.AIError as e:
                placeholder.error(f"🤖 生成失败：{e}")
            else:
                text = "".join(parts)
                if text:
                    st.session_state.ai_report_text = text
                tokens_str, cost = ai_mod.usage_cost(usage_box["usage"])
                st.session_state.ai_report_cost = f"⚡ 本次消耗 {tokens_str} tokens · 约 ¥{cost:.4f}"
                st.rerun()

        if st.session_state.ai_report_text:
            st.markdown(_safe_ai_markdown(st.session_state.ai_report_text))
            st.download_button(
                "📥 下载 AI 安全报告（txt）",
                st.session_state.ai_report_text.encode("utf-8"),
                "AI安全报告.txt",
                "text/plain",
                use_container_width=True,
            )
            if st.session_state.ai_report_cost:
                st.caption(st.session_state.ai_report_cost)

        st.divider()

        # ---- 交互问答 ----
        st.markdown("#### 💬 交互问答")
        st.caption("带着扫描数据提问，例如：这个项目能上线吗？最该先修的 5 个漏洞是什么？")

        question = st.text_input(
            "输入你的问题",
            key="ai_question",
            placeholder="例如：最严重的漏洞是什么？怎么修？",
        )
        if st.button("🤖 提问", key="ai_ask_btn", disabled=not question.strip()):
            from modules import ai as ai_mod

            gen, usage_box = ai_mod.ask_question(result, question.strip())
            parts = []
            placeholder = st.empty()
            try:
                for chunk in gen:
                    parts.append(chunk)
                    placeholder.markdown("".join(parts))
            except ai_mod.AIError as e:
                placeholder.error(f"🤖 回答失败：{e}")
            else:
                text = "".join(parts)
                if text:
                    tokens_str, cost = ai_mod.usage_cost(usage_box["usage"])
                    st.session_state.ai_chat.append({
                        "q": question.strip(),
                        "a": text,
                        "cost": f"⚡ {tokens_str} tokens · 约 ¥{cost:.4f}",
                    })
                st.rerun()

        if st.session_state.ai_chat:
            st.markdown("**历史问答**（最近 5 条）")
            for item in list(st.session_state.ai_chat)[-5:]:
                with st.container(border=True):
                    st.markdown(f"**❓ 你问：**{item['q']}")
                    st.markdown(f"**🤖 回答：**\n\n{item['a']}")
                    st.caption(item["cost"])

# ---- 初始状态 ----
elif not st.session_state.scan_done:
    st.info("👈 请在左侧上传文件并点击「开始安全扫描」")

    intro_col1, intro_col2 = st.columns([1.25, 1])

    with intro_col1:
        with st.container(border=True):
            st.markdown('<div class="viz-title">🔍 本系统做什么</div>', unsafe_allow_html=True)
            st.markdown("""
            输入 Python 项目，输出**可验证**的漏洞研判结果：

            | 步骤 | 做什么 | 怎么验证 |
            |------|--------|----------|
            | 1️⃣ 解析 | 提取项目所有依赖包和版本 | 对照 requirements.txt |
            | 2️⃣ 查询 | OSV + NVD + GitHub 检索 | NVD 官方链接直达 |
            | 3️⃣ 研判 | 置信度评级 + EPSS 利用预测 + 修复优先级 | 每个结论有据可查 |
            """)

    with intro_col2:
        with st.container(border=True):
            st.markdown('<div class="viz-title">✨ 和普通工具有什么不同</div>', unsafe_allow_html=True)
            st.markdown("""
            - ❌ 普通工具：列一堆 CVE，不知道真假
            - ✅ 本系统：**每个漏洞都有置信度评级和 NVD 官方链接**
            - 🔧 还支持：间接依赖检测、一键修复方案
            """)

    st.markdown("### 📈 后续升级方向")
    st.markdown("- npm/Maven 多生态支持 → 许可证合规检测 → CI/CD 自动扫描 → Skill 技能包安全检测（已上线，见页面底部）")


# ==========================================
# Skill 安全检测辅助函数（2026-09-09 新增，定义在使用之前）
# ==========================================
def _extract_skill_zip(zip_bytes: bytes, dest: str) -> str:
    """安全解压技能包 zip：拒绝路径穿越（zip slip），返回技能包根目录"""
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for info in zf.infolist():
            name = info.filename.replace("\\", "/")
            if name.startswith("/") or ".." in name.split("/"):
                raise ValueError(f"压缩包含非法路径，已拒绝解压：{info.filename}")
        zf.extractall(dest)
    # 若顶层只有一个目录且无 SKILL.md，进入该目录（GitHub 下载的 zip 常见结构）
    skill_md = os.path.join(dest, "SKILL.md")
    if not os.path.isfile(skill_md):
        entries = [e for e in os.listdir(dest) if os.path.isdir(os.path.join(dest, e))]
        if len(entries) == 1 and os.path.isfile(os.path.join(dest, entries[0], "SKILL.md")):
            return os.path.join(dest, entries[0])
    return dest


def _run_skill_scan(zip_bytes: bytes | None = None, text: str | None = None,
                    demo: bool = False):
    """双层检测：静态规则引擎 + AI 语义研判，结果写入 session_state 后刷新页面"""
    from modules import skill_scanner as ss
    from modules import ai as ai_mod
    from config import config

    tmp_dir = tempfile.mkdtemp(prefix="skill_scan_")
    try:
        if demo:
            root = ss.make_demo_package(tmp_dir)
            result = ss.scan_skill_package(root)
            skill_md = os.path.join(root, "SKILL.md")
            with open(skill_md, encoding="utf-8", errors="ignore") as f:
                skill_text = f.read()
        elif zip_bytes is not None:
            root = _extract_skill_zip(zip_bytes, tmp_dir)
            result = ss.scan_skill_package(root)
            skill_text = ""
            skill_md = os.path.join(root, "SKILL.md")
            if os.path.isfile(skill_md):
                with open(skill_md, encoding="utf-8", errors="ignore") as f:
                    skill_text = f.read()
        else:
            result = ss.scan_skill_text("", text or "")
            skill_text = text or ""
    except Exception as e:
        st.error(f"❌ Skill 检测失败：{e}")
        return
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    st.session_state.skill_result = result
    st.session_state.skill_ai_text = ""
    st.session_state.skill_ai_cost = ""

    # 第二层：AI 语义研判（未配置 key 时跳过）
    if not skill_text.strip() or not config.DEEPSEEK_API_KEY:
        st.rerun()
        return

    hints = "\n".join(
        f"[{f['severity']}][{f['category']}] {f['rule']}：{f['evidence']}"
        for f in result["findings"][:10]
    )
    gen, usage_box = ai_mod.review_skill(skill_text, hints)
    parts = []
    placeholder = st.empty()
    try:
        for chunk in gen:
            parts.append(chunk)
            placeholder.markdown("#### 🤖 AI 语义研判（第二层检测，流式生成中）\n\n" + _safe_ai_markdown("".join(parts)))
    except ai_mod.AIError as e:
        placeholder.error(f"🤖 语义研判失败：{e}")
        st.rerun()
        return
    text_out = "".join(parts)
    if text_out:
        st.session_state.skill_ai_text = text_out
        tokens_str, cost = ai_mod.usage_cost(usage_box["usage"])
        st.session_state.skill_ai_cost = f"⚡ 本次消耗 {tokens_str} tokens · 约 ¥{cost:.4f}"
    st.rerun()


# ==========================================
# Skill 安全检测区（独立功能，不依赖依赖扫描结果）
# ==========================================
if "skill_result" not in st.session_state:
    st.session_state.skill_result = None
if "skill_ai_text" not in st.session_state:
    st.session_state.skill_ai_text = ""
if "skill_ai_cost" not in st.session_state:
    st.session_state.skill_ai_cost = ""
if "skill_benchmark" not in st.session_state:
    st.session_state.skill_benchmark = False

st.divider()
st.markdown('<div id="skill-section"></div>', unsafe_allow_html=True)
st.markdown('<div class="section-title">🛡️ Skill 安全检测（AI Agent 技能包）</div>', unsafe_allow_html=True)
st.caption(
    "Agent Skills 已成为新型软件供应链攻击面——2026 年 ClawHavoc 事件中 1,184 个恶意技能"
    "造成 24.7 万次安装，Snyk 审计发现 36.82% 的技能含提示注入。"
    "本功能对技能包做「静态规则引擎 + AI 语义研判」双层检测。"
)

skill_col1, skill_col2 = st.columns(2)

with skill_col1:
    with st.container(border=True):
        st.markdown("**📦 方式一：上传技能包（zip）**")
        skill_zip = st.file_uploader("zip上传", type=["zip"], key="skill_zip",
                                     label_visibility="collapsed")
        sc1, sc2 = st.columns([1, 1])
        with sc1:
            if st.button("🛡️ 检测技能包", type="primary", key="skill_zip_btn",
                         disabled=not skill_zip, use_container_width=True):
                _run_skill_scan(zip_bytes=skill_zip.getvalue())
        with sc2:
            if st.button("🎬 演示样例", key="skill_demo_btn", use_container_width=True):
                _run_skill_scan(demo=True)
        st.caption("支持从 GitHub 下载的技能包 zip，自动定位 SKILL.md；"
                   "「演示样例」为故意构造的恶意技能，仅用于功能演示。")

with skill_col2:
    with st.container(border=True):
        st.markdown("**📝 方式二：粘贴 SKILL.md 内容**")
        skill_text = st.text_area("内容", key="skill_text", height=170,
                                  label_visibility="collapsed",
                                  placeholder="粘贴 SKILL.md 的完整内容……")
        if st.button("🛡️ 检测文本", key="skill_text_btn",
                     disabled=not skill_text.strip(), use_container_width=True):
            _run_skill_scan(text=skill_text)

# ---- 恶意样本检测率演示（内置样本库，回应"与grep有何区别"的质疑） ----
with st.container(border=True):
    bench_col1, bench_col2 = st.columns([1, 3])
    with bench_col1:
        if st.button("📊 运行样本检测率测试", key="skill_bench_btn",
                     use_container_width=True):
            st.session_state.skill_benchmark = True
    with bench_col2:
        st.caption("内置样本库：30 个恶意技能（基于 ClawHavoc/Snyk/ToxicSkills 等公开披露的"
                   "恶意模式构造）+ 20 个正常技能对照。纯本地规则引擎，毫秒级完成，零费用。")

if st.session_state.skill_benchmark:
    import subprocess
    _bench_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "samples", "run_skill_benchmark.py")
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

    sr = st.session_state.skill_result
    findings = sr["findings"]
    verdict = sr["verdict"]
    vcolor = ss_mod.SEV_COLOR[verdict]

    st.divider()
    st.markdown(f"### 🛡️ 检测结果：{sr['skill_name']}")
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
        st.dataframe(pd.DataFrame(rows), use_container_width=True, height=380,
                     column_config={
                         "等级": st.column_config.TextColumn(width="small"),
                         "类别": st.column_config.TextColumn(width="small"),
                         "位置": st.column_config.TextColumn(width="small"),
                     })
    else:
        st.success("🎉 未发现风险，该技能通过静态规则引擎全部检测。")

    # AI 语义研判结果（第二层）
    if st.session_state.skill_ai_text:
        with st.container(border=True):
            st.markdown("#### 🤖 AI 语义研判（第二层检测）")
            st.markdown(_safe_ai_markdown(st.session_state.skill_ai_text))
            if st.session_state.skill_ai_cost:
                st.caption(st.session_state.skill_ai_cost)


# ==========================================
# 辅助函数（已移至文件头部，见上）
# ==========================================
