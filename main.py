"""
SkillGuard —— AI 技能供应链安全检测平台
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


# ==========================================
# 辅助函数（定义在使用之前，避免 NameError）
# ==========================================
def esc(text) -> str:
    """HTML 转义，防止技能包中的恶意内容破坏界面结构或注入脚本"""
    s = "" if text is None else str(text)
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;").replace("'", "&#39;"))


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
        lines.append("# 由 SkillGuard 自动生成（已包含修复版本）")
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
    page_title="SkillGuard · AI 技能供应链安全检测平台",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==========================================
# 界面样式（v3.1 二版：深藏青横幅 + 点阵纹理 + 卡片化）
# ==========================================
st.markdown("""
<style>
/* ==========================================================
   SkillGuard · 浅色高级主题（2026-10-15 重制 · 浅色版）
   设计基调：雾白底 + 极淡网格 + 柔和阴影 + 克制配色
   要点：高级感来自「留白 + 层次 + 细节」，而非堆砌特效
   ========================================================== */

:root {
    --bg-page:      #f7f8fa;
    --bg-card:      #ffffff;
    --bg-soft:      #fbfcfd;
    --border:       #e8eaed;
    --border-soft:  #f0f2f4;
    --text:         #1a1d21;
    --text-sub:     #5f6772;
    --text-faint:   #98a0aa;
    --accent:       #2563eb;
    --accent-soft:  #eff4ff;
    --accent-line:  #c7d7fe;
    --violet:       #7c3aed;
    --green:        #059669;
    --green-soft:   #ecfdf5;
    --amber:        #d97706;
    --amber-soft:   #fffbeb;
    --red:          #dc2626;
    --red-soft:     #fef2f2;
    --rose:         #e11d48;
    --shadow-sm:    0 1px 2px rgba(16,24,40,0.04);
    --shadow-md:    0 4px 14px rgba(16,24,40,0.06);
    --shadow-lg:    0 12px 32px rgba(16,24,40,0.08);
}

/* ---------- 页面底色：极淡网格 + 顶部柔光 ---------- */
.stApp {
    background:
        radial-gradient(900px 480px at 50% -8%, rgba(37,99,235,0.045), transparent 65%),
        linear-gradient(180deg, #fafbfc 0%, var(--bg-page) 40%, #f5f6f8 100%);
    background-attachment: fixed;
    color: var(--text);
}
.stApp::before {
    content: "";
    position: fixed; inset: 0; pointer-events: none; z-index: 0;
    background-image:
        linear-gradient(rgba(16,24,40,0.020) 1px, transparent 1px),
        linear-gradient(90deg, rgba(16,24,40,0.020) 1px, transparent 1px);
    background-size: 56px 56px;
    -webkit-mask-image: radial-gradient(circle at 50% 0%, #000 0%, transparent 78%);
    mask-image: radial-gradient(circle at 50% 0%, #000 0%, transparent 78%);
}
.stMain, .stApp > div { position: relative; z-index: 1; }
html, body, [class*="css"] { color: var(--text); }

/* ---------- 主横幅 ---------- */
.hero-banner {
    position: relative; overflow: hidden;
    background: linear-gradient(135deg, #ffffff 0%, #fcfdff 55%, #f7faff 100%);
    border: 1px solid var(--border);
    border-radius: 18px;
    padding: 32px 36px 28px;
    box-shadow: var(--shadow-md);
    margin-bottom: 10px;
}
.hero-banner::before {
    content: ""; position: absolute; right: -70px; top: -100px;
    width: 300px; height: 300px; border-radius: 50%;
    border: 1px solid rgba(37,99,235,0.10);
}
.hero-banner::after {
    content: ""; position: absolute; right: 54px; top: -30px;
    width: 168px; height: 168px; border-radius: 50%;
    background: radial-gradient(circle, rgba(124,58,237,0.055), transparent 70%);
    border: 1px solid rgba(124,58,237,0.09);
}
.hero-title {
    font-size: 2.02rem; font-weight: 700; letter-spacing: -0.4px;
    background: linear-gradient(94deg, #111827 0%, #1e3a8a 52%, #5b21b6 100%);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    background-clip: text;
    line-height: 1.25;
}
.hero-sub {
    color: var(--text-sub); font-size: 0.92rem;
    margin-top: 9px; line-height: 1.75; letter-spacing: 0.1px;
}
.hero-sub b { color: var(--accent); font-weight: 600; }
.hero-badges { margin-top: 15px; display: flex; flex-wrap: wrap; gap: 6px; }
.hero-chip {
    display: inline-block;
    background: var(--accent-soft);
    border: 1px solid var(--accent-line);
    color: #1d4ed8; border-radius: 999px;
    padding: 4px 12px; font-size: 11.5px; font-weight: 600;
    letter-spacing: 0.2px;
}

/* ---------- 侧边栏 ---------- */
section[data-testid="stSidebar"] {
    background: #fbfcfd;
    border-right: 1px solid var(--border);
}
section[data-testid="stSidebar"] .block-container { padding-top: 1.3rem; }
.sidebar-brand {
    background: linear-gradient(135deg, #ffffff, #f8faff);
    border: 1px solid var(--border);
    border-radius: 13px; padding: 13px 15px; margin-bottom: 6px;
    box-shadow: var(--shadow-sm);
}
.sidebar-brand-title {
    font-weight: 700; font-size: 1rem; letter-spacing: -0.1px;
    background: linear-gradient(94deg, #111827, #1e3a8a);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    background-clip: text;
}
.sidebar-brand-sub { font-size: 0.71rem; color: var(--text-faint); margin-top: 3px; }

/* ---------- 分区标题 ---------- */
.section-title {
    font-size: 1.1rem; font-weight: 650; color: var(--text);
    padding-left: 12px; margin: 14px 0 14px 0;
    position: relative; letter-spacing: -0.1px;
    display: flex; align-items: center;
}
.section-title::before {
    content: ""; position: absolute; left: 0; top: 50%;
    transform: translateY(-50%);
    width: 3px; height: 17px; border-radius: 2px;
    background: linear-gradient(180deg, var(--accent), var(--violet));
}

/* ---------- 指标卡 ---------- */
.metric-card {
    position: relative; overflow: hidden;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 14px; padding: 16px 14px 17px;
    text-align: center;
    box-shadow: var(--shadow-sm);
    transition: transform .2s cubic-bezier(.2,.8,.3,1), box-shadow .2s ease, border-color .2s ease;
}
.metric-card:hover {
    transform: translateY(-3px);
    box-shadow: var(--shadow-lg);
    border-color: var(--accent-line);
}
.metric-card::before {
    content: ""; position: absolute; top: 0; left: 0; right: 0; height: 2.5px;
    background: linear-gradient(90deg, var(--accent), var(--violet));
    opacity: 0.85;
}
.metric-card-red::before   { background: linear-gradient(90deg, #ef4444, var(--rose)); }
.metric-card-green::before { background: linear-gradient(90deg, #10b981, var(--green)); }
.metric-card-orange::before{ background: linear-gradient(90deg, #f59e0b, var(--amber)); }
.metric-icon { font-size: 16px; margin-bottom: 5px; opacity: 0.75; }
.metric-value {
    font-size: 1.85rem; font-weight: 700; line-height: 1.14;
    background: linear-gradient(94deg, #111827, #1e3a8a);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    background-clip: text;
}
.metric-label {
    font-size: 10.5px; color: var(--text-faint);
    margin-top: 6px; letter-spacing: 1.1px; text-transform: uppercase;
}

/* ---------- 导航条 ---------- */
.nav-strip { display: flex; gap: 8px; flex-wrap: wrap; margin: 12px 0 18px; }
.nav-strip a {
    display: inline-block; padding: 7px 16px;
    background: var(--bg-card); color: var(--text-sub);
    border: 1px solid var(--border); border-radius: 999px;
    text-decoration: none; font-size: 0.82rem; font-weight: 550;
    box-shadow: var(--shadow-sm);
    transition: all .18s ease;
}
.nav-strip a:hover {
    background: var(--accent-soft); color: #1d4ed8;
    border-color: var(--accent-line); transform: translateY(-1px);
    box-shadow: var(--shadow-md);
}

/* ---------- 按钮 ---------- */
.stButton > button[kind="primary"] {
    background: linear-gradient(135deg, var(--accent) 0%, #4f46e5 100%);
    color: #ffffff; border: none; border-radius: 10px;
    font-weight: 600; letter-spacing: 0.3px;
    padding-top: 0.46rem; padding-bottom: 0.46rem;
    box-shadow: 0 2px 8px rgba(37,99,235,0.22);
    transition: transform .16s ease, box-shadow .16s ease, filter .16s ease;
}
.stButton > button[kind="primary"]:hover {
    transform: translateY(-1.5px);
    box-shadow: 0 6px 18px rgba(37,99,235,0.30);
    filter: brightness(1.05);
}
.stButton > button:not([kind="primary"]) {
    background: var(--bg-card); color: var(--text-sub);
    border: 1px solid var(--border); border-radius: 10px;
    font-weight: 550; box-shadow: var(--shadow-sm);
    transition: all .16s ease;
}
.stButton > button:not([kind="primary"]):hover {
    background: var(--accent-soft); color: #1d4ed8;
    border-color: var(--accent-line); transform: translateY(-1.5px);
}

/* ---------- 输入控件 ---------- */
[data-testid="stFileUploaderDropzone"] {
    background: var(--bg-soft);
    border: 1.5px dashed #d8dce2; border-radius: 12px;
    transition: all .18s ease;
}
[data-testid="stFileUploaderDropzone"]:hover {
    border-color: var(--accent); background: var(--accent-soft);
}
[data-testid="stWidgetLabel"] p, label { color: var(--text-sub) !important; font-weight: 550; }
.stCaption, [data-testid="stCaptionContainer"] { color: var(--text-faint) !important; }
div[data-baseweb="input"] input,
div[data-baseweb="textarea"] textarea { color: var(--text) !important; }

/* ---------- 容器/卡片 ---------- */
div[data-testid="stVerticalBlockBorderWrapper"] > div,
div[data-testid="stExpander"] {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 14px;
    box-shadow: var(--shadow-sm);
}
div[data-testid="stExpander"] { padding: 10px 14px; }

/* ---------- 攻击链卡片 ---------- */
.chain-card {
    background: var(--bg-card);
    border: 1px solid var(--border); border-radius: 16px;
    margin: 14px 0; overflow: hidden;
    box-shadow: var(--shadow-md);
    transition: transform .2s ease, box-shadow .2s ease;
}
.chain-card:hover { transform: translateY(-2px); box-shadow: var(--shadow-lg); }
.chain-card-head {
    padding: 15px 21px; font-weight: 650; font-size: 1rem; color: #ffffff;
    display: flex; align-items: center; justify-content: space-between;
    flex-wrap: wrap; gap: 9px;
}
.chain-card-head.sev-严重 { background: linear-gradient(135deg, #dc2626, #e11d48); }
.chain-card-head.sev-高危 { background: linear-gradient(135deg, #ea580c, #d97706); }
.chain-card-head.sev-中危 { background: linear-gradient(135deg, #d97706, #ca8a04); }
.chain-card-head.sev-低危 { background: linear-gradient(135deg, #059669, #0d9488); }
.chain-card-body { padding: 17px 21px; }

.chain-steps { display: flex; align-items: stretch; gap: 0; margin: 15px 0 12px; flex-wrap: wrap; }
.chain-step {
    flex: 1 1 180px; min-width: 158px;
    background: var(--bg-soft);
    border: 1px solid var(--border-soft); border-radius: 12px;
    padding: 12px 14px;
    transition: border-color .18s ease, background .18s ease, transform .18s ease;
}
.chain-step:hover {
    border-color: var(--accent-line); background: var(--accent-soft);
    transform: translateY(-2px);
}
.chain-step-cap { font-weight: 650; color: #1d4ed8; font-size: 0.9rem; margin-bottom: 5px; }
.chain-step-src { font-size: 0.78rem; color: var(--text-sub); word-break: break-all; line-height: 1.5; }
.chain-step-loc {
    font-size: 0.74rem; color: var(--text-faint); margin-top: 5px;
    font-family: "Cascadia Code", Consolas, monospace;
}
.chain-step-rule {
    display: inline-block; margin-top: 7px;
    background: var(--amber-soft); color: #92400e;
    border: 1px solid #fde68a; border-radius: 5px;
    padding: 2px 8px; font-size: 0.71rem; font-weight: 550;
}
.chain-arrow {
    display: flex; align-items: center; padding: 0 9px;
    color: #94a3b8; font-size: 1.4rem; font-weight: 700;
}

.chain-impact, .chain-advice {
    border-radius: 10px; padding: 12px 15px; margin-top: 10px;
    font-size: 0.88rem; line-height: 1.72;
}
.chain-impact {
    background: var(--red-soft);
    border-left: 3px solid var(--red); color: #7f1d1d;
}
.chain-advice {
    background: var(--accent-soft);
    border-left: 3px solid var(--accent); color: #1e3a8a;
}
.chain-impact b, .chain-advice b { color: inherit; }

/* ---------- 对比双栏 ---------- */
.compare-row { display: flex; gap: 14px; margin: 14px 0; flex-wrap: wrap; }
.compare-col {
    flex: 1 1 300px; border-radius: 14px; padding: 15px 18px;
    border: 1px solid var(--border); background: var(--bg-card);
    box-shadow: var(--shadow-sm);
}
.compare-col.traditional {
    background: var(--bg-soft); border-left: 3px solid #cbd5e1;
}
.compare-col.advanced {
    background: linear-gradient(180deg, #fffbfb, #fef5f5);
    border-left: 3px solid var(--red);
    box-shadow: 0 4px 16px rgba(220,38,38,0.08);
}
.compare-col h4 { margin: 0 0 10px 0; font-size: 0.97rem; color: var(--text); }
.compare-col.traditional h4 { color: var(--text-sub); }
.compare-col.advanced h4 { color: #b91c1c; }
.compare-col table { width: 100%; border-collapse: collapse; font-size: 0.84rem; }
.compare-col table th {
    color: var(--text-sub); border-bottom: 1px solid var(--border);
    padding: 6px 5px; text-align: left; font-weight: 600;
}
.compare-col table td { color: var(--text-sub); padding: 5px; border-bottom: 1px solid var(--border-soft); }

/* ---------- 能力云 ---------- */
.cap-cloud { display: flex; gap: 7px; flex-wrap: wrap; margin: 10px 0; }
.cap-cloud-item {
    background: var(--accent-soft);
    border: 1px solid var(--accent-line);
    border-radius: 999px; padding: 5px 13px;
    font-size: 0.8rem; color: #1d4ed8; font-weight: 550;
}
.cap-cloud-item b { color: var(--violet); font-weight: 700; }

/* ---------- 提示条 ---------- */
.demo-hint {
    background: linear-gradient(135deg, #f8fbff, #fcfaff);
    border: 1px solid var(--accent-line);
    color: var(--text-sub); border-radius: 13px;
    padding: 15px 19px; font-size: 0.88rem;
    line-height: 1.78; margin: 10px 0;
    box-shadow: var(--shadow-sm);
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
    border: 1px solid var(--border); border-radius: 12px; overflow: hidden;
    box-shadow: var(--shadow-sm);
}
[data-testid="stDataFrame"] * { font-size: 0.84rem; }

/* ---------- 进度 ---------- */
.scan-progress {
    display: flex; align-items: center; gap: 13px;
    background: linear-gradient(135deg, #f8fbff, #fbfaff);
    border: 1px solid var(--border); border-left: 3px solid var(--accent);
    border-radius: 12px; padding: 14px 18px; margin: 9px 0;
    font-size: 0.92rem; color: var(--text-sub);
    box-shadow: var(--shadow-sm);
}
.scan-progress-stage { color: var(--text-faint); font-size: 0.85rem; }
.scan-progress-spin { display: inline-block; animation: scan-spin 1.2s linear infinite; }
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
    box-shadow: var(--shadow-sm);
}
div[data-testid="stAlertContainer"] p { color: var(--text) !important; }
</style>
""", unsafe_allow_html=True)

# ==========================================
# 侧边栏
# ==========================================
with st.sidebar:
    st.markdown("""
    <div class="sidebar-brand">
        <div class="sidebar-brand-title">SkillGuard</div>
        <div class="sidebar-brand-sub">AI 技能供应链安全检测</div>
    </div>
    """, unsafe_allow_html=True)

    st.divider()

    # ===== 功能切换（2026-10-26 聚焦化：4 个入口收敛为 3 个）=====
    # 原「📦 依赖漏洞扫描」独立入口已取消 —— 该能力与 Snyk / pip-audit /
    # OSV-Scanner 等成熟工具功能重叠，单独作为并列功能会削弱主线。
    # 现在它降级为「组合风险分析」视图里的 *依赖侧证据*（可选附加）。
    VIEW_MAIN = "🛡️ Skill 安全检测"
    VIEW_CHAIN = "🔗 组合风险分析"
    VIEW_DEMO = "🎬 离线演示"

    current_view = st.radio(
        "功能选择",
        [VIEW_MAIN, VIEW_CHAIN, VIEW_DEMO],
        label_visibility="collapsed",
        key="main_view",
    )

    st.divider()

    if current_view == VIEW_CHAIN:
        # 依赖侧证据：传统依赖漏洞扫描（可选附加，默认折叠）
        with st.expander("📎 依赖侧证据（可选）", expanded=False):
            st.caption("上传项目包后，可同时解析其传统依赖的已知漏洞，"
                       "作为组合风险分析里的「依赖侧证据」。非必需。")
            upload_mode = st.radio(
                "选择上传方式",
                ["requirements.txt", "项目压缩包 (ZIP/RAR)", "package.json (npm)"]
            )
            uploaded_file = st.file_uploader(
                "选择文件",
                type=["txt", "zip", "rar", "json"],
                help="支持 requirements.txt, .zip, .rar, package.json"
            )

            st.markdown("**⚙️ 扫描选项**")
            do_epss = st.checkbox("EPSS 利用预测", value=True,
                                  help="查询 FIRST EPSS，评估漏洞30天内被利用的概率")
            use_nvd = st.checkbox("NVD 交叉验证", value=True,
                                  help="使用 NIST NVD 数据库进行交叉验证（需联网）")
            do_transitive = st.checkbox("间接依赖检测（一层推断）", value=False,
                                        help="自动推断直接依赖的一层间接依赖并检测漏洞。"
                                             "扫描时间会显著增加，且版本为约束推断值，"
                                             "精确检测建议使用 pip freeze 完整清单")

            start_scan = st.button("🚀 开始安全扫描", type="primary", width="stretch")
            st.caption("💡 每个漏洞结论都有 NVD/GitHub 官方链接可验证")
            st.caption("📄 扫描结果会显示在「组合风险分析」页面下方的"
                       "「📎 依赖侧证据」面板中。")
    else:
        # 上传控件只在「组合风险分析」视图下定义，
        # 但下方主流程会引用这些变量 —— 此处给出安全默认值，
        # 避免切换到其他功能时抛 NameError。
        upload_mode = "requirements.txt"
        uploaded_file = None
        do_epss = True
        use_nvd = True
        do_transitive = False
        start_scan = False


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
# 说明：AI 研判为**可选**能力，未配置 MaaS 时自动降级为本地模板并明确显示
# 「未调用大模型」。检测结论全部由确定性规则 + OSV/NVD/GitHub/EPSS 权威数据得出，
# 代码级约束见 modules/adjudicator.py 的 assert_ai_not_judging()。

# ==========================================
# 主页面
# ==========================================
st.markdown("""
<div id="top" class="hero-banner">
    <div class="hero-title">SkillGuard · AI 技能供应链安全检测</div>
    <div class="hero-sub">32 条检测规则 · <b>组合风险分析</b> · 权威置信度评级 · 证据溯源</div>
    <div class="hero-badges">
        <span class="hero-chip">OWASP Agentic Skills Top10</span>
        <span class="hero-chip">真实样本 TPR 100% / FPR 2.0%</span>
        <span class="hero-chip">纯离线 · 33ms</span>
    </div>
</div>
""", unsafe_allow_html=True)

# ---- 功能切换（用侧边栏 radio 收敛入口，避免页面过长杂乱）----

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
# ==========================================
# 依赖侧证据（2026-10-26 聚焦化重构）
# 原「📦 依赖漏洞扫描」是独立视图，功能与 Snyk / pip-audit / OSV-Scanner
# 等成熟工具高度重叠，单独并列会削弱主线，也难回答「你和 Snyk 什么区别」。
# 现在它降级为「组合风险分析」视图里的 *可选附加证据*：传统依赖漏洞作为
# 资产图谱中的「依赖侧节点」，与技能、工具节点合流参与组合分析。
# ==========================================
def _render_dep_evidence():
    """渲染传统依赖漏洞的扫描结果（由「组合风险分析」视图的折叠面板调用）。"""
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
                fixed_content = _build_fixed_requirements(req_path, fix_map, dep_list)

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
    """静态规则引擎检测，结果写入 session_state 后刷新页面"""
    from modules import skill_scanner as ss

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
    st.rerun()


# ==========================================
# ===== 功能 B：Agent Skill 安全检测 =====
if current_view == VIEW_MAIN:
    # ==========================================
    if "skill_result" not in st.session_state:
        st.session_state.skill_result = None
    if "skill_benchmark" not in st.session_state:
        st.session_state.skill_benchmark = False

    st.divider()
    st.markdown('<div id="skill-section"></div>', unsafe_allow_html=True)
    st.markdown('<div class="section-title">🛡️ Skill 安全检测（AI Agent 技能包）</div>', unsafe_allow_html=True)
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
            | 2️⃣ 组合分析 | 把技能拆成 6 类危险能力，找跨技能攻击链 | 每条链路可回溯到行号 |
            """)

    with intro_col2:
        with st.container(border=True):
            st.markdown('<div class="viz-title">✨ 和普通工具有什么不同</div>',
                        unsafe_allow_html=True)
            st.markdown("""
            - ❌ 普通工具：列一堆命中项，不知道真实危害
            - ✅ 本系统：**给出可核验的攻击链 + 真实危害 + 处置建议**
            - 🔗 还能把传统依赖漏洞作为**依赖侧节点**接入同一张资产图谱
            - 🤖 AI 只做汇总与处置建议，**不参与判定**（结论可复现）
            """)

    skill_col1, skill_col2 = st.columns(2)

    with skill_col1:
        with st.container(border=True):
            st.markdown("**📦 方式一：上传技能包（zip）**")
            skill_zip = st.file_uploader("zip上传", type=["zip"], key="skill_zip",
                                         label_visibility="collapsed")
            sc1, sc2 = st.columns([1, 1])
            with sc1:
                if st.button("🛡️ 检测技能包", type="primary", key="skill_zip_btn",
                             disabled=not skill_zip, width="stretch"):
                    _run_skill_scan(zip_bytes=skill_zip.getvalue())
            with sc2:
                if st.button("🎬 演示样例", key="skill_demo_btn", width="stretch"):
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
                         disabled=not skill_text.strip(), width="stretch"):
                _run_skill_scan(text=skill_text)

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
        from modules import adjudicator as adj_mod

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

        # ===== AI 研判（赛题1 要求的「人工智能（必选）」能力入口）=====
        with st.container(border=True):
            st.markdown("**🤖 AI 研判 · 风险态势与处置建议**")
            st.caption(
                "检测结论由上方的确定性规则给出（可核验）；"
                "AI 只负责把分散的检测结果综合起来回答「最该先处理什么、为什么、怎么做」，"
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
                可直接在技能包源文件中定位核对。全程离线运行，不调用任何大模型，
                因此结论<b>可重复、可审计、不随模型版本变化</b>。
            </div>
            """, unsafe_allow_html=True)
        else:
            st.success("🎉 未发现风险，该技能通过静态规则引擎全部检测。")


    # ==========================================
    # 组合风险分析区（2026-10-15 新增 · 项目核心创新）

# ===== 功能 C：组合风险分析 =====
if current_view == VIEW_CHAIN:
    # ==========================================
    st.divider()
    st.markdown('<div id="chain-section"></div>', unsafe_allow_html=True)
    st.markdown('<div class="section-title">🔗 组合风险分析</div>',
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
        """对用户上传的多个技能包做组合风险分析"""
        from modules import attack_chain as ac
        from modules import skill_scanner as ss

        tmp_dir = tempfile.mkdtemp(prefix="chain_multi_")
        try:
            results = []
            for idx, zb in enumerate(zip_list):
                sub = os.path.join(tmp_dir, f"skill_{idx}")
                os.makedirs(sub, exist_ok=True)
                try:
                    root = _extract_skill_zip(zb, sub)
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
            if st.button("🔗 运行组合风险分析演示", type="primary",
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
        from modules import attack_chain as ac_mod

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
            _render_dep_evidence()
        else:
            st.info("尚未扫描依赖侧证据。在左侧「📎 依赖侧证据（可选）」中"
                    "上传项目包并点击「开始安全扫描」，结果会显示在这里。")

# ===== 功能 D：离线演示模式 =====
if current_view == VIEW_DEMO:
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
