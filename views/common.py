# -*- coding: utf-8 -*-
"""共享 UI 组件与工具函数。

拆出这一层的原因：四个视图都要用同一批组件（指标卡、证据溯源表格、
HTML 转义、文件上传），散在各自视图里会重复十几遍。
"""
import io
import os
import shutil
import tempfile
import zipfile

import pandas as pd
import streamlit as st


# ==========================================
# 基础工具
# ==========================================
def esc(text) -> str:
    """HTML 转义，防止技能包中的恶意内容破坏界面结构或注入脚本"""
    s = "" if text is None else str(text)
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;").replace("'", "&#39;"))


def build_fixed_requirements(req_path: str | None, fix_map: dict,
                             dep_list: list[dict]) -> str:
    """
    根据修复方案生成修改后的 requirements.txt 内容。

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
        lines.append("# 由 AI 技能组合风险体检站自动生成（已包含修复版本）")
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


def extract_skill_zip(zip_bytes: bytes, dest: str) -> str:
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


def run_skill_scan(zip_bytes: bytes | None = None, text: str | None = None,
                   demo: bool = False):
    """静态规则引擎检测技能包，结果写入 session_state 后刷新页面。

    注意：本函数只跑确定性规则、不调用任何大模型（AI 意图分诊在 views/combo_view.py
    的组合体检链路中，是意图闸门与外发闸门的来源）。
    """
    from modules import skill_scanner as ss

    tmp_dir = tempfile.mkdtemp(prefix="skill_scan_")
    try:
        if demo:
            root = ss.make_demo_package(tmp_dir)
            result = ss.scan_skill_package(root)
            skill_md = os.path.join(root, "SKILL.md")
            with open(skill_md, encoding="utf-8", errors="ignore") as f:
                skill_text = f.read()  # noqa: F841 — 保留以维持 with 块结构
        elif zip_bytes is not None:
            root = extract_skill_zip(zip_bytes, tmp_dir)
            result = ss.scan_skill_package(root)
            skill_text = ""
            skill_md = os.path.join(root, "SKILL.md")
            if os.path.isfile(skill_md):
                with open(skill_md, encoding="utf-8", errors="ignore") as f:
                    skill_text = f.read()  # noqa: F841 — 保留以维持 with 块结构
        else:
            result = ss.scan_skill_text("", text or "")
    except Exception as e:
        st.error(f"❌ Skill 检测失败：{e}")
        return
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    st.session_state.skill_result = result
    st.rerun()


# ==========================================
# 复用 UI 组件
# ==========================================
def metric_card(value, label, color="", icon=""):
    """指标卡：四个视图通用"""
    cls = f"metric-card {color}".strip()
    icon_html = f'<div class="metric-icon">{icon}</div>' if icon else ""
    st.markdown(f"""
    <div class="{cls}">
        {icon_html}
        <div class="metric-value">{value}</div>
        <div class="metric-label">{label}</div>
    </div>
    """, unsafe_allow_html=True)


def section_title(title: str, anchor: str = ""):
    """分区标题：四个视图通用"""
    div = f'<div id="{anchor}"></div>' if anchor else ""
    st.markdown(f'{div}<div class="section-title">{title}</div>',
                unsafe_allow_html=True)


def severity_badge(severity: str) -> str:
    """严重度徽章"""
    mapping = {
        "严重": "badge-critical", "高危": "badge-high",
        "中危": "badge-medium", "低危": "badge-low",
    }
    return mapping.get(severity, "badge-low")


def evidence_table(rows: list, columns: list) -> None:
    """证据溯源表格：每条结论都能定位到原文行号"""
    st.dataframe(
        pd.DataFrame(rows),
        width="stretch",
        hide_index=True,
        column_config={
            col: st.column_config.TextColumn(width="small")
            for col in columns
        },
    )


def file_uploader_box(label: str, types: list, key: str, help_text: str = ""):
    """统一的文件上传控件（放在主内容区，不放侧边栏）"""
    return st.file_uploader(label, type=types, key=key, help=help_text)
