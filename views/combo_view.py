# -*- coding: utf-8 -*-
"""视图 2：组合体检（三段式架构流水线）

规则快筛（阶段A）→ AI 意图分诊（阶段B）→ 组合判定（阶段C）。
单点检测回答不了「这些技能凑在一起会怎样」，本页面专门回答这个问题：
  - 阶段A 复用 modules/skill_scanner.py 的 32 条规则（确定性，可核验）
  - 阶段B 调用 modules/adjudicator.py 的 judge_skill_combined()
    （每技能一次调用，带磁盘缓存；未配置 MaaS 时跳过且明确提示，不中断）
  - 阶段C 调用 modules/combo_analysis.py 的 build_chains()
    （能力互补 × 意图闸门 × 外发闸门 三要素成链，纯本地推导）
"""
import json
import os

import pandas as pd
import streamlit as st

from views.common import esc, metric_card, section_title

# 示例场景目录（samples/scenarios，含 _truth.json 标准答案）
_SCENARIO_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "samples", "scenarios")

# 意图判定的展示口径（界面文案统一在这里维护）
_VERDICT_LABEL = {
    "MALICIOUS": "🔴 恶意（MALICIOUS）",
    "SUSPICIOUS": "🟠 可疑（SUSPICIOUS）",
    "BENIGN": "🟢 正常（BENIGN）",
    "PARSE_FAIL": "⚪ 解析失败（PARSE_FAIL）",
}
_SCOPE_LABEL = {
    "GENERIC": "🌐 通用内容（GENERIC）",
    "STRUCTURED": "🧱 固定结构（STRUCTURED）",
    "NONE": "🚫 不外发（NONE）",
    "PARSE_FAIL": "⚪ 解析失败（PARSE_FAIL）",
}


def _load_scenario_options() -> list:
    """读取 _truth.json，返回示例场景下拉项（含真假标注）。"""
    truth_path = os.path.join(_SCENARIO_DIR, "_truth.json")
    try:
        with open(truth_path, encoding="utf-8") as f:
            truth = json.load(f)
    except (OSError, ValueError):
        return []
    opts = []
    for t in truth:
        tag = "真链路" if t.get("label") == "REAL" else "假链路"
        opts.append(f"{t['scenario_id']}（{tag}）")
    return opts


def _load_scenario_skills(option: str) -> dict:
    """按下拉项加载该场景全部 SKILL.md，返回 {技能名: 正文}。"""
    sid = option.split("（")[0]
    d = os.path.join(_SCENARIO_DIR, sid)
    skills = {}
    if os.path.isdir(d):
        for fn in sorted(os.listdir(d)):
            if fn.endswith(".md"):
                with open(os.path.join(d, fn), encoding="utf-8",
                          errors="ignore") as f:
                    skills[fn[:-3]] = f.read()
    return skills


def _run_pipeline(skills: dict, do_deps: bool = True) -> None:
    """执行四段式流水线，结果写入 session_state。

    规则快筛(A) → AI 意图分诊(B) → 组合判定(C) → 依赖研判(D)。
    🔴 AI 分诊严格串行（逐个技能更新进度）——禁止并发轰炸 API。
    未配置 MaaS 时跳过阶段B；do_deps=False 或技能无依赖声明时跳过阶段D，均不中断。
    """
    from modules import adjudicator as adj
    from modules import skill_scanner as ss
    from modules.combo_analysis import build_chains, extract_caps

    names = list(skills.keys())

    # ---- 阶段A：规则快筛（纯本地，毫秒级）----
    rule_hits = {}
    for n in names:
        rule_hits[n] = len(ss.scan_skill_text(n, skills[n])["findings"])

    # ---- 阶段B：AI 意图分诊（串行 + 进度条 + 磁盘缓存）----
    ai_ok = adj.is_available()
    intents = {}
    call_info = ""
    if ai_ok:
        # 调用量预告写入 session_state（P3-1）：_run_pipeline 末尾的 st.rerun
        # 会清掉这里的临时 st.info，只有落进 combo_result 才能持久展示。
        uncached = adj.count_uncached(skills)
        call_info = (f"🤖 本次体检对 {uncached}/{len(names)} 个未命中缓存的技能"
                     f"调用了模型（其余命中本地缓存，零调用、零费用）。")
        progress = st.progress(0.0, text="AI 意图分诊中…")
        for i, n in enumerate(names, 1):
            progress.progress(i / len(names),
                              text=f"AI 意图分诊中… {n}（{i}/{len(names)}）")
            intents[n] = adj.judge_skill_combined(n, skills[n])
    else:
        st.warning("ℹ️ 未配置 MaaS（MAAS_BASE_URL / MAAS_API_KEY / MAAS_MODEL），"
                   "AI 意图分诊已跳过，仅执行 规则快筛 → 组合判定。")

    # ---- 阶段C：组合判定（纯本地推导，无 AI 参与）----
    caps = {n: extract_caps(skills[n]) for n in names}
    chains = build_chains(names, caps, intents)

    # ---- 阶段D：依赖研判（技能声明的第三方依赖 → 四源漏洞库）----
    dep = (_run_dep_stage(skills, names) if do_deps
           else {"status": "skipped", "msg": "", "result": None, "pkgs": []})

    st.session_state.combo_result = {
        "skills": skills,
        "rule_hits": rule_hits,
        "intents": intents,
        "ai_ok": ai_ok,
        "chains": chains,
        "call_info": call_info,
        "dep_status": dep["status"],
        "dep_msg": dep["msg"],
        "dep_result": dep["result"],
        "dep_pkgs": dep["pkgs"],
    }
    st.rerun()


def _extract_req_specs(skills: dict, names: list) -> list:
    """从技能正文提取 requirements 行，**尽量保留 `==` 版本号**。

    为什么不能直接用 asset_graph._extract_dep_names：那个函数是给「建图」用的，
    会把 `requests==2.25.0` 里的版本**剥掉**，只剩包名 —— 拿去查漏洞库时
    就变成「查这个包的所有历史漏洞」，报出来的漏洞对不上声明的版本。
    这里专门保留版本，让查询结果与技能里写的版本一一对应。
    """
    import re as _re

    rx = _re.compile(r"pip3?\s+install\s+([^\n&|;]+)", _re.I)
    valid = _re.compile(r"^[A-Za-z0-9_.@/-]+(==[A-Za-z0-9_.*+-]+)?$")
    out: list = []
    for n in names:
        for m in rx.finditer(skills.get(n, "") or ""):
            for tok in m.group(1).split():
                tok = tok.strip()
                if not tok or tok.startswith(("-", ".", "http")):
                    continue
                spec = _re.split(r"[;\[\]]", tok)[0].strip()
                if spec and valid.match(spec) and spec not in out:
                    out.append(spec)
    return out


def _run_dep_stage(skills: dict, names: list) -> dict:
    """阶段D：技能声明的第三方依赖 → OSV / NVD / GitHub / EPSS 四源漏洞研判。

    - 依赖名取自技能正文里的 ``pip / npm / apt install`` 声明，纯本地正则提取，不联网；
    - 漏洞查询需联网；无任何依赖声明时直接跳过（status="none"），不拖慢体检；
    - 断网或查询失败时把原因记入 ``status="error"``，**绝不把「查不到」当成
      「没漏洞」**——与规则 / 意图两条链的 fail-closed 口径保持一致。

    返回 ``{"status", "msg", "result", "pkgs"}``：
      status ∈ {"ok", "none", "error"}；result 即 ScanEngine.run_full_scan() 的返回。
    """
    import shutil
    import tempfile

    pkgs = _extract_req_specs(skills, names)
    if not pkgs:
        return {"status": "none", "msg": "", "result": None, "pkgs": []}

    tmpd = tempfile.mkdtemp(prefix="ov_dep_")
    try:
        req = os.path.join(tmpd, "requirements.txt")
        with open(req, "w", encoding="utf-8") as f:
            f.write("\n".join(pkgs) + "\n")
        from modules.engine import ScanEngine
        prog = st.progress(0.0, text="依赖漏洞研判中…")

        def _cb(msg, percent=None):
            if percent is not None:
                prog.progress(min(max(percent, 0), 100) / 100.0,
                              text=f"依赖漏洞研判：{msg}")

        r = ScanEngine().run_full_scan(
            uploaded_file_path=req, upload_mode="requirements",
            project_name="技能声明的依赖", include_transitive=False,
            use_nvd=True, do_epss=True, progress_cb=_cb)
        return {"status": "ok", "msg": "", "result": r, "pkgs": pkgs}
    except Exception as e:
        return {"status": "error", "msg": str(e), "result": None, "pkgs": pkgs}
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)


def _degraded_count(intents: dict) -> int:
    """统计分诊失败（PARSE_FAIL / degraded）的技能数——fail-closed 的依据。"""
    return sum(1 for j in intents.values()
               if j.get("degraded")
               or j.get("verdict") == "PARSE_FAIL"
               or j.get("scope") == "PARSE_FAIL")


def _render_install_decision(res: dict) -> None:
    """安装决定总结：有严重链路 → 建议不装并列出元凶；无可疑 → 可安装。

    🔴 fail-closed：只要存在分诊失败的技能，绝不出「可安装」结论。
    """
    chains = res["chains"]
    intents = res["intents"]
    failed = _degraded_count(intents)

    if chains:
        critical = [c for c in chains if c["sev"] == "严重"]
        culprits = sorted({c["mal"] for c in chains} | {c["other"] for c in chains})
        if critical:
            st.error(
                "❌ **安装决定：建议不安装。** 检测到 " + str(len(critical))
                + " 条严重组合链路（凭据外泄 / 命令回传 / 持续泄露级别）。\n\n"
                "元凶技能：" + "、".join(f"`{esc(c)}`" for c in culprits)
                + "\n\n即使每个技能单独看都只是「能做某事」，"
                  "组合后凑齐了完整攻击链——请从元凶技能开始排查。")
        else:
            st.warning(
                "⚠️ **安装决定：谨慎安装。** 未发现严重链路，但存在 "
                + str(len(chains)) + " 条高危组合链路，"
                "建议确认相关技能的业务必要性后再安装。")
        if failed:
            st.warning(
                f"⚠️ AI 分诊未完成（{failed}/{len(intents)} 失败），"
                "本报告仅覆盖分诊成功的技能——请检查 MaaS 配置后重新体检"
                "（失败技能未写缓存，恢复后会自动重判）。")
        return

    if failed:
        st.warning(
            f"⚠️ **AI 分诊未完成（{failed}/{len(intents)} 失败），"
            "本结论不可用于放行**——请检查 MaaS 配置后重新体检"
            "（失败技能未写缓存，恢复后会自动重判）。")
        return

    flagged = [n for n, j in intents.items()
               if j.get("verdict") in ("MALICIOUS", "SUSPICIOUS")]
    if flagged:
        st.warning(
            "⚠️ **安装决定：暂缓安装，建议人工复核。** 未发现成链组合，"
            "但以下技能的行为意图被 AI 判为可疑：" + "、".join(f"`{esc(n)}`" for n in flagged))
    elif res["ai_ok"]:
        st.success("✅ **安装决定：可安装。** 规则快筛无组合风险，"
                   "AI 分诊未发现可疑意图，三要素未成链。")
    else:
        st.info("✅ **规则侧结论：未发现组合风险。**（本次未做 AI 意图分诊，"
                "结论仅覆盖规则与能力共现维度）")


def _render_ai_table(res: dict) -> None:
    """阶段B 结果表：每技能一行，可展开核对原文证据行号。"""
    intents = res["intents"]
    if not intents:
        return
    st.markdown("#### 第 3 步 · AI 意图分诊")
    # P3-1：调用量预告持久渲染（_run_pipeline 里的临时提示会被 st.rerun 冲掉）
    if res.get("call_info"):
        st.info(res["call_info"])
    st.caption("每个技能一次调用，同时判定「行为意图」与「外发数据范围」两项；"
               "判定带原文行号证据，点击技能名可展开核对。"
               f"本次实际发起模型调用 {sum(1 for j in intents.values() if not j.get('cached'))}"
               f" 次（其余命中本地缓存，零调用）；分诊失败的技能未写入缓存，"
               "重试时会自动重判。")
    rows = []
    for n, j in intents.items():
        degraded = (j.get("degraded") or j.get("verdict") == "PARSE_FAIL"
                    or j.get("scope") == "PARSE_FAIL")
        rows.append({
            "技能": n,
            "状态": ("⚪ 分诊失败" if degraded
                     else ("💾 缓存命中" if j.get("cached") else "🌐 本次调用")),
            "行为意图": _VERDICT_LABEL.get(j.get("verdict"), j.get("verdict", "—")),
            "外发范围": _SCOPE_LABEL.get(j.get("scope"), j.get("scope", "—")),
            "意图理由": j.get("reason", ""),
            "证据行号": "、".join(str(x) for x in j.get("ev_intent", [])) or "—",
            "外发证据行号": "、".join(str(x) for x in j.get("ev_scope", [])) or "—",
        })
    st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True,
                 column_config={
                     "技能": st.column_config.TextColumn(width="medium"),
                     "意图理由": st.column_config.TextColumn(width="large"),
                 })

    lines_map = {n: res["skills"][n].split("\n") for n in intents}
    for n, j in intents.items():
        ev_lines = list(j.get("ev_intent", [])) + list(j.get("ev_scope", []))
        with st.expander(f"🔍 核对证据 · {n}"
                         + ("（缓存命中，未发起新调用）" if j.get("cached") else "")):
            st.markdown(
                f"- 意图：**{_VERDICT_LABEL.get(j.get('verdict'), j.get('verdict'))}**"
                f" —— {esc(j.get('reason', ''))}")
            st.markdown(
                f"- 外发范围：**{_SCOPE_LABEL.get(j.get('scope'), j.get('scope'))}**"
                f" —— {esc(j.get('scope_reason', ''))}")
            if ev_lines:
                for ln in sorted(set(ev_lines)):
                    if 1 <= ln <= len(lines_map[n]):
                        st.markdown(f"> **行 {ln}**：{esc(lines_map[n][ln - 1].strip())}")
            else:
                st.caption("模型未给出可核验的行号证据。")


def _render_chains(res: dict) -> None:
    """阶段C 组合报告 + 安装决定。"""
    from modules.combo_analysis import CAPABILITY_LABELS

    st.markdown("#### 第 4 步 · 组合判定报告")
    chains = res["chains"]
    if not chains:
        # 只报事实，不下结论——最终结论统一由「安装决定」给出，避免双重口径
        failed = _degraded_count(res["intents"])
        if failed:
            st.info(f"组合链路未检出（AI 分诊存在 {failed} 项失败，"
                    "最终结论见下方「安装决定」）。")
        else:
            st.success("✅ 未发现组合风险——三要素（能力互补 / 意图闸门 / 外发闸门）未成链。")
    else:
        sev_icon = {"严重": "🔴", "高危": "🟠"}
        rows = []
        for c in chains:
            rows.append({
                "链路模板": c["tid"],
                "严重度": sev_icon.get(c["sev"], "⚪") + " " + c["sev"],
                "作用域": c["scope"],
                "技能 A": c["mal"],
                "提供能力": CAPABILITY_LABELS.get(c["mal_cap"], c["mal_cap"]),
                "技能 B": c["other"] if c["other"] != c["mal"] else "（同一技能内部）",
                "提供能力 ": CAPABILITY_LABELS.get(c["other_cap"], c["other_cap"]),
                "外发范围": _SCOPE_LABEL.get(c["other_scope"], c["other_scope"]),
                "成链依据": c["why"],
            })
        st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True,
                     column_config={
                         "成链依据": st.column_config.TextColumn(width="large"),
                     })
        with st.expander("📖 链路明细（AI 理由与外发闸门核验）"):
            for c in chains:
                st.markdown(
                    f"**[{c['tid']}] {c['sev']} · {c['scope']}**\n\n"
                    f"- 技能 A `{esc(c['mal'])}` 提供「"
                    f"{CAPABILITY_LABELS.get(c['mal_cap'], c['mal_cap'])}」"
                    f"—— {esc(c['mal_reason']) or '（无 AI 理由）'}\n"
                    f"- 技能 B `{esc(c['other'])}` 提供「"
                    f"{CAPABILITY_LABELS.get(c['other_cap'], c['other_cap'])}」"
                    f"（外发范围：{_SCOPE_LABEL.get(c['other_scope'], c['other_scope'])}）"
                    f"—— {esc(c['other_reason']) or '（无 AI 理由）'}\n"
                    f"- 依据：{esc(c['why'])}")
    _render_install_decision(res)


def render() -> None:
    """渲染本视图（侧边栏「组合体检」入口）。"""
    if "combo_skills" not in st.session_state:
        st.session_state.combo_skills = {}
    if "combo_result" not in st.session_state:
        st.session_state.combo_result = None

    st.divider()
    section_title("🧬 组合体检")
    st.caption(
        "单点检测回答「这个技能有没有问题」，组合体检回答「**这批技能凑在一起会怎样**」。"
        "三段式流水线：32 条规则快筛 → AI 意图分诊（意图 + 外发范围，带磁盘缓存）"
        "→ 三要素成链（能力互补 × 意图闸门 × 外发闸门）。"
        "组合判定逻辑经探针实测：13 个多技能场景 13/13 全对（TP 6 / TN 7）；"
        "107 个真实语料产出 139 条组合链路，恶意端全部落在 5 个已知恶意样本内，"
        "其中 135 条集中在同一样本的 1×N 配对（明细见 samples/_probe_final.json）。")

    # ---- 第 1 步：选择技能来源 ----
    st.markdown("#### 第 1 步 · 选择待检技能")
    src_c1, src_c2 = st.columns(2)
    with src_c1:
        st.markdown("**方式一：上传多个 SKILL.md**")
        uploads = st.file_uploader("上传 SKILL.md（可多选）", type=["md"],
                                   accept_multiple_files=True, key="combo_upload")
    with src_c2:
        st.markdown("**方式二：选用内置示例场景**")
        opts = _load_scenario_options()
        picked = st.selectbox("示例场景（含真链路与假链路对照）",
                              ["（不上传，使用示例场景）"] + opts,
                              key="combo_scenario") if opts else None

    if st.button("🚀 开始组合体检",
                 disabled=not (uploads or (picked and picked != "（不上传，使用示例场景）")),
                 type="primary", key="combo_run_btn"):
        skills = {}
        overwritten = []
        if uploads:
            for f in uploads:
                name = f.name[:-3] if f.name.endswith(".md") else f.name
                if name in skills:
                    overwritten.append(name)
                skills[name] = f.getvalue().decode("utf-8", errors="ignore")
            if overwritten:
                st.warning("⚠️ 已覆盖同名技能：" + "、".join(f"`{esc(n)}`" for n in overwritten)
                           + "（同名后传覆盖先传）")
        elif picked:
            skills = _load_scenario_skills(picked)
        if skills:
            st.session_state.combo_skills = skills
            _run_pipeline(skills)

    res = st.session_state.combo_result
    if not res:
        return

    # ---- 第 2 步：规则快筛结果 ----
    st.markdown("#### 第 2 步 · 规则快筛（32 条规则，确定性结论）")
    skills = res["skills"]
    total_hits = sum(res["rule_hits"].values())
    m1, m2, m3 = st.columns(3)
    with m1:
        metric_card(len(skills), "待检技能数", icon="📦")
    with m2:
        flagged = sum(1 for v in res["rule_hits"].values() if v > 0)
        metric_card(flagged, "规则命中技能数",
                    color="metric-card-red" if flagged else "metric-card-green",
                    icon="⚠️")
    with m3:
        metric_card(total_hits, "命中风险点总数",
                    color="metric-card-red" if total_hits else "metric-card-green",
                    icon="🎯")
    st.dataframe(
        pd.DataFrame([{"技能": n, "规则命中数": res["rule_hits"][n]}
                      for n in skills]), width="stretch", hide_index=True)

    # ---- 第 3 步：AI 分诊表（未配置 MaaS 时已提示并跳过）----
    st.divider()
    if res["intents"]:
        _render_ai_table(res)
    elif not res["ai_ok"]:
        st.info("ℹ️ 第 3 步（AI 意图分诊）已跳过：未配置 MaaS。")

    # ---- 第 4 步：组合报告 + 安装决定 ----
    st.divider()
    _render_chains(res)
