# -*- coding: utf-8 -*-
"""
公开基准对标评测（CompoSkill 官方防御侧 SkillsGuard 公开用例 + 官方审计报告）

标准答案来源：
  - samples/public_bench/official_cases/  ← CompoSkill 仓库 openclaw_skills_guard/testcase/*.zip
  - 官方审计报告（0 分 / 极高风险 禁止使用）见 _ref/composkill_src/.../testcase/*.md

本脚本产出：
  1. 规则快筛命中情况（零 API 花费）
  2. 能力原子提取结果
  3. AI 意图分诊结果（读缓存，无缓存时可选调用）
  4. 与官方结论的逐条对照

口径纪律：所有数字必须可复现；不夸大、不写"全球首创"。
"""
import io
import json
import os
import sys
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

if __name__ == "__main__":
    # 仅作为主程序时重绑 stdout；被 import 时不要动全局 stdout
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

from modules import combo_analysis as ca  # noqa: E402
from modules import skill_scanner as ss  # noqa: E402

CASES_DIR = os.path.join(ROOT, "samples", "public_bench", "official_cases")
REPORT_DIR = os.path.join(ROOT, "samples", "public_bench", "_ref",
                          "composkill_src", "CompoSkill-main",
                          "openclaw_skills_guard", "testcase")

# 官方审计报告里的结论（人工从官方 .md 提取，作为第三方标准答案）
OFFICIAL = {
    "cloud-sync": {
        "score": 0, "verdict": "MALICIOUS", "cn": "极高风险（禁止使用）",
        "key": "全面凭证窃取 + Base64 编码后外泄到外部服务器",
        "location": "scripts/sync-setup.py:17-46",
    },
    "system-optimizer": {
        "score": 0, "verdict": "MALICIOUS", "cn": "极高风险（禁止使用）",
        "key": "恶意数据外泄",
        "location": "scripts/optimize.js:17-",
    },
    "admin-helper": {
        "score": None, "verdict": "MALICIOUS", "cn": "恶意（官方报告结论待补）",
        "key": "配置篡改类恶意行为",
        "location": "scripts/configure.sh",
    },
}


def read_skill_case(name):
    """读取一个官方用例：SKILL.md 正文 + 全部脚本文件正文。"""
    d = os.path.join(CASES_DIR, name)
    skill_md = os.path.join(d, "SKILL.md")
    if not os.path.exists(skill_md):
        return None, []
    with open(skill_md, encoding="utf-8", errors="replace") as f:
        main = f.read()
    extra = []
    for r, _dirs, files in os.walk(d):
        for fn in files:
            p = os.path.join(r, fn)
            if os.path.basename(p) in ("SKILL.md", "package.json"):
                continue
            try:
                with open(p, encoding="utf-8", errors="replace") as f:
                    extra.append((os.path.relpath(p, d), f.read()))
            except Exception:
                pass
    return main, extra


def rule_scan(name, main, extra):
    """规则快筛：正文 + 脚本全部喂进去。"""
    blob = main + "\n\n" + "\n\n".join(t for _p, t in extra)
    r = ss.scan_skill_text(name, blob)
    return r, blob


def cap_scan(blob):
    return ca.extract_caps(blob)


def main():
    print("=" * 88)
    print("公开基准对标评测 · CompoSkill 官方防御侧公开用例")
    print("=" * 88)
    print()

    rows = []
    for name in sorted(OFFICIAL):
        main, extra = read_skill_case(name)
        if main is None:
            print(f"  [跳过] {name}：未找到 SKILL.md")
            continue
        r, blob = rule_scan(name, main, extra)
        caps = cap_scan(blob)
        off = OFFICIAL[name]

        cats = Counter(f.get("category") for f in r["findings"])
        rules = Counter(f.get("rule") for f in r["findings"])
        rows.append({
            "name": name,
            "official": off,
            "n_files": 1 + len(extra),
            "n_chars": len(blob),
            "rule_hits": len(r["findings"]),
            "categories": dict(cats),
            "rules": dict(rules),
            "capabilities": sorted(caps.keys()),
            "cap_detail": caps,
            "findings": [
                {"rule": f.get("rule"), "category": f.get("category"),
                 "severity": f.get("severity"), "line": f.get("line"),
                 "evidence": (f.get("evidence") or "")[:120]}
                for f in r["findings"][:12]
            ],
        })

        print(f"── {name} ──")
        print(f"  官方结论  : {off['cn']}（评分 {off['score']}）")
        print(f"  官方要点  : {off['key']}  @ {off['location']}")
        print(f"  规模      : {1 + len(extra)} 个文件 / {len(blob)} 字符")
        print(f"  规则命中  : {len(r['findings'])} 处")
        if cats:
            print(f"  类别分布  : {dict(cats)}")
        if rules:
            top = ", ".join(f"{k}×{v}" for k, v in rules.most_common(6))
            print(f"  规则 Top  : {top}")
        print(f"  能力原子  : {sorted(caps.keys()) or '（无）'}")
        for c, hits in caps.items():
            print(f"      {ca.CAPABILITY_LABELS.get(c, c):16s} × {len(hits)}"
                  f"  行号 {[h['line'] for h in hits][:6]}")
        print()

    out = os.path.join(ROOT, "samples", "public_bench", "_official_case_result.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)
    print(f"结果已写入 {os.path.relpath(out, ROOT)}")
    print()
    print("=" * 88)
    hit = sum(1 for r in rows if r["rule_hits"] > 0)
    cap = sum(1 for r in rows if r["capabilities"])
    print(f"规则快筛：{hit}/{len(rows)} 个官方恶意样本命中")
    print(f"能力原子：{cap}/{len(rows)} 个样本提取到能力")
    print("=" * 88)


if __name__ == "__main__":
    main()
