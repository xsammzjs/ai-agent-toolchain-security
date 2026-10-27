"""
对外材料数字一致性检查
==================================================
扫描所有对外文档（README + docs/）里的关键数字，
与代码实测值比对，找出「材料写的 ≠ 实际跑的」。

用法：python samples/check_doc_consistency.py

为什么需要：
官方要求「组委会将根据队伍提交材料进行复现，若发现验证效果与答辩材料
呈现结果不符，则取消晋级&获奖资格」。
文档数字和实测数字必须严格一致——哪怕只差一个数，也是「不符」。

用法示例输出：
  [OK]   规则条数            32 条      全部出现
  [WARN] 代码行数            约7070行   docs/项目说明书.md 写的是 6,900
"""
import io
import os
import re
import sys
from collections import Counter

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from modules import skill_scanner as ss

# ==========================================================
# 对外文档范围（只有这些会交给评委/老师）
# ==========================================================
DOC_FILES = [
    "README.md",
    "docs/作品报告.md",
    "docs/项目说明书.md",
    "docs/模板1填写对照表.md",
    "docs/发给老师的说明.md",
    "docs/项目学习材料.md",
    "docs/汇报前最小清单.md",
    "docs/项目实况理解.md",
    "docs/CodeArts审计实践.md",
    # 2026-10-26 新增：这两份是给老师看的汇报材料，同样要守住口径
    "docs/项目讲解手册.md",
    "docs/汇报话术一页卡.md",
]

# ==========================================================
# 关键数字 → 允许出现的表述（正则）
# 每一个都必须能在文档里找到，否则说明文档漏了这个数
# ==========================================================
KEY_NUMBERS = [
    ("规则条数", 32, [r"32\s*条", r"32条"]),
    ("威胁类别", 8, [r"8\s*类", r"8类"]),
    ("误报率", 2.0, [r"2\.0%", r"误报\s*2%"]),
    ("检出率", 100.0, [r"100%"]),
    ("特异度", 98.0, [r"98%"]),
    ("样本总数", 107, [r"107\s*个", r"107个"]),
    ("回归断言", 151, [r"151\s*条", r"151条"]),
    ("扫描耗时", 33, [r"33\s*毫秒", r"33ms"]),
    ("代码规模", 9786, [r"9[,.]?78[0-9]\s*行"]),
    ("初始误报率", 58.6, [r"58\.6%"]),
    ("攻击链模板", 7, [r"7\s*(?:类|个)\s*链路", r"7\s*类链路"]),
    ("能力原子", 8, [r"8\s*(?:个|类)\s*能力", r"8\s*个能力"]),
]

# ==========================================================
# 明确禁止出现的过时表述
# ==========================================================
# 每条：(正则, 说明, 白名单)
# 白名单里的 (文件, 上下文关键词) 命中时跳过——
# 因为有些地方**故意**提到旧数字（讲历史演进、或者教人不要这么说）。
# 例：讲「第一版误报 58.6%」「早期 7 样本时误报 0%」是真实历史，应该保留。
BANNED = [
    (r"FPR\s*0%", "FPR 0%（正确值是 2.0%）", []),
    (r"6,722\s*行|6722\s*行", "6,722 行（实测核心 6,514）", []),
    (r"6,900\s*行|6900\s*行", "6,900 行（实测约 7,070）", []),
    (r"121\s*条回归|121\s*条断言", "121 条断言（实测 151 条）", []),
    (r"国奖无同类实现|国奖同类作品里没人做过",
     "「国奖无同类实现」——应限定调研范围",
     [("docs/发给老师的说明.md", "不要说"),
      ("docs/项目实况理解.md", "听着像在说华为赛赛道"),
      ("docs/项目实况理解.md", "比含糊说"),
      # 这两份是「反面清单」文档，列出的是**不能说的话**本身
      ("docs/项目讲解手册.md", "不要说"),
      ("docs/项目讲解手册.md", "听着像在说"),
      ("docs/汇报话术一页卡.md", "不要说")]),
    (r"误报率\s*0%|误报\s*0%",
     "误报率 0%（正确值是 2.0%）",
     [("docs/作品报告.md", "Snyk"),
      ("docs/CodeArts审计实践.md", "第一版检测规则"),
      ("docs/发给老师的说明.md", "第一版规则在手工构造"),
      ("docs/项目实况理解.md", "早期版本在手工构造")]),
    # 🔴 2026-10-25：作品报告第三章曾整段停留在旧的 7 样本口径，
    # 而第五章写的是 107 样本，同一份报告自相矛盾 → 答辩致命。
    (r"整体准确率\s*:\s*7/7|良性样本误报率\s*\(FPR\)\s*:\s*0/2\s*=\s*0\.0%",
     "作品报告第三章停留在旧 7 样本口径（正确：107 样本 / FPR 2.0%）",
     # 「Snyk 7 样本子集单独评测」那一段是**故意**保留的对照组，
     # 命中的是该段内的两行数字，所以白名单关键词要落在被命中的行上。
     [("docs/作品报告.md", "0/2 = 0.0%"),
      ("docs/作品报告.md", "7/7 = 100.0%")]),
    (r"规则数从\s*23\s*增至\s*25", "旧规则条数口径（现为 32 条）", []),
    # 🔴 2026-10-26 聚焦化重构后，「双链」不再是项目定位。
    #    老师明确要求功能聚焦，材料/UI 里不应再出现这个说法。
    (r"双链", "「双链」——现定位为 AI 技能组合风险体检站",
     [("docs/汇报话术一页卡.md", "不要说"),
      ("docs/汇报话术一页卡.md", "不要用")]),
    # 旧视图名：现叫「资产关联分析」
    (r"攻击链关联分析(?!)", "旧视图名「攻击链关联分析」（现为「资产关联分析」）", []),
    # 旧入口数量：现在是 4 个功能（依赖漏洞恢复独立入口）
    (r"3\s*个功能视图|三视图|三个视图|3\s*个视图",
     "旧视图数量（现为 4 个功能）", []),
    # 旧项目名
    (r"AI\s*技能供应链安全检测平台|AI\s*Agent\s*工具链安全检测平台",
     "旧项目名（现为「AI 技能组合风险体检站」）", []),
    # 🔴 复现校验项数：加检查项时数字必须同步更新（当前 14 项）
    (r"1[23]\s*项(?:第三方可复现)?校验|1[23]\s*项全绿",
     "复现校验项数过时（当前 14 项）", []),
]


UI_FILES = ["main.py"]

# UI 文案专用的禁止表述（对外可见，评委在浏览器里能直接看到）
UI_BANNED = [
    (r"29\s*条检测规则|29\s*条规则", "UI 写「29 条检测规则」（正确值 32 条）"),
    (r"FPR\s*0%", "UI 写「FPR 0%」（正确值 2.0%）"),
    (r"AI\s*辅助研判功能已整体移除|不再调用任何大模型",
     "UI 注释说「不再调用任何大模型」——与 adjudicator.py 矛盾"),
    # 🔴 2026-10-26 聚焦化：UI 里不得再出现旧定位
    (r"双链", "UI 出现「双链」——现定位为 AI 技能组合风险体检站"),
    (r"攻击链关联分析", "UI 出现旧视图名「攻击链关联分析」（现为「资产关联分析」）"),
    (r"AI\s*技能供应链安全检测平台|AI\s*Agent\s*工具链安全检测平台",
     "UI 出现旧项目名（现为「AI 技能组合风险体检站」）"),
]


def is_whitelisted(rel, line_text, whitelist):
    """白名单命中判断：该行是否属于「故意提及旧数字」的场景。"""
    for wl_file, wl_kw in whitelist:
        if rel == wl_file and wl_kw in line_text:
            return True
    return False


def read_doc(rel):
    p = os.path.join(ROOT, rel)
    if not os.path.isfile(p):
        return None
    return io.open(p, encoding="utf-8").read()


def measure_code_size():
    """按对外口径实测代码行数。

    口径（与 ``docs/项目说明书.md`` 的「代码规模」一行一致，评委可原样复算）::

        交付代码 = modules/ + views/ + launcher/ + main.py + config.py + start.py
        回归测试 = tests/test_regression.py

    返回 ``(交付代码行数, 回归测试行数, 合计)``。
    """
    def count(paths):
        total = 0
        for p in paths:
            full = os.path.join(ROOT, p)
            if os.path.isfile(full):
                total += sum(1 for _ in io.open(full, encoding="utf-8", errors="ignore"))
            elif os.path.isdir(full):
                for dp, dn, fns in os.walk(full):
                    dn[:] = [d for d in dn if d != "__pycache__"]
                    for fn in fns:
                        if fn.endswith(".py"):
                            total += sum(1 for _ in io.open(os.path.join(dp, fn),
                                                            encoding="utf-8", errors="ignore"))
        return total

    core = count(["modules", "views", "launcher", "main.py", "config.py", "start.py"])
    test = count([os.path.join("tests", "test_regression.py")])
    return core, test, core + test


def main():
    print("=" * 76)
    print("对外材料数字一致性检查")
    print("=" * 76)
    print(f"文档范围：{len(DOC_FILES)} 份\n")

    docs = {}
    for rel in DOC_FILES:
        s = read_doc(rel)
        if s is not None:
            docs[rel] = s
    print(f"实际读到 {len(docs)} 份\n")

    # ---------- ① 关键数字必须出现 ----------
    print("① 关键数字是否在对外材料中正确出现")
    print("-" * 76)
    miss_count = 0
    for label, val, patterns in KEY_NUMBERS:
        found_in = []
        for rel, s in docs.items():
            for pat in patterns:
                if re.search(pat, s):
                    found_in.append(rel)
                    break
        if found_in:
            print(f"  [OK]   {label:12s} {str(val):10s} 出现在 {len(found_in)} 份文档")
        else:
            print(f"  [MISS] {label:12s} {str(val):10s} ❌ 所有文档都没找到")
            miss_count += 1

    # ---------- ② 禁止表述 ----------
    print("\n② 是否存在已过时的表述")
    print("-" * 76)
    bad_count = 0
    for pat, why, whitelist in BANNED:
        hits = []
        skipped = 0
        for rel, s in docs.items():
            lines = s.splitlines()
            for m in re.finditer(pat, s):
                line_no = s[:m.start()].count("\n")
                line_text = lines[line_no] if line_no < len(lines) else ""
                if is_whitelisted(rel, line_text, whitelist):
                    skipped += 1
                    continue
                hits.append(f"{rel}:{line_no + 1}  {line_text.strip()[:60]}")
        if hits:
            print(f"  [WARN] {why}")
            for h in hits[:6]:
                print(f"         {h}")
            bad_count += len(hits)
        else:
            note = f"（{skipped} 处为故意提及，已豁免）" if skipped else ""
            print(f"  [OK]   无「{pat}」{note}")

    # ---------- ③ UI 文案一致性（main.py 浏览器里直接可见） ----------
    print("\n③ UI 文案（main.py，对外可见）")
    print("-" * 76)
    ui_bad = 0
    for rel in UI_FILES:
        s = read_doc(rel)
        if s is None:
            print(f"  [SKIP] {rel} 未找到")
            continue
        for pat, why in UI_BANNED:
            for m in re.finditer(pat, s):
                lines = s.splitlines()
                line_no = s[:m.start()].count("\n")
                line_text = lines[line_no] if line_no < len(lines) else ""
                print(f"  [WARN] {why}")
                print(f"         {rel}:{line_no + 1}  {line_text.strip()[:60]}")
                ui_bad += 1
    if ui_bad == 0:
        print("  [OK]   UI 文案无过时表述")

    # ---------- ④ 实测值与材料对照 ----------
    print("\n④ 代码实测值")
    print("-" * 76)
    print(f"  RULE_TABLE 条数：{len(ss.RULE_TABLE)}（对外口径 32）")
    cats = Counter(r[0] for r in ss.RULE_TABLE)
    print(f"  表内威胁类别：{len(cats)}（对外口径 8 = 表内 7 + 隐藏字符注入 1）")
    print(f"  严重度分布：{dict(Counter(r[1] for r in ss.RULE_TABLE))}")

    # ---------- ⑤ 代码规模：材料声明 vs 实测（防「材料数字 ≠ 实际」） ----------
    print("\n⑤ 代码规模（材料声明 vs 实测）")
    print("-" * 76)
    core, test, total = measure_code_size()
    print(f"  实测交付代码：{core} 行｜回归测试：{test} 行｜合计：{total} 行")
    claimed = {}
    for rel, s in docs.items():
        for m in re.finditer(r"([\d][\d,]*)\s*行", s):
            v = int(m.group(1).replace(",", ""))
            if 5000 <= v <= 20000:          # 只认代码规模量级的数字，避开「第 15 行」等
                claimed.setdefault(v, set()).add(rel)
    size_bad = 0
    if not claimed:
        print("  [WARN] 材料里找不到可校验的代码规模数字")
        size_bad += 1
    for v in sorted(claimed):
        best = min((core, total), key=lambda t: abs(v - t) / t)
        drift = abs(v - best) / best
        where = "、".join(sorted(claimed[v])[:3])
        if drift <= 0.03:
            print(f"  [OK]   材料写 {v:,} 行，与实测（{best:,} 行）偏差 {drift * 100:.1f}%　{where}")
        else:
            print(f"  [WARN] 材料写 {v:,} 行，与实测（{best:,} 行）偏差 {drift * 100:.1f}%，超 3%")
            print(f"         {where}")
            size_bad += 1

    # ---------- 汇总 ----------
    print("\n" + "=" * 76)
    if miss_count or bad_count or ui_bad or size_bad:
        print(f"发现 {miss_count} 项缺失、{bad_count} 处过时表述、"
              f"{ui_bad} 处 UI 过时、{size_bad} 处代码规模不符")
        print("=" * 76)
        return 1
    print("✅ 对外材料数字全部一致，无过时表述")
    print("=" * 76)
    return 0


if __name__ == "__main__":
    sys.exit(main())
