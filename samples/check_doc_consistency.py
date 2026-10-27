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
sys.path.insert(0, os.path.join(ROOT, "samples"))

from modules import skill_scanner as ss

# 代码规模的**唯一实现**在这里。本脚本只引用，不重新实现——
# 两个脚本各算一套口径，会被旧快照写回覆盖后互相打架（2026-10-27 实测）。
import check_code_size as _check_code_size

# 对外材料里「代码规模」这个数必须是实测值，所以关键数字表也直接取实测值，
# 不用硬编码 —— 材料写错时 ① 会直接报 MISS，而不是等到第 ⑤ 项才被发现。
_CODE_SIZE_TOTAL = _check_code_size.measure()["total"]

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
    ("代码规模", _CODE_SIZE_TOTAL, [rf"{_CODE_SIZE_TOTAL:,}\s*行", rf"{_CODE_SIZE_TOTAL}\s*行"]),
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
    (r"6,722\s*行|6722\s*行", "6,722 行（实测全交付 10,328）", []),
    (r"6,900\s*行|6900\s*行", "6,900 行（实测全交付 10,328）", []),
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
    # 旧入口数量：现在是 5 个功能（依赖漏洞恢复独立入口，组合体检独立成视图）
    (r"3\s*个功能视图|三视图|三个视图|3\s*个视图|三个功能|三视图",
     "旧视图数量（现为 5 个功能）", []),
    # 🔴 2026-10-27 口径收敛后：入口数、链路模板数、能力原子数、UI 入口数
    #    都已经统一，下面这几条是**防回退**用的——
    #    旧口径一旦被抄回文档，材料会与代码/正文自相矛盾。
    (r"(?<![0-9])3\s*个功能|四个功能|四大功能|四个界面",
     "旧入口数量（现为 5 个功能：AI 技能安全检测 / 组合体检 / 依赖漏洞检测 / 资产关联分析 / 离线演示）", []),
    (r"6\s*类链路模板|6\s*个能力原子|6\s*类危险能力",
     "旧链路/能力原子口径（现为 8 个能力原子 / 7 类链路模板）",
     # 「旧图存档警告」是故意引用旧口径来说明「不能插」，豁免
     [("docs/模板1填写对照表.md", "旧图"),
      ("docs/模板1填写对照表.md", "不得插入"),
      ("docs/模板1填写对照表.md", "仅供存档"),
      ("docs/模板1填写对照表.md", "直接冲突")]),
    # AI 的定位：现在是「意图闸门 + 外发范围闸门」，不是「只汇总不判定」
    (r"AI\s*只汇总|只汇总，不改判定|AI\s*只做汇总|不参与判定",
     "旧 AI 定位（现为 AI 意图分诊是组合判定的必要环节）",
     [("docs/模板1填写对照表.md", "旧图"),
      ("docs/模板1填写对照表.md", "不得插入"),
      ("docs/模板1填写对照表.md", "仅供存档"),
      ("docs/模板1填写对照表.md", "直接冲突")]),
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

    口径的唯一来源是 ``samples/check_code_size.py``（本函数直接 import 它的
    ``measure()``，**不再自己算一遍**）——两个脚本各算一套口径，迟早会被旧快照
    写回覆盖、互相打架：2026-10-27 这一天就因此在 9,786 与 10,307 之间反复翻转。

    口径**不在本文件里写死**——唯一来源是 ``samples/check_code_size.py``
    （它同时也是对外材料「代码规模」那一行标注的统计脚本，评委就按它复算）。
    本函数只取它的实测结果，所以口径怎么定、两个脚本都不会打架。

    返回 ``(交付代码行数, 回归测试行数, 合计)``。
    """
    stats = _check_code_size.measure()
    return stats["deliver_total"], stats["test_total"], stats["total"]


def measure_runtime_values():
    """实测「代码运行时会算出来的对外数字」，与材料承诺的口径对撞。

    返回 ``[(标签, 实测值, 对外口径, 不一致时的说明), ...]``。

    【为什么要单独做这一项】
    本脚本的 ①②③④ 只看**文字**——文档里写了 32 条规则，文档里就通过了；
    但代码里 ``len(RULE_TABLE) + 3`` 算出来是 33，浏览器和导出的报告里
    显示的是 33，**文字检查完全发现不了**。2026-10-27 就这样漏过一次
    （`modules/skill_scanner.py` 的 rule_count 写成了 +3）。

    这里把同一批数字的**运行时实测值**取出来跟对外口径直接对撞：
    对不上就 [WARN] + 退出码置 1，跟现有的守卫保持同一套严格度。

    口径一旦要改，这里也要同步改 —— 这正是它该有的成本：改数字必须两处一起改。
    """
    # 规则条数：RULE_TABLE 30 条正则 + 隐藏字符检测通道 1 + 跨行组合规则 1 = 32
    rule_count = ss.scan_skill_text("t", "hello")["stats"]["rule_count"]
    # 威胁类别：表内 7 类 + 隐藏字符注入 1 类 = 8
    cats = len(Counter(r[0] for r in ss.RULE_TABLE)) + 1
    # 能力原子 / 链路模板：新主线的两个对外数字
    from modules import combo_analysis as _ca
    caps = len(_ca.CAPABILITY_PATTERNS)
    templates = len(_ca.PAIR_TEMPLATES)

    return [
        ("检测规则数", rule_count, 32,
         "modules/skill_scanner.py 的 stats.rule_count 算成了 "
         f"{rule_count}（对外口径 32 = RULE_TABLE 30 + 隐藏字符通道 1 + 跨行组合规则 1）。"
         "界面「检测规则数」指标卡与导出的 Markdown 报告都会写这个值，"
         "会与材料的 32 条对不上。"),
        ("RULE_TABLE 条数", len(ss.RULE_TABLE), 30,
         "modules/skill_scanner.py 的 RULE_TABLE 条数变了，"
         "对外口径 32 条规则（30 正则 + 2 条模块级）需同步核对。"),
        ("威胁类别数", cats, 8,
         "对外口径 8 类威胁（表内 7 类 + 隐藏字符注入 1 类）需同步核对。"),
        ("能力原子数", caps, 8,
         "对外口径 8 个能力原子（modules/combo_analysis.py 的 CAPABILITY_PATTERNS）"
         "需同步核对。"),
        ("链路模板数", templates, 7,
         "对外口径 7 类链路模板（modules/combo_analysis.py 的 PAIR_TEMPLATES）"
         "需同步核对。"),
    ]


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

    # ---------- ⑥ 运行时口径断言（防「界面显示 ≠ 材料口径」） ----------
    # 🔴 2026-10-28 新增。之前本脚本只扫**文档文字**，扫不到**运行时值**，
    #    于是 `modules/skill_scanner.py` 里把 rule_count 写成 len(RULE_TABLE)+3
    #    （运行时 = 33）时，材料全部写 32、脚本全部报 [OK]，**没有任何一处报警**。
    #    结果：浏览器里的「检测规则数」指标卡显示 33、导出的 Markdown 报告写 33，
    #    评委下载的报告与材料对不上 —— 官方要求「验证效果与答辩材料呈现结果不符」
    #    即取消资格，这类漂移是致命的。
    #    本项把「代码实际算出来的数」与「对外承诺的数」直接对撞，值不同就退出码置 1。
    print("\n⑥ 运行时口径断言（代码实测值 vs 对外承诺值）")
    print("-" * 76)
    runtime_bad = 0
    for label, actual, expected, why in measure_runtime_values():
        if actual == expected:
            print(f"  [OK]   {label:22s} {actual:>6} （对外口径 {expected}）")
        else:
            print(f"  [WARN] {label:22s} {actual:>6} ≠ 对外口径 {expected}")
            print(f"         {why}")
            runtime_bad += 1

    # ---------- 汇总 ----------
    print("\n" + "=" * 76)
    if miss_count or bad_count or ui_bad or size_bad or runtime_bad:
        print(f"发现 {miss_count} 项缺失、{bad_count} 处过时表述、"
              f"{ui_bad} 处 UI 过时、{size_bad} 处代码规模不符、"
              f"{runtime_bad} 处运行时口径不符")
        print("=" * 76)
        return 1
    print("✅ 对外材料数字全部一致，无过时表述")
    print("=" * 76)
    return 0


if __name__ == "__main__":
    sys.exit(main())
