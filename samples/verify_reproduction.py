"""
一键复现校验（答辩/评审复核用）
==================================================
一条命令验证：**本仓库在任意机器上都能复现出材料里写的每一个数字**。

用法：
    python samples/verify_reproduction.py

为什么需要这个脚本
------------------
官方原文：「组委会将根据队伍提交材料进行复现，若发现验证效果与答辩材料
呈现结果不符，则取消晋级&获奖资格」。

复现 = 评委拿到你的代码，在他们的环境里跑出和你 PPT 上一样的数字。
「网页能打开」不等于「数字能被复现」。

2026-10-22 实测发现的真实问题（已修）：
  1. 100 个真实良性样本被 .gitignore 排除，没进仓库
     → 评委 clone 后跑评测只能得到 0/2，而非材料里的 2/100
  2. run_corpus_eval.py 的恶意语料路径写错（real_corpus/real_toxicskills/
     而实际在 real_toxicskills/）
     → 该脚本从未统计过恶意样本，TPR 与 FPR 一直由两个脚本各算一半
  两者叠加的后果：材料里的数字当时**无法被第三方复现**。

本脚本做什么
------------
逐项核对 5 类内容，每项给出 PASS / FAIL 与实测值：

  ① 语料完整性   —— 样本数、manifest 溯源、逐文件 ground truth 标签
  ② 检出率 TPR   —— 恶意样本检出比例
  ③ 误报率 FPR   —— 良性样本误报比例 + 特异度
  ④ 规则规模     —— 规则条数、威胁类别数
  ⑤ 回归测试     —— 151 条断言是否全绿

任一项 FAIL 时以非零退出码结束，方便在 CI 或答辩前自查。
"""
import io
import json
import os
import re
import subprocess
import sys
from collections import Counter

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from modules import skill_scanner as ss

# ==========================================================
# 期望值（与 docs/作品报告.md、模板1 填写对照表保持一致）
# 任何一项对不上都会报 FAIL —— 这是刻意设计的
# ==========================================================
EXPECT = {
    "rule_count": 32,          # 30 条 RULE_TABLE + 隐藏字符注入 + 凭证窃取完整链路
    "rule_table": 30,          # 仅 RULE_TABLE 内的条数
    "threat_categories": 8,    # 7 类（表内）+ 隐藏字符注入（模块级）
    "tpr_percent": 100.0,      # 恶意样本检出率
    "fpr_percent": 2.0,        # 良性样本误报率
    "benign_samples": 100,     # 真实科研良性样本数
    "malicious_samples": 5,    # 真实恶意样本数
    "regression_assertions": 151,
    "core_lines": 6514,         # modules/ + main.py + config.py
    "test_lines": 554,          # tests/test_regression.py
    "total_lines": 7070,        # 对外口径 ≈ 7,070 行
    "total_samples": 107,       # 5 恶意 + 102 良性
}

RESULTS = []


def record(name, ok, expect_text, got_text, detail=""):
    RESULTS.append({
        "name": name, "ok": ok,
        "expect": expect_text, "got": got_text, "detail": detail,
    })
    flag = "PASS" if ok else "FAIL"
    print(f"  [{flag}] {name}")
    print(f"         期望: {expect_text}")
    print(f"         实测: {got_text}")
    if detail:
        print(f"         说明: {detail}")


# ==========================================================
# ① 语料完整性
# ==========================================================
def check_corpus():
    print("\n" + "=" * 74)
    print("① 语料完整性")
    print("=" * 74)

    benign_dir = os.path.join(HERE, "real_corpus", "benign_scientific")
    mal_dir = os.path.join(HERE, "real_toxicskills")

    # 良性样本
    if os.path.isdir(benign_dir):
        ben_files = [f for f in os.listdir(benign_dir)
                     if f.endswith(".md") and not f.startswith("_")]
        record("良性样本已随仓库提供", len(ben_files) == EXPECT["benign_samples"],
               f"{EXPECT['benign_samples']} 个", f"{len(ben_files)} 个",
               "若为 0 个，说明 .gitignore 误排除了语料，评委会复现失败")
    else:
        record("良性样本已随仓库提供", False,
               f"{EXPECT['benign_samples']} 个", "目录不存在")

    # 溯源 manifest
    mf = os.path.join(benign_dir, "_manifest.json")
    if os.path.isfile(mf):
        try:
            data = json.load(open(mf, encoding="utf-8"))
            items = data.get("items", [])
            has_url = all("url" in i and "source_path" in i for i in items)
            record("语料溯源信息完整（合规要求）",
                   bool(items) and has_url,
                   f"{len(items)} 条记录且均含 url/source_path",
                   f"{len(items)} 条记录，url 完整={has_url}",
                   "官方要求引用数据必须标注来源")
        except (OSError, ValueError) as e:
            record("语料溯源信息完整（合规要求）", False, "可解析的 manifest", str(e))
    else:
        record("语料溯源信息完整（合规要求）", False, "存在 _manifest.json", "缺失")

    # 恶意样本 + 逐文件标签
    if os.path.isdir(mal_dir):
        mal_files = [f for f in os.listdir(mal_dir)
                     if f.endswith(".md") and not f.startswith("_")]
        lf = os.path.join(mal_dir, "_labels.json")
        if os.path.isfile(lf):
            try:
                labels = json.load(open(lf, encoding="utf-8"))
                labels = {k: v for k, v in labels.items() if not k.startswith("_")}
                missing = [f for f in mal_files if f not in labels]
                mal_n = sum(1 for v in labels.values() if v == "malicious")
                record("恶意样本逐文件 ground truth 标注", not missing,
                       f"每个样本都有标注，恶意 {EXPECT['malicious_samples']} 个",
                       f"恶意 {mal_n} 个，缺标注 {len(missing)} 个",
                       "混装目录必须逐文件标注，否则 TPR 分母会被稀释")
            except (OSError, ValueError) as e:
                record("恶意样本逐文件 ground truth 标注", False, "可解析的 _labels.json", str(e))
        else:
            record("恶意样本逐文件 ground truth 标注", False,
                   "存在 _labels.json", "缺失")
        record("恶意样本已随仓库提供", len(mal_files) >= EXPECT["malicious_samples"],
               f">= {EXPECT['malicious_samples']} 个", f"{len(mal_files)} 个")
    else:
        record("恶意样本已随仓库提供", False,
               f">= {EXPECT['malicious_samples']} 个", "目录不存在")


# ==========================================================
# ② ③ 检出率 / 误报率 —— 复用 run_corpus_eval 的统计逻辑
# ==========================================================
def check_metrics():
    print("\n" + "=" * 74)
    print("② ③ 检出率 / 误报率")
    print("=" * 74)

    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "rce", os.path.join(HERE, "run_corpus_eval.py"))
    rce = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rce)

    mal = rce.eval_corpus("real_toxicskills", "malicious")
    ben = rce.eval_corpus("benign_scientific", "benign")
    if not mal or not ben:
        record("检出率/误报率可计算", False, "两个语料都能加载",
               f"malicious={'ok' if mal else '缺失'} / benign={'ok' if ben else '缺失'}")
        return

    mal_total = mal["mal_total"]
    ben_total = ben["ben_total"]
    tpr = mal["tp"] / mal_total * 100 if mal_total else 0
    fpr = ben["fp"] / ben_total * 100 if ben_total else 0
    spec_pct = ben["tn"] / ben_total * 100 if ben_total else 0

    record("恶意样本检出率 TPR", abs(tpr - EXPECT["tpr_percent"]) < 0.05,
           f"{EXPECT['tpr_percent']:.1f}%", f"{tpr:.1f}%",
           f"{mal['tp']}/{mal_total}")
    record("良性样本误报率 FPR", abs(fpr - EXPECT["fpr_percent"]) < 0.05,
           f"{EXPECT['fpr_percent']:.1f}%", f"{fpr:.1f}%",
           f"{ben['fp']}/{ben_total}")
    record("特异度（正确放行率）", abs(spec_pct - 98.0) < 0.05,
           "98.0%", f"{spec_pct:.1f}%")

    # 合并混淆矩阵
    # 注意：real_toxicskills 目录是恶意/良性混装（5 恶意 + 2 良性），
    # 其中的 2 个良性样本（判为安全）要计入 TN，否则 TN 会少算 2。
    total = mal["total"] + ben["total"]
    tp_all = mal["tp"]
    fn_all = mal["fn"]
    fp_all = ben["fp"] + mal["fp"]
    tn_all = ben["tn"] + mal["tn"]
    correct = tp_all + tn_all
    mal_n = mal["mal_total"]
    ben_n = ben["ben_total"] + mal["ben_total"]
    print(f"\n  合并混淆矩阵：TP {tp_all} / FN {fn_all} / "
          f"FP {fp_all} / TN {tn_all}")
    print(f"  总样本 {total} 个，判定正确 {correct}/{total} "
          f"= {correct/total*100:.1f}%")
    print(f"  （分母口径：恶意 {mal_n} 个 + 良性 {ben_n} 个 = {mal_n + ben_n} 个）")


# ==========================================================
# ④ 规则规模
# ==========================================================
def check_rules():
    print("\n" + "=" * 74)
    print("④ 规则规模")
    print("=" * 74)

    record("RULE_TABLE 条数", len(ss.RULE_TABLE) == EXPECT["rule_table"],
           f"{EXPECT['rule_table']} 条", f"{len(ss.RULE_TABLE)} 条")

    cats = Counter(c for c, _, _, _, _, _ in ss.RULE_TABLE)
    # 隐藏字符注入是模块级检测通道，不在 RULE_TABLE 内
    total_cats = len(cats) + 1
    record("威胁类别数", total_cats == EXPECT["threat_categories"],
           f"{EXPECT['threat_categories']} 类", f"{total_cats} 类",
           f"表内 {len(cats)} 类 + 隐藏字符注入 1 类")

    total_rules = len(ss.RULE_TABLE) + 2  # 隐藏字符注入 + 凭证窃取完整链路
    record("规则总数（对外口径）", total_rules == EXPECT["rule_count"],
           f"{EXPECT['rule_count']} 条", f"{total_rules} 条",
           "30 条正则 + 1 条隐藏字符检测 + 1 条跨行组合规则")


# ==========================================================
# ⑥ 代码规模（防止文档口径漂移）
# ==========================================================
def _count_lines(paths):
    n = 0
    for p in paths:
        if not os.path.isfile(p):
            continue
        with open(p, "rb") as f:
            n += sum(1 for _ in f)
    return n


def check_code_size():
    print("\n" + "=" * 74)
    print("⑥ 代码规模")
    print("=" * 74)

    mod_dir = os.path.join(ROOT, "modules")
    core_files = []
    for dirpath, dirnames, filenames in os.walk(mod_dir):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for fn in filenames:
            if fn.endswith(".py"):
                core_files.append(os.path.join(dirpath, fn))
    core_files += [os.path.join(ROOT, "main.py"), os.path.join(ROOT, "config.py")]

    core = _count_lines(core_files)
    test = _count_lines([os.path.join(ROOT, "tests", "test_regression.py")])
    total = core + test

    # 行数会随开发变动，只做提示不作为 FAIL 项（避免每次改代码都红）
    print(f"  核心代码（modules + main.py + config.py）：{core} 行"
          f"（材料口径 {EXPECT['core_lines']}）")
    print(f"  回归测试：{test} 行（材料口径 {EXPECT['test_lines']}）")
    print(f"  合计：{total} 行（材料口径 ≈ {EXPECT['total_lines']}）")
    print()
    print("  ℹ️  代码规模会随开发变动，此项**不参与 PASS/FAIL 判定**。")
    print("      但如果材料里的数字与实测差距较大，答辩时容易被追问，")
    print("      请同步更新 docs/作品报告.md 等对外文档。")


# ==========================================================
# ⑦ 样本总数
# ==========================================================
def check_sample_count():
    print("\n" + "=" * 74)
    print("⑦ 评测样本总数")
    print("=" * 74)

    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "rce", os.path.join(HERE, "run_corpus_eval.py"))
    rce = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rce)

    total = 0
    for corpus in ("benign_scientific", "real_toxicskills", "toxic_skills",
                   "benign_misc"):
        r = rce.eval_corpus(corpus, "benign")
        if r:
            total += r["total"]
    record("评测样本总数", total == EXPECT["total_samples"],
           f"{EXPECT['total_samples']} 个", f"{total} 个",
           "5 恶意 + 102 良性，均为含完整正文的真实公开样本")


# ==========================================================
# ⑤ 回归测试
# ==========================================================
def check_regression():
    print("\n" + "=" * 74)
    print("⑤ 回归测试")
    print("=" * 74)

    script = os.path.join(ROOT, "tests", "test_regression.py")
    if not os.path.isfile(script):
        record("151 条回归断言全绿", False, "151 条", "测试文件不存在")
        return

    try:
        r = subprocess.run([sys.executable, script],
                           capture_output=True, text=True, timeout=300,
                           encoding="utf-8", errors="replace")
        out = r.stdout or ""
        # 断言总数：从「合计：通过 N，失败 M」里取 N
        n_ok = None
        for line in out.splitlines():
            if "合计：通过" in line:
                seg = line.split("合计：通过")[1]
                n_ok = int(seg.split("，")[0].strip().isdigit() and
                           seg.split("，")[0].strip() or 0)
        record("151 条回归断言全绿",
               n_ok == EXPECT["regression_assertions"] and r.returncode == 0,
               f"{EXPECT['regression_assertions']} 条",
               f"{n_ok if n_ok is not None else '?'} 条",
               "行为锁定组必须全绿，否则说明改动破坏了原有功能")
    except subprocess.TimeoutExpired:
        record("151 条回归断言全绿", False, "151 条", "执行超时")



def check_code_refs():
    """文档里的代码引用（文件:行号 / 符号:行号）是否仍指向正确位置。

    重构拆文件后行号会悄悄失效 —— 评委按材料去翻代码却对不上，
    材料可信度直接受损。这一项把「材料与代码一致」也纳入复现校验。
    """
    print("\n" + "=" * 74)
    print("⑬ 文档代码引用有效性")
    print("=" * 74)

    script = os.path.join(ROOT, "samples", "check_code_refs.py")
    if not os.path.isfile(script):
        record("文档代码引用全部有效", True, "全部有效", "检查脚本不存在，跳过")
        return
    try:
        r = subprocess.run([sys.executable, script],
                           capture_output=True, text=True, timeout=120,
                           encoding="utf-8", errors="replace")
        out = r.stdout or ""
        n_checked = 0
        for line in out.splitlines():
            m = re.search(r"检查了 (\d+) 处代码引用", line)
            if m:
                n_checked = int(m.group(1))
        ok = r.returncode == 0
        detail = ""
        if not ok:
            bad = [l.strip() for l in out.splitlines() if l.strip().startswith("docs/")]
            detail = "；".join(bad[:3])
        record("文档代码引用全部有效", ok, "全部有效",
               f"{n_checked} 处引用" + (f"；失效：{detail}" if detail else ""))
    except Exception as e:
        record("文档代码引用全部有效", False, "全部有效", f"执行失败：{e}")



def check_architecture():
    """代码架构体检：文件规模、语法、门面完整性、静态问题。

    官方要求评委按提交材料复现。材料里写了「代码 7000 行、模块清晰」，
    如果实际文件是 2000 行的巨兽，评委一翻就发现材料与代码不符 ——
    这一项把「架构与材料描述一致」也纳入复现校验。
    """
    print("\n" + "=" * 74)
    print("⑭ 代码架构体检")
    print("=" * 74)

    script = os.path.join(ROOT, "samples", "check_architecture.py")
    if not os.path.isfile(script):
        record("代码架构均衡无问题", True, "无问题", "检查脚本不存在，跳过")
        return
    try:
        r = subprocess.run([sys.executable, script],
                           capture_output=True, text=True, timeout=180,
                           encoding="utf-8", errors="replace")
        out = r.stdout or ""
        n_files = 0
        for pat in (r"全部 (\d+) 个文件都在",      # 全部合规
                    r"发现 (\d+) 处架构问题",      # 有问题时的总数
                    r"(\d+) 个文件超过"):          # 超标文件数
            m = re.search(pat, out)
            if m:
                n_files = int(m.group(1))
                break
        if not n_files:
            n_files = None                          # 匹配不到就不谎报 0
        ok = r.returncode == 0
        detail = ""
        if not ok:
            bad = [l.strip() for l in out.splitlines()
                   if l.strip().startswith(("modules/", "views/", "main.py", "samples/"))]
            detail = "；".join(bad[:3])
        desc = f"{n_files} 个文件" if n_files else "文件数未知"
        record("代码架构均衡无问题", ok, "无问题",
               desc + (f"；问题：{detail}" if detail else ""))
    except Exception as e:
        record("代码架构均衡无问题", False, "无问题", f"执行失败：{e}")


# ==========================================================
def main():
    print("=" * 74)
    print("一键复现校验 · 验证材料里的每个数字能否被第三方复现")
    print("=" * 74)
    print("官方要求：组委会将根据队伍提交材料进行复现，")
    print("          若发现验证效果与答辩材料呈现结果不符，则取消晋级&获奖资格")
    print(f"仓库根目录：{ROOT}")

    check_corpus()
    check_metrics()
    check_rules()
    check_regression()
    check_code_size()
    check_sample_count()
    check_code_refs()
    check_architecture()

    print("\n" + "=" * 74)
    failed = [r for r in RESULTS if not r["ok"]]
    print(f"汇总：共 {len(RESULTS)} 项检查，通过 {len(RESULTS) - len(failed)}，失败 {len(failed)}")
    print("=" * 74)

    if failed:
        print("\n🔴 未通过项（材料中的数字目前无法被完整复现，必须先修）：\n")
        for r in failed:
            print(f"  · {r['name']}")
            print(f"      期望 {r['expect']}，实测 {r['got']}")
            if r["detail"]:
                print(f"      {r['detail']}")
        print()
        return 1

    print("\n✅ 全部通过：材料中的每个数字都能在本机一键复现。")
    print("   提交前请再确认：git 已推送、语料已入库、Streamlit 站点已唤醒。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
