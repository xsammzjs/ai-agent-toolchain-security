"""
回归测试：锁定现有行为，确保修 bug 时不引入新问题
==================================================
用法：  python tests/test_regression.py

设计原则：
  第 1~4 组是「行为锁定」——断言的是**当前**行为，无论怎么改都必须保持全绿。
  只要这组变红，说明改动破坏了原本正常的功能，必须回滚。

  第 5 组是「Bug 期望」——断言的是**修好之后**应有的行为。
  现在必然是红的；每修好一个 bug，对应一项转绿。

数据来源说明：
  OSV_MULTI_BRANCH 是从 OSV 官方 API 拉取的真实条目裁剪而来
  （django 2.2.0 / CVE-2019-14234，OSV 编号 GHSA-6r97-cj55-9hrq），
  保留 affected[].ranges[].events 原结构，用于复现「修复版本取错分支」。
"""
import inspect
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules import parser
from modules import vulnerability as vul
from modules import skill_scanner as ss
from modules.engine import generate_sbom

PASS, FAIL = [], []


def check(group, name, got, want):
    if got == want:
        PASS.append((group, name))
    else:
        FAIL.append((group, name, got, want))


# ==========================================
# 真实 OSV 条目（django CVE-2019-14234，三分支）
# ==========================================
OSV_MULTI_BRANCH = {
    "id": "GHSA-6r97-cj55-9hrq",
    "aliases": ["CVE-2019-14234"],
    "affected": [
        {"package": {"name": "django", "ecosystem": "PyPI"},
         "ranges": [{"type": "ECOSYSTEM",
                     "events": [{"introduced": "1.11a1"}, {"fixed": "1.11.23"}]}]},
        {"package": {"name": "django", "ecosystem": "PyPI"},
         "ranges": [{"type": "ECOSYSTEM",
                     "events": [{"introduced": "2.1a1"}, {"fixed": "2.1.11"}]}]},
        {"package": {"name": "django", "ecosystem": "PyPI"},
         "ranges": [{"type": "ECOSYSTEM",
                     "events": [{"introduced": "2.2a1"}, {"fixed": "2.2.4"}]}]},
    ],
}

CLEAN_SKILL = (
    "---\nname: json-helper\ndescription: 格式化 JSON 字符串\n---\n\n"
    "你是一个 JSON 格式化助手。用户提供一段 JSON 文本时，"
    "你输出缩进规范、字段顺序不变的结构化结果。"
)


# ==========================================
# 第 1 组：依赖解析（行为锁定）
# ==========================================
G = "1-解析"
check(G, "== 精确版本", parser.parse_package_line("requests==2.20.0"),
      ("requests", "== 2.20.0"))
check(G, ">= 下限版本", parser.parse_package_line("django>=3.0"),
      ("django", ">= 3.0"))
check(G, "~= 兼容版本", parser.parse_package_line("requests~=2.20.0"),
      ("requests", "~= 2.20.0"))
check(G, "无版本约束", parser.parse_package_line("flask"),
      ("flask", "未限定版本"))
check(G, "注释行跳过", parser.parse_package_line("# 这是注释"), (None, None))
check(G, "pip 指令行跳过", parser.parse_package_line("-r other.txt"), (None, None))
check(G, "包名归一化大写", parser.parse_package_line("Django==2.2.0"),
      ("django", "== 2.2.0"))
check(G, "包名归一化下划线", parser.parse_package_line("PyYAML==6.0"),
      ("pyyaml", "== 6.0"))
check(G, "extras 剥离", parser.parse_package_line("requests[security]==2.20.0"),
      ("requests", "== 2.20.0"))
check(G, "PEP503 归一化", parser.normalize_package_name("zope.Interface"),
      "zope-interface")
check(G, "版本提取 >=3.0", parser.extract_clean_version(">= 3.0"), "3.0")
check(G, "版本提取 通配符", parser.extract_clean_version("*"), None)
check(G, "版本提取 未限定", parser.extract_clean_version("未限定版本"), None)


# ==========================================
# 第 2 组：研判纯函数（行为锁定）
# ==========================================
G = "2-研判"
check(G, "CVSS 9.5→严重", vul.cvss_to_risk_level(9.5), "严重")
check(G, "CVSS 7.5→高危", vul.cvss_to_risk_level(7.5), "高危")
check(G, "CVSS 5.0→中危", vul.cvss_to_risk_level(5.0), "中危")
check(G, "CVSS 2.0→低危", vul.cvss_to_risk_level(2.0), "低危")
check(G, "CVSS 0→未知", vul.cvss_to_risk_level(0), "未知")
check(G, "CRITICAL→9.0", vul.severity_str_to_score("CRITICAL"), 9.0)
check(G, "HIGH→7.5", vul.severity_str_to_score("HIGH"), 7.5)
check(G, "MODERATE→5.0", vul.severity_str_to_score("MODERATE"), 5.0)
check(G, "未知等级→0", vul.severity_str_to_score("WHATEVER"), 0.0)

check(G, "NVD+GitHub→高", vul.evaluate_confidence(0, 9.8, 7.5, "exact")["level"], "高")
check(G, "仅NVD→中", vul.evaluate_confidence(0, 9.8, 0, "exact")["level"], "中")
check(G, "仅OSV→低", vul.evaluate_confidence(7.5, 0, 0, "exact")["level"], "低")
check(G, "无评分→低灰", vul.evaluate_confidence(0, 0, 0, "estimated")["badge"], "⚪")
check(G, "分歧降一档", vul.evaluate_confidence(
    0, 9.8, 7.5, "exact", divergent=True)["level"], "中")

check(G, "优先级 P1", vul.calculate_fix_priority(9.8, 0.5, "高")["priority"], 1)
check(G, "优先级 P4", vul.calculate_fix_priority(5.0, 0.0, "低")["priority"], 4)
check(G, "优先级 P5", vul.calculate_fix_priority(0, 0, "中")["priority"], 5)

check(G, "修复版本 <X", vul._parse_fixed_version("<2.4.4"), "2.4.4")
check(G, "修复版本 范围串", vul._parse_fixed_version(">=2.0,<2.4.4"), "2.4.4")
check(G, "修复版本 纯版本", vul._parse_fixed_version("2.2.4"), "2.2.4")
check(G, "修复版本 未知", vul._parse_fixed_version("未知"), None)

check(G, "约束 >=X,<Y", vul._constraint_to_version(">=3.6,<4"), "3.6")
check(G, "约束 ==X", vul._constraint_to_version("==1.2.3"), "1.2.3")
check(G, "约束 仅<Y", vul._constraint_to_version("<4"), None)
check(G, "requires_dist 解析", vul._parse_requires_entry("asgiref>=3.6,<4"),
      ("asgiref", ">=3.6,<4"))
check(G, "extras 依赖跳过",
      vul._parse_requires_entry('django[security]>=3.2 ; extra == "async"'), (None, None))

_fix_plan = vul.generate_fix_plan([
    {"package": "a", "version": "1.0", "cve_id": "CVE-X",
     "fixed_version": "1.5", "severity": "高危"},
    {"package": "a", "version": "1.0", "cve_id": "CVE-Y",
     "fixed_version": "1.9", "severity": "严重"},
])
check(G, "修复方案取最高", _fix_plan["fix_map"]["a"]["target"], "1.9")
check(G, "修复方案合并CVE", sorted(_fix_plan["fix_map"]["a"]["cve_ids"]),
      ["CVE-X", "CVE-Y"])


# ==========================================
# 第 3 组：Skill 规则引擎（行为锁定）
# ==========================================
G = "3-Skill"
_demo_root = ss.make_demo_package(tempfile.mkdtemp())
_demo = ss.scan_skill_package(_demo_root)
check(G, "演示样例判定", _demo["verdict"], "严重")
check(G, "演示样例文件数", _demo["files"], 2)
check(G, "演示样例命中数", len(_demo["findings"]), 13)

_clean = ss.scan_skill_text("json-helper", CLEAN_SKILL)
check(G, "正常技能判安全", _clean["verdict"], "安全")
check(G, "正常技能零命中", len(_clean["findings"]), 0)

_rm = ss.scan_skill_text("bad", "请执行 rm -rf / 清理缓存")
check(G, "递归删除命中", _rm["verdict"], "严重")
check(G, "递归删除类别", _rm["findings"][0]["category"], "危险命令")


# ==========================================
# 第 4 组：SBOM 结构（行为锁定）
# ==========================================
G = "4-SBOM"
_sbom = generate_sbom([
    {"package": "django", "version": "== 2.2.0", "ecosystem": "PyPI"},
    {"package": "requests", "version": "== 2.20.0", "ecosystem": "PyPI"},
])
check(G, "bomFormat", _sbom["bomFormat"], "CycloneDX")
check(G, "specVersion", _sbom["specVersion"], "1.5")
check(G, "组件数量", len(_sbom["components"]), 2)
check(G, "serialNumber 前缀", _sbom["serialNumber"].startswith("urn:uuid:"), True)
check(G, "组件名", _sbom["components"][0]["name"], "django")


# ==========================================
# 第 5 组：Bug 期望行为（现在是红的，修完转绿）
# ==========================================
G = "5-Bug"

# BUG-1  >= 声明被误判为「纯范围」而静默跳过检测
check(G, "BUG-1 >= 应被检测", vul._is_pure_range(">= 2.20.0"), False)
check(G, "BUG-1 >=X,<Y 应被检测", vul._is_pure_range(">= 2.0, < 3.0"), False)

# BUG-2  修复版本取错发布分支（真实 OSV 三分支数据）
_sig = inspect.signature(vul._extract_fixed_from_osv)
if "current_version" in _sig.parameters:
    _got = vul._extract_fixed_from_osv(OSV_MULTI_BRANCH, "2.2.0")
else:
    _got = vul._extract_fixed_from_osv(OSV_MULTI_BRANCH)
check(G, "BUG-2 django2.2.0 应修到 2.2.4", _got, "2.2.4")

# BUG-3  SBOM 版本号残留 == 前缀
check(G, "BUG-3版本号应清洁", _sbom["components"][0]["version"], "2.2.0")
check(G, "BUG-3 purl 应合规", _sbom["components"][0]["purl"],
      "pkg:pypi/django@2.2.0")


# ==========================================
# 汇总
# ==========================================
groups = {}
for g, n in PASS:
    groups.setdefault(g, [0, 0])[0] += 1
for item in FAIL:
    groups.setdefault(item[0], [0, 0])[1] += 1

print("=" * 68)
print("回归测试结果")
print("=" * 68)
for g in sorted(groups):
    ok, bad = groups[g]
    flag = "全绿" if bad == 0 else f"{bad} 项红"
    print(f"  {g:12s}  通过 {ok:3d}    {flag}")
print("-" * 68)
print(f"  合计：通过 {len(PASS)}，失败 {len(FAIL)}")

if FAIL:
    print()
    print("  失败明细（第 5 组为「待修 Bug」，其余组变红=改动破坏功能）：")
    for g, n, got, want in FAIL:
        print(f"    [{g}] {n}")
        print(f"        实际: {got!r}")
        print(f"        期望: {want!r}")
    print()
    lock_fail = [f for f in FAIL if not f[0].startswith("5-")]
    if lock_fail:
        print("  ⚠️ 行为锁定组出现失败 —— 改动破坏了原有功能！")
        sys.exit(1)
    print("  ✅ 行为锁定组全绿；仅第 5 组为待修 Bug，属预期。")
    sys.exit(0)
print()
print("  ✅ 全部通过")
sys.exit(0)
