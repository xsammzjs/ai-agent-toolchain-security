"""
真实 GitHub 项目重测：验证 >= 漏检 bug 修复前后的检出差异
==========================================================
背景：项目 docs 里声称「本工具比 pip-audit 多检出 6 条」，但真实项目对比
（run_compare_log.txt）显示本工具 112 vs pip-audit 200，差距很大。
原因已定位为 _is_pure_range 把 >= 声明静默跳过。

本脚本对同一批真实项目分别用「修复前逻辑」和「修复后逻辑」各扫一遍，
直接量化修复效果。

说明：
- 漏洞条目全部来自 OSV（NVD/GitHub 只做富化，不新增条目），因此关闭
  NVD/EPSS 不影响检出条数，但能把耗时从小时级压到分钟级
- 两次扫描在同一进程内跑，OSV 查询走内存缓存，第二遍几乎不耗时
"""
import io
import os
import sys
import json
import time
from datetime import datetime

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules import parser, vulnerability as vul

REAL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "vuln_reqs", "real_projects")

# 修复前的原始判定逻辑
def old_is_pure_range(ver_str: str) -> bool:
    if not ver_str:
        return False
    has_range = any(op in ver_str for op in [">", "<"])
    has_exact = "==" in ver_str
    return has_range and not has_exact


# 真实网络请求之间加间隔，避免触发 OSV 限流导致静默失败
_ORIG_QUERY_OSV = vul.query_osv
_DELAY = {"on": True}


def _throttled_query_osv(pkg, ver, eco="PyPI"):
    if _DELAY["on"]:
        time.sleep(0.2)
    return _ORIG_QUERY_OSV(pkg, ver, eco)


vul.query_osv = _throttled_query_osv


def run_scan(file_path: str, use_old_logic: bool) -> dict:
    """扫描单个项目，返回 (漏洞条数, 参与检测的依赖数, 被跳过的依赖数)"""
    original = vul._is_pure_range
    if use_old_logic:
        vul._is_pure_range = old_is_pure_range
    try:
        deps = parser.parse_requirements(file_path)
        deps = {(d["package"], d["version"]): d for d in deps}
        dep_list = list(deps.values())
        stats: dict = {}
        # 只查 OSV：漏洞条目来源唯一，NVD/GitHub 仅做富化，不影响条数
        found = vul.detect_vulnerabilities(
            dep_list, parser, use_nvd=False, do_epss=False,
            progress_cb=None, stats=stats,
        )
        return {
            "deps": len(dep_list),
            "scanned": stats.get("scanned_count", len(dep_list)),
            "skipped": stats.get("skipped_count", 0),
            "vulns": len(found),
            "cves": len({v["cve_id"] for v in found}),
            "query_errors": stats.get("query_errors", {}),
        }
    finally:
        vul._is_pure_range = original


def main():
    files = sorted(
        f for f in os.listdir(REAL_DIR)
        if f.startswith("req_") and f.endswith(".txt") and not f.endswith("_raw.txt")
    )
    print("=" * 78)
    print("真实 GitHub 项目重测：>= 漏检修复前后对比")
    print("=" * 78)
    print(f"项目数: {len(files)}   开始时间: {datetime.now():%H:%M:%S}")
    print()

    results = []
    t0 = time.time()
    for idx, fname in enumerate(files, 1):
        path = os.path.join(REAL_DIR, fname)
        name = fname[4:-4]
        try:
            before = run_scan(path, use_old_logic=True)
            after = run_scan(path, use_old_logic=False)
        except Exception as e:
            print(f"  [{idx}/{len(files)}] {name:20s} 失败: {type(e).__name__}: {e}"[:100])
            continue
        results.append({"project": name, "before": before, "after": after})
        errs = after.get("query_errors", {})
        err_note = ""
        if errs:
            err_note = "  ⚠️查询失败:" + ",".join(f"{k}{v}" for k, v in errs.items())
        print(f"  [{idx}/{len(files)}] {name:20s} "
              f"依赖{before['deps']:3d}  修复前 {before['vulns']:4d} 条 "
              f"→ 修复后 {after['vulns']:4d} 条  "
              f"(+{after['vulns'] - before['vulns']}){err_note}")
        sys.stdout.flush()

    print()
    print("=" * 78)
    tb = sum(r["before"]["vulns"] for r in results)
    ta = sum(r["after"]["vulns"] for r in results)
    sb = sum(r["before"]["skipped"] for r in results)
    sa = sum(r["after"]["skipped"] for r in results)
    print("汇总（%d 个真实项目，耗时 %.0fs）" % (len(results), time.time() - t0))
    print("-" * 78)
    print("  修复前检出: %d 条   （跳过依赖 %d 个）" % (tb, sb))
    print("  修复后检出: %d 条   （跳过依赖 %d 个）" % (ta, sa))
    print("  净增:       %d 条   （+%.1f%%）" % (ta - tb, (ta - tb) / max(tb, 1) * 100))
    print("=" * 78)

    out = {
        "generated_at": datetime.now().isoformat(),
        "projects": results,
        "total_before": tb, "total_after": ta,
        "skipped_before": sb, "skipped_after": sa,
    }
    out_path = os.path.join(REAL_DIR, "benchmark_fixed_results.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print()
    print("结果已保存:", out_path)


if __name__ == "__main__":
    main()
