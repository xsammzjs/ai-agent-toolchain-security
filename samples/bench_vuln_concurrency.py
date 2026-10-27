# -*- coding: utf-8 -*-
"""依赖漏洞四源查询：串行 vs 并发 加速比基准（可复现）

==============================================================
【这个脚本解决什么问题】

对外材料里有一处性能数字「串行 8.0 s → 并发 1.4 s，加速比 5.75×」
（依赖漏洞四源查询 OSV / NVD / GitHub Advisory / EPSS，8 个依赖）。
问题是：这个数字**原先只存在于代码注释里，没有任何脚本可以复现它**，
而作品报告附录 B 结尾写着「本报告所有数字均可在上述文件中找到」。

本脚本就是那个「可被找到的文件」——它按材料里描述的方式实测一遍，
把结果写进 `samples/public_bench/_concurrency_bench.json`。

【测的是什么】

同一批依赖，分别用两个入口跑同一个漏洞检测逻辑：

  · 串行：`modules/vuln/detect.py: detect_vulnerabilities()`
  · 并发：`modules/vuln/detect.py: detect_vulnerabilities_concurrent()`

两者的单依赖内部逻辑完全相同（并发入口就是逐个调串行函数），
所以**并发只改变速度，不改变结论**——脚本会同时断言两边的
漏洞集合完全一致，不一致就报错退出。

【为什么要清缓存】

`modules/vuln/common.py` 里有一层 `_api_cache`（四源查询结果缓存，
TTL 1 小时）。不清缓存的话第二次跑直接命中缓存，测出来是「读缓存」的速度，
不是「查四个漏洞库」的速度，数字会失真。

【实测前提：需要外网】

本基准查询的是**真实**的 OSV / NVD / GitHub Advisory / EPSS 四个公开 API，
因此**必须能联网**。断网环境下跑本脚本会得到一堆超时，
加速比会明显偏低——这是网络状况问题，不是代码问题。
离线环境请不要引用本脚本产出的数字。

【用法】

    .venv/Scripts/python.exe samples/bench_vuln_concurrency.py

【产出】

    samples/public_bench/_concurrency_bench.json
      {
        "n_deps": 8,
        "serial_seconds": ...,
        "concurrent_seconds": ...,
        "speedup": ...,
        "vulns_identical": true,
        "n_vulns": ...,
        "caveat": "..."
      }
"""
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from modules.vuln import common as vcommon
from modules.vuln import detect as vdetect

OUT = os.path.join(ROOT, "samples", "public_bench", "_concurrency_bench.json")

# 被测依赖：8 个常见的、有真实漏洞记录的 PyPI 包。
# 固定写死（不读随机文件）是为了让每次实测的输入完全一致，可比。
#
# 【version 字段的格式说明】必须带 `==` 前缀，这是 modules/vuln/version.py
# 的 `_is_pure_range()` 判定规则：没有下界运算符（== / ~= / >= / >）的版本串
# 会被判为「纯范围约束」直接跳过——那 8 个依赖就一个都不会查，
# 测出来会是 0.00 s / 0 条的假数据（我第一次写就踩了这个坑）。
DEPS = [
    {"package": "requests", "version": "== 2.19.1", "ecosystem": "PyPI"},
    {"package": "urllib3", "version": "== 1.24.1", "ecosystem": "PyPI"},
    {"package": "jinja2", "version": "== 2.10", "ecosystem": "PyPI"},
    {"package": "pyyaml", "version": "== 5.1", "ecosystem": "PyPI"},
    {"package": "django", "version": "== 2.2.0", "ecosystem": "PyPI"},
    {"package": "flask", "version": "== 1.0", "ecosystem": "PyPI"},
    {"package": "pillow", "version": "== 5.4.1", "ecosystem": "PyPI"},
    {"package": "cryptography", "version": "== 2.3", "ecosystem": "PyPI"},
]


def clear_api_cache() -> None:
    """清空四源查询缓存——否则第二次跑测的是读缓存，不是查库。"""
    with vcommon._api_cache_lock:
        vcommon._api_cache.clear()


def _vuln_key_set(vulns: list) -> set:
    """把漏洞列表归一成可比对的集合（忽略浮点耗时等非确定性字段）。"""
    keys = set()
    for v in vulns or []:
        keys.add((
            str(v.get("package", "")),
            str(v.get("version", "")),
            str(v.get("id", "") or v.get("cve_id", "")),
            str(v.get("source", "")),
        ))
    return keys


def main() -> int:
    print("=" * 68)
    print("依赖漏洞四源查询 · 串行 vs 并发 加速比基准")
    print("=" *  68)
    print(f"依赖数：{len(DEPS)}")
    print(f"查询源：OSV / NVD / GitHub Advisory / EPSS（真实网络请求）")
    print()

    # ---------- 串行 ----------
    clear_api_cache()
    print("[1/2] 串行扫描中（清空 API 缓存，真实网络请求）…")
    t0 = time.time()
    serial_vulns = vdetect.detect_vulnerabilities(DEPS, None,
                                                  use_nvd=True, do_epss=True)
    serial_seconds = time.time() - t0
    print(f"      耗时 {serial_seconds:.2f} s，检出 {len(serial_vulns)} 条")

    # ---------- 并发 ----------
    clear_api_cache()
    print("[2/2] 并发扫描中（同样清空 API 缓存，真实网络请求）…")
    t0 = time.time()
    concurrent_vulns = vdetect.detect_vulnerabilities_concurrent(
        DEPS, None, use_nvd=True, do_epss=True, max_workers=8)
    concurrent_seconds = time.time() - t0
    print(f"      耗时 {concurrent_seconds:.2f} s，检出 {len(concurrent_vulns)} 条")

    # ---------- 结论一致性（并发只改速度不改结论）----------
    s_set, c_set = _vuln_key_set(serial_vulns), _vuln_key_set(concurrent_vulns)
    identical = s_set == c_set
    speedup = (serial_seconds / concurrent_seconds) if concurrent_seconds > 0 else 0.0

    print()
    print(f"加速比：{serial_seconds:.2f} / {concurrent_seconds:.2f} = {speedup:.2f}×")
    print(f"漏洞集合一致：{'是 ✅' if identical else '否 ❌'}")
    if not identical:
        print(f"  仅串行有：{sorted(s_set - c_set)[:5]}")
        print(f"  仅并发有：{sorted(c_set - s_set)[:5]}")

    out = {
        "source": "本仓库自测：modules/vuln/detect.py 的串行/并发两个入口",
        "n_deps": len(DEPS),
        "deps": DEPS,
        "serial_seconds": round(serial_seconds, 2),
        "concurrent_seconds": round(concurrent_seconds, 2),
        "speedup": round(speedup, 2),
        "vulns_identical": identical,
        "n_vulns_serial": len(serial_vulns),
        "n_vulns_concurrent": len(concurrent_vulns),
        "caveat": "本基准查询真实 OSV/NVD/GitHub/EPSS 四个公开 API，必须联网；"
                  "耗时受网络状况影响，离线环境不可复现，也不应引用。"
                  "并发只改变速度，不改变结论——脚本会断言两边漏洞集合完全一致。",
    }

    # ---- 累积历次运行记录：加速比随网络状况浮动，单点值说明不了问题 ----
    # 追加而不是覆盖，这样「4.45~4.63×」这个区间在文件里是**可核验的**——
    # 区间两端就是 runs 里真实跑出来的两条记录。
    runs = []
    if os.path.isfile(OUT):
        try:
            with open(OUT, encoding="utf-8") as f:
                prev = json.load(f)
            if isinstance(prev.get("runs"), list):
                runs = prev["runs"]
        except (OSError, ValueError):
            runs = []
    runs.append({
        "serial_seconds": round(serial_seconds, 2),
        "concurrent_seconds": round(concurrent_seconds, 2),
        "speedup": round(speedup, 2),
        "n_vulns": len(concurrent_vulns),
        "vulns_identical": identical,
    })
    out["runs"] = runs
    if len(runs) > 1:
        sp = sorted(r["speedup"] for r in runs)
        out["speedup_range"] = f"{sp[0]:.2f}~{sp[-1]:.2f}"
        out["speedup_range_note"] = (
            f"{len(runs)} 次实测的加速比区间；单点值随网络状况浮动，"
            "材料里写区间而非单点值。")

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print()
    print(f"结果已写入：{os.path.relpath(OUT, ROOT)}")
    if len(runs) > 1:
        print(f"累计 {len(runs)} 次实测，加速比区间：{out['speedup_range']}")

    if not identical:
        print()
        print("❌ 串行与并发的漏洞集合不一致——并发实现有问题，不应继续引用本基准")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
