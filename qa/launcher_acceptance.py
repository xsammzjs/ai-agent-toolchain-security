# -*- coding: utf-8 -*-
"""启动方式验收工具箱（QA 工具，非产品代码）

为「快速运行.bat / start.py」这套启动方式提供**可复现**的验收手段。
每个用例对应《启动方式验收清单》里的一条勾选项，改完代码跑一遍就知道过没过。

    python qa/launcher_acceptance.py [--list|--only C2|--slow|--json]
    （不带参数 = 跑常规用例；--slow 加跑慢速用例；--only 只跑指定编号）

模块划分（每个文件 ≤300 行）：本文件是入口；`_harness.py` 测试框架；
`_portkit.py` 端口与进程工具；`cases_a/b/c/g/h/x.py` 按用例组分。
各模块末尾有自己那份 CASES 注册表，入口按（字母组, 序号）拼起来排序，
保证输出顺序与拆分前逐项一致。
⚠️ 踩坑提醒（都实测踩过，细节见《启动方式验收清单》第 0 节）：
本机回环请求会走 http_proxy 需清空代理；netstat 输出是 GBK；
Streamlit 冷启动 10-30 秒所以一律轮询等待而非固定 sleep；
等子进程输出不能用阻塞 readline；端口匹配要精确（":8765 " 不能写成 ":8765"）；
哑巴占用进程必须保证清理。
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import List, Optional, Tuple

# 让 `python qa/launcher_acceptance.py` 能 import 到同目录的内部模块
# （脚本运行时 sys.path[0] 已是 qa/，这里再兜一层，保证被当模块导入也能用）
_QA_DIR = Path(__file__).resolve().parent
if str(_QA_DIR) not in sys.path:
    sys.path.insert(0, str(_QA_DIR))

import cases_a                                                    # noqa: E402
import cases_b                                                    # noqa: E402
import cases_c                                                    # noqa: E402
import cases_g                                                    # noqa: E402
import cases_h                                                    # noqa: E402
import cases_x                                                    # noqa: E402
from _harness import Result                                       # noqa: E402

Case = Tuple[str, str, object, bool]


def _sort_key(case: Case) -> Tuple[str, int]:
    """按 (字母组, 序号) 排序。

    各模块的 CASES 是分散的，拼接后顺序会和拆分前不一样
    （比如 G7 在 cases_c.py 里，会排到 G1 前面）。
    这里统一按「字母组 + 序号」排 —— 与拆分前的顺序**逐项一致**，
    保证对外输出完全不变。
    """
    cid = case[0]
    return cid[0], int(cid[1:])


# 常规用例（默认跑）—— 各模块的 CASES 列表见 cases_*.py 末尾
CASES: List[Case] = sorted(
    cases_a.CASES + cases_b.CASES + cases_c.CASES
    + cases_g.CASES + cases_x.CASES,
    key=_sort_key,
)

# 慢速用例：需要联网装依赖，默认不跑（用 --slow 或 --only H1 触发）
SLOW_CASES: List[Case] = cases_h.CASES

# 候选池**始终**包含慢速用例 —— 否则 `--only H1` 会找不到（--list 里承诺过能用）。
ALL_CASES: List[Case] = CASES + SLOW_CASES


def select_cases(args: argparse.Namespace) -> Optional[List[Case]]:
    """按命令行参数挑用例；返回 None 表示没匹配到。"""
    if args.only:
        keys = {k.upper() for k in args.only}
        picked = [c for c in ALL_CASES if c[0].upper() in keys]
        return picked or None
    # 不指定 --only 时才按 --slow 决定要不要跑慢速的
    return ALL_CASES if args.slow else CASES


def main(argv: Optional[List[str]] = None) -> int:
    # 输出重定向到文件时必须实时刷新，否则中途被 kill 会一个字都看不到
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(line_buffering=True)      # type: ignore[union-attr]
        except (AttributeError, OSError, ValueError):
            pass

    parser = argparse.ArgumentParser(description="启动方式验收工具箱")
    parser.add_argument("--list", action="store_true", help="只列用例清单")
    parser.add_argument("--only", nargs="*", help="只跑指定编号，如 A1 C2")
    parser.add_argument("--slow", action="store_true",
                        help="额外跑慢速用例（需联网装依赖，耗时数分钟）")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    args = parser.parse_args(argv)

    if args.list:
        print("验收用例清单：")
        for cid, name, _fn, _safe in CASES:
            print(f"  {cid:4s} {name}")
        print("慢速用例（需 --slow 或 --only H1）：")
        for cid, name, _fn, _safe in SLOW_CASES:
            print(f"  {cid:4s} {name}")
        return 0

    selected = select_cases(args)
    if selected is None:
        print(f"没有匹配的用例：{args.only}")
        return 2

    results: List[Result] = []
    for cid, name, fn, _safe in selected:
        res = Result(cid, name)
        t0 = time.time()
        try:
            fn(res)                                          # type: ignore[operator]
        except Exception as exc:                  # noqa: BLE001
            res.check(False, f"用例执行异常：{type(exc).__name__}: {exc}")
        res.evidence.append(f"[TIME] {time.time() - t0:.1f}s")
        results.append(res)

    if args.json:
        print(json.dumps(
            [{"id": r.cid, "name": r.name, "passed": r.passed,
              "skipped": r.skipped, "skip_reason": r.skip_reason,
              "evidence": r.evidence} for r in results],
            ensure_ascii=False, indent=2))
        return 0 if all(r.passed for r in results) else 1

    print("=" * 72)
    print("启动方式验收结果")
    print("=" * 72)
    for r in results:
        if r.skipped:
            flag = "⏭ 跳过"
        elif r.passed:
            flag = "✅ 通过"
        else:
            flag = "❌ 失败"
        print(f"\n[{r.cid}] {r.name}  —— {flag}")
        for line in r.evidence:
            print(f"    {line}")
    passed = sum(1 for r in results if r.passed)
    skipped = sum(1 for r in results if r.skipped)
    print("\n" + "=" * 72)
    tail = f"，跳过 {skipped}" if skipped else ""
    print(f"合计：通过 {passed} / {len(results)}{tail}")
    print("=" * 72)
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
