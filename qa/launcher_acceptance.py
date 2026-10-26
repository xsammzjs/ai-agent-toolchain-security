# -*- coding: utf-8 -*-
"""启动方式验收工具箱（QA 工具，非产品代码）

=====================================================
用途
=====================================================
为「快速运行.bat / start.py」这套启动方式提供**可复现**的验收手段。
每个函数对应《启动方式验收清单》里的一条勾选项，工程师改完可直接跑：

    python qa/launcher_acceptance.py            # 跑全部（不含慢速用例）
    python qa/launcher_acceptance.py --list     # 只列用例清单
    python qa/launcher_acceptance.py --only A3  # 只跑指定编号
    python qa/launcher_acceptance.py --slow     # 加跑慢速用例（联网装依赖）
    python qa/launcher_acceptance.py --json     # 输出 JSON

=====================================================
模块划分
=====================================================
    launcher_acceptance.py   本文件 —— 入口：注册表 + 参数解析 + 输出
    _harness.py              测试框架：Result / netstat / 轮询等待 / Launcher
    _portkit.py              端口与进程工具：测试端口加锁 / 哑巴占用者
    cases_a.py               A 编码 / B 依赖
    cases_b.py               C 端口 / D 浏览器
    cases_c.py               E 停止 / F 视图与 health
    cases_g.py               G bat↔start.py 交接
    cases_h.py               H 首次运行（慢速）
    cases_x.py               X 验收脚本自身的自检

=====================================================
重要约束（实测踩过的坑，别重复踩）
=====================================================
1. 本机设了 http_proxy / https_proxy 环境变量，**本机回环请求会走代理**，
   直接 curl http://127.0.0.1:8501 会超时。必须加 --noproxy '*'
   或用 urllib 的 ProxyHandler({}) 清空代理。
2. TaskStop 只杀 shell，不杀它派生的 python 子进程 —— 收尾要用
   netstat 找 PID 再 taskkill。
3. Streamlit 的 _bind_socket 总是设 SO_REUSEADDR，Windows 上会让
   「后启动者抢占已占用端口」。所以**探测端口是否空闲不能只靠 bind**。
4. netstat 输出是 GBK 编码，用 subprocess 捕获时必须 decode("gbk")。
5. **Streamlit 冷启动要 10-30 秒**。所有「等服务起来」的断言必须用
   **轮询 + 超时**，不能用固定 sleep —— 否则会在服务还没起来时就判 FAIL
   （这是测试方法 Bug，不是产品缺陷）。
6. 等子进程输出**不能**用阻塞的 stdout.readline() —— 没有新输出时它会
   一直卡住，导致超时检查根本执行不到，整个脚本挂死。必须后台线程读。
7. 端口匹配要精确：":8765" 会把 ":87650" 也算进来，必须用 ":8765 "。
8. 哑巴占用进程必须保证清理 —— 漏 kill 会让端口一直被占，下次跑连环失败。
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Callable, List, Optional, Tuple

# 让 `python qa/launcher_acceptance.py` 能 import 到同目录的内部模块
# （脚本运行时 sys.path[0] 已是 qa/，这里再兜一层，保证被当模块导入也能用）
_QA_DIR = Path(__file__).resolve().parent
if str(_QA_DIR) not in sys.path:
    sys.path.insert(0, str(_QA_DIR))

from _harness import Result                                    # noqa: E402
from cases_a import (                                          # noqa: E402
    case_a1_bat_encoding,
    case_a2_bat_cmd_parse,
    case_a3_bat_codepage,
    case_b1_bat_dep_check,
    case_b2_no_reinstall,
)
from cases_b import (                                          # noqa: E402
    case_c1_port_conflict_behavior,
    case_c2_actual_port_matches,
    case_c3_wildcard_occupant,
    case_d1_open_browser,
)
from cases_c import (                                          # noqa: E402
    case_g7_signal_exit_port_released,
    case_e1_stop_method,
    case_e2_ctrl_c_no_orphan,
    case_f1_four_views,
    case_f2_health_endpoint,
)
from cases_g import (                                          # noqa: E402
    case_g1_bat_delegates,
    case_g2_no_browser_in_check,
    case_g3_bat_exit_code,
    case_g4_bat_ask_port,
    case_g5_ask_port_prompt,
    case_g6_cancel_exit_code,
)
from cases_h import case_h1_no_venv_first_run                   # noqa: E402
from cases_x import (                                          # noqa: E402
    case_x1_port_match_precision,
    case_x2_holder_failure_detected,
    case_x3_holder_cleanup,
)


# ==========================================================
# 注册表
# ==========================================================
CASES: List[Tuple[str, str, Callable[[Result], None], bool]] = [
    ("A1", "bat 编码：无 BOM + CRLF", case_a1_bat_encoding, True),
    ("A2", "bat 能被 cmd.exe 正常解析", case_a2_bat_cmd_parse, True),
    ("A3", "bat 有 chcp 65001（中文不乱码）", case_a3_bat_codepage, True),
    ("B1", "bat 依赖检查覆盖全部必需包", case_b1_bat_dep_check, True),
    ("B2", "依赖齐全时不重复安装", case_b2_no_reinstall, True),
    ("C1", "端口占用时探测准确且不崩", case_c1_port_conflict_behavior, True),
    ("C2", "实际端口 == 提示地址（避让后不串号）", case_c2_actual_port_matches, True),
    ("C3", "占用者绑 0.0.0.0 时也能识别（防重复实例）", case_c3_wildcard_occupant, True),
    ("D1", "自动开浏览器且 URL 与实际端口一致", case_d1_open_browser, True),
    ("E1", "停止方式明确告知", case_e1_stop_method, True),
    ("E2", "Ctrl+C 后端口释放、无孤儿进程", case_e2_ctrl_c_no_orphan, True),
    ("F1", "四个视图都能执行（AppTest）", case_f1_four_views, True),
    ("F2", "health 接口返回 200 ok", case_f2_health_endpoint, True),
    ("G1", "bat 委托 start.py（单一逻辑源）", case_g1_bat_delegates, True),
    ("G2", "--check 不开浏览器", case_g2_no_browser_in_check, True),
    ("G3", "bat 正确传递 start.py 退出码", case_g3_bat_exit_code, True),
    ("G4", "start.py 接受 bat 传的 --ask-port", case_g4_bat_ask_port, True),
    ("G5", "交互提示端口号跟随实际起始端口", case_g5_ask_port_prompt, True),
    ("G6", "用户取消时退出码非 0", case_g6_cancel_exit_code, True),
    ("G7", "信号退出后端口被释放", case_g7_signal_exit_port_released, True),
    ("X1", "自检：端口精确匹配（不误伤相邻端口）", case_x1_port_match_precision, True),
    ("X2", "自检：占位进程启动失败能被识别", case_x2_holder_failure_detected, True),
    ("X3", "自检：占位进程异常路径也清理干净", case_x3_holder_cleanup, True),
]

# 慢速用例：需要联网装依赖，默认不跑（用 --only H1 或 --slow 触发）
SLOW_CASES: List[Tuple[str, str, Callable[[Result], None], bool]] = [
    ("H1", "无 venv 首次运行能自建并装依赖（慢）", case_h1_no_venv_first_run, True),
]


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

    all_cases = CASES + (SLOW_CASES if args.slow else [])

    if args.list:
        print("验收用例清单：")
        for cid, name, _fn, _safe in CASES:
            print(f"  {cid:4s} {name}")
        print("慢速用例（需 --slow 或 --only H1）：")
        for cid, name, _fn, _safe in SLOW_CASES:
            print(f"  {cid:4s} {name}")
        return 0

    selected = all_cases
    if args.only:
        keys = {k.upper() for k in args.only}
        selected = [c for c in all_cases if c[0].upper() in keys]
        if not selected:
            print(f"没有匹配的用例：{args.only}")
            return 2

    results: List[Result] = []
    for cid, name, fn, _safe in selected:
        res = Result(cid, name)
        t0 = time.time()
        try:
            fn(res)
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
