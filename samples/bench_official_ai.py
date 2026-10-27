# -*- coding: utf-8 -*-
"""对 CompoSkill 官方公开用例做 AI 意图分诊（走正式判定的磁盘缓存）。"""
import io
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "samples"))

import config  # noqa: F401,E402  触发 load_dotenv
from modules import adjudicator as adj  # noqa: E402

import bench_official_eval as be  # noqa: E402


def blob_of(name):
    main, extra = be.read_skill_case(name)
    return main + "\n\n" + "\n\n".join(t for _p, t in extra)


def main():
    print("MaaS 可用:", adj.is_available())
    print()
    out = []
    for name in sorted(be.OFFICIAL):
        blob = blob_of(name)
        r = adj.judge_skill_combined(name, blob)
        off = be.OFFICIAL[name]
        print(f"── {name} ──")
        print(f"  官方结论  : {off['cn']}")
        print(f"  我们的判定: {r['verdict']}  | 外发范围: {r['scope']}"
              f"  | degraded: {r.get('degraded')}")
        print(f"  理由      : {r.get('reason', '')[:110]}")
        print(f"  外发理由  : {r.get('scope_reason', '')[:110]}")
        print(f"  证据行号  : 意图 {r.get('ev_intent')} / 外发 {r.get('ev_scope')}")
        agree = (r["verdict"] == "MALICIOUS") == (off["verdict"] == "MALICIOUS")
        print(f"  与官方一致 : {'✅ 是' if agree else '❌ 否'}")
        print()
        out.append({
            "name": name,
            "official": off,
            "ours": {k: r.get(k) for k in
                     ("verdict", "scope", "reason", "scope_reason",
                      "ev_intent", "ev_scope", "degraded", "cached")},
            "agree_with_official": agree,
            "n_chars": len(blob),
        })

    p = os.path.join(ROOT, "samples", "public_bench", "_official_ai_result.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"结果已写入 {os.path.relpath(p, ROOT)}")
    n_ok = sum(1 for x in out if x["agree_with_official"])
    print(f"AI 意图分诊与官方结论一致：{n_ok}/{len(out)}")


if __name__ == "__main__":
    main()
