# -*- coding: utf-8 -*-
"""补跑 crawl4ai、ComfyUI 的本工具+Trivy（requirements已就绪）"""
import io
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

import importlib.util
spec = importlib.util.spec_from_file_location(
    "rc", os.path.join(os.path.dirname(os.path.abspath(__file__)), "run_real_compare.py"))
rc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rc)

REPOS = ["unclecode/crawl4ai", "Comfy-Org/ComfyUI"]
rows = []
for repo in REPOS:
    print("=== %s ===" % repo, flush=True)
    slug = rc.slug(repo)
    path = os.path.join(rc.BASE, "req_%s.txt" % slug)
    if not os.path.isfile(path):
        print("  无requirements,跳过", flush=True)
        continue
    stars = 0
    try:
        info = rc.requests.get("https://api.github.com/repos/%s" % repo,
                               headers=rc.API_HEADERS, timeout=30)
        stars = info.json().get("stargazers_count", 0)
    except Exception:
        pass
    deps = rc.count_deps(path)
    our = rc.run_our_tool(repo, path)
    print("  本工具: %d 条 (%.0fs)" % (len(our["vulns"]), our["seconds"]), flush=True)
    tr = rc.run_trivy(repo)
    print("  Trivy: %d 条" % len(tr["vulns"]), flush=True)
    rows.append({"repo": repo, "stars": stars, "deps": deps,
                 "ours": len(our["vulns"]), "trivy": len(tr["vulns"])})

json.dump(rows, io.open(os.path.join(rc.BASE, "crawl_comfy_results.json"), "w",
                        encoding="utf-8"), ensure_ascii=False, indent=2)
print("完成:", json.dumps(rows, ensure_ascii=False))
