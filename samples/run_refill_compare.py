# -*- coding: utf-8 -*-
"""
补跑 MetaGPT、home-assistant 的三工具对比（统一口径：唯一CVE）
复用 run_real_compare.py 的下载/扫描函数，pip-audit 按 aliases 映射去重。
"""
import io
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

import importlib.util
spec = importlib.util.spec_from_file_location(
    "rc", os.path.join(os.path.dirname(os.path.abspath(__file__)), "run_real_compare.py"))
rc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rc)

REPOS = ["FoundationAgents/MetaGPT", "home-assistant/core"]
PY311 = rc.PY311


def run_pip_audit_cve(path: str) -> dict:
    """pip-audit 唯一CVE口径：GHSA/PYSEC 映射 aliases 里的 CVE 去重"""
    t0 = time.perf_counter()
    out_json = os.path.join(rc.BASE, "pipaudit_%s.json" % os.path.basename(path)
                            .replace("req_", "").replace(".txt", ""))
    p = subprocess.run(
        [PY311, "-m", "pip_audit", "-r", path, "-f", "json",
         "--no-deps", "--progress-spinner", "off", "-o", out_json],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900)
    secs = time.perf_counter() - t0
    if p.returncode not in (0, 1) or not os.path.isfile(out_json):
        return {"vulns": [], "seconds": secs, "note": "pip-audit失败: %s" % p.stderr[-150:]}
    data = json.load(io.open(out_json, encoding="utf-8"))
    cves = set()
    for dep in data.get("dependencies", []):
        for v in dep.get("vulns", []):
            vid = v.get("id", "")
            if vid.startswith("CVE"):
                cves.add(vid)
            for a in v.get("aliases", []):
                if a.startswith("CVE"):
                    cves.add(a)
    return {"vulns": sorted(cves), "seconds": secs, "note": ""}


rows = []
for repo in REPOS:
    slug = rc.slug(repo)
    path = os.path.join(rc.BASE, "req_%s.txt" % slug)
    print("=== %s ===" % repo, flush=True)
    if not os.path.isfile(path):
        print("  无requirements文件,跳过", flush=True)
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
    pa = run_pip_audit_cve(path)
    print("  pip-audit(唯一CVE): %d 条 (%.0fs)" % (len(pa["vulns"]), pa["seconds"]), flush=True)
    tr = rc.run_trivy(repo)
    print("  Trivy: %d 条" % len(tr["vulns"]), flush=True)
    rows.append({"repo": repo, "stars": stars, "deps": deps,
                 "ours": len(our["vulns"]), "pipaudit": len(pa["vulns"]),
                 "trivy": len(tr["vulns"]), "note": pa.get("note", "")})

json.dump(rows, io.open(os.path.join(rc.BASE, "refill_compare_results.json"), "w",
                        encoding="utf-8"), ensure_ascii=False, indent=2)
print("完成:", json.dumps(rows, ensure_ascii=False))
