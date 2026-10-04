# -*- coding: utf-8 -*-
"""补跑 home-assistant/core 的三工具对比（slug=core）"""
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

repo = "home-assistant/core"
slug = "core"
path = os.path.join(rc.BASE, "req_core.txt")

stars = 0
try:
    info = rc.requests.get("https://api.github.com/repos/%s" % repo,
                           headers=rc.API_HEADERS, timeout=30)
    stars = info.json().get("stargazers_count", 0)
except Exception:
    pass

deps = rc.count_deps(path)
print("=== %s (star %s) ===" % (repo, stars), flush=True)
our = rc.run_our_tool(repo, path)
print("  本工具: %d 条 (%.0fs)" % (len(our["vulns"]), our["seconds"]), flush=True)

t0 = time.perf_counter()
out_json = os.path.join(rc.BASE, "pipaudit_core.json")
p = subprocess.run(
    [rc.PY311, "-m", "pip_audit", "-r", path, "-f", "json",
     "--no-deps", "--progress-spinner", "off", "-o", out_json],
    capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900)
secs = time.perf_counter() - t0
cves = set()
if p.returncode in (0, 1) and os.path.isfile(out_json):
    data = json.load(io.open(out_json, encoding="utf-8"))
    for dep in data.get("dependencies", []):
        for v in dep.get("vulns", []):
            vid = v.get("id", "")
            if vid.startswith("CVE"):
                cves.add(vid)
            for a in v.get("aliases", []):
                if a.startswith("CVE"):
                    cves.add(a)
    note = ""
else:
    note = "pip-audit失败: %s" % p.stderr[-200:]
print("  pip-audit(唯一CVE): %d 条 (%.0fs) %s" % (len(cves), secs, note), flush=True)

tr = rc.run_trivy(repo)
print("  Trivy: %d 条" % len(tr["vulns"]), flush=True)

row = {"repo": repo, "stars": stars, "deps": deps,
       "ours": len(our["vulns"]), "pipaudit": len(cves),
       "trivy": len(tr["vulns"]), "note": note}
json.dump([row], io.open(os.path.join(rc.BASE, "core_compare_results.json"), "w",
                         encoding="utf-8"), ensure_ascii=False, indent=2)
print("完成:", json.dumps(row, ensure_ascii=False))
