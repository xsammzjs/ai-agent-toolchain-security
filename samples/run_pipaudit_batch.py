# -*- coding: utf-8 -*-
"""
批量重跑pip-audit（统一口径：GHSA/PYSEC映射aliases去重到唯一CVE计数）
6个已有项目+新下载的crawl4ai/ComfyUI
"""
import io
import json
import os
import subprocess
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(BASE, "samples", "vuln_reqs", "real_projects")
PY311 = r"D:\dev_jieshiqi\python\python3.11.9\python.exe"

REPOS = ["minimind", "gpt_academic", "MoneyPrinterTurbo",
         "MediaCrawler", "Deep-Live-Cam", "crawl4ai", "ComfyUI"]
# OpenManus 已两次确认 pip-audit 超时（900s/600s 均无结果），记录为超时，不再重试


def count_unique_cves(path):
    d = json.load(io.open(path, encoding="utf-8"))
    cves = set()
    for dep in d.get("dependencies", []):
        for v in dep.get("vulns", []):
            i = v.get("id", "")
            if i.startswith("CVE"):
                cves.add(i)
            for a in v.get("aliases", []):
                if a.startswith("CVE"):
                    cves.add(a)
    return len(cves)


results = {}
for slug in REPOS:
    req = os.path.join(OUT, "req_%s.txt" % slug)
    if not os.path.isfile(req):
        print(slug, "无requirements,跳过")
        continue
    out_json = os.path.join(OUT, "pipaudit_%s.json" % slug)
    if os.path.isfile(out_json) and slug != "gpt_academic":
        c = count_unique_cves(out_json)
        results[slug] = c
        print(slug, "已有缓存:", c, "个唯一CVE")
        continue
    print("跑", slug, "...")
    try:
        r = subprocess.run(
            [PY311, "-m", "pip_audit", "-r", req, "-f", "json", "--no-deps",
             "--progress-spinner", "off", "-o", out_json],
            capture_output=True, text=True, timeout=900)
    except subprocess.TimeoutExpired:
        print(slug, "pip-audit超时900s")
        results[slug] = -2
        continue
    if r.returncode not in (0, 1):
        print(slug, "pip-audit退出码", r.returncode, r.stderr[-300:])
        results[slug] = -1
        continue
    if not os.path.isfile(out_json):
        print(slug, "无输出json")
        results[slug] = -1
        continue
    c = count_unique_cves(out_json)
    results[slug] = c
    print(slug, ":", c, "个唯一CVE")

with io.open(os.path.join(OUT, "pipaudit_unique_cves.json"), "w", encoding="utf-8") as f:
    json.dump(results, f, ensure_ascii=False, indent=2)
print("完成:", json.dumps(results))
