# -*- coding: utf-8 -*-
"""
真实项目三工具横向对比（2026-09-14，回应评委建议第5条）
=====================================================
从GitHub下载 10 个真实高star项目的 requirements.txt，
同一批文件分别用 本工具 / pip-audit / Trivy 扫描，按漏洞编号去重统计对比。

结果缓存到 samples/vuln_reqs/real_projects/ 下：
  cache_real_<slug>.json  本工具结果
  trivy_real_<slug>.json  Trivy 原始 JSON
汇总表打印到 stdout，并存 real_compare_results.json。
"""
import io
import json
import os
import re
import shutil
import subprocess
import sys
import time

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_reqs", "real_projects")
os.makedirs(BASE, exist_ok=True)

# 10 个真实项目（从 25 项目清单中取版本已锁定的：8 个检出漏洞 + 2 个零漏洞对照）
REPOS = [
    "jingyaogong/minimind",
    "FoundationAgents/MetaGPT",
    "FoundationAgents/OpenManus",
    "binary-husky/gpt_academic",
    "unclecode/crawl4ai",
    "harry0703/MoneyPrinterTurbo",
    "NanmiCoder/MediaCrawler",
    "home-assistant/core",
    "Comfy-Org/ComfyUI",
    "hacksider/Deep-Live-Cam",
]

TRIVY = shutil.which("trivy") or \
    r"C:\Users\34612\AppData\Local\Microsoft\WinGet\Packages\AquaSecurity.Trivy_Microsoft.Winget.Source_8wekyb3d8bbwe\trivy.EXE"
TRIVY_CACHE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "trivy_cache")
PY311 = None
for c in [r"D:\dev_jieshiqi\python\python3.11.9\python.exe", r"C:\Python311\python.exe"]:
    if os.path.isfile(c):
        PY311 = c
        break

API_HEADERS = {"User-Agent": "sbom-tool-benchmark", "Accept": "application/vnd.github+json"}


def slug(repo: str) -> str:
    return repo.split("/")[-1]


def log(msg: str):
    print(msg, flush=True)


# ---------- 1. 下载 requirements.txt ----------
def fetch_requirements(repo: str) -> tuple[str, int]:
    """返回 (本地路径, star数)。找不到 requirements 文件时抛 RuntimeError。"""
    info = requests.get(f"https://api.github.com/repos/{repo}", headers=API_HEADERS, timeout=30)
    info.raise_for_status()
    data = info.json()
    branch = data.get("default_branch", "main")
    stars = data.get("stargazers_count", 0)
    tree = requests.get(
        f"https://api.github.com/repos/{repo}/git/trees/{branch}?recursive=1",
        headers=API_HEADERS, timeout=60)
    tree.raise_for_status()
    paths = [t["path"] for t in tree.json().get("tree", [])
             if t.get("type") == "blob" and re.match(r".*requirements.*\.txt$", t["path"], re.I)]
    # 排除 dev/test/docs/ci 类文件
    candidates = [p for p in paths
                  if not re.search(r"(dev|test|docs?|ci|setup|tools?|\.github)/", p, re.I)]
    if not candidates:
        candidates = paths
    if not candidates:
        raise RuntimeError("无 requirements*.txt")
    # 优先根目录 requirements.txt
    picked = "requirements.txt" if "requirements.txt" in candidates else sorted(candidates, key=len)[0]
    raw = requests.get(
        f"https://raw.githubusercontent.com/{repo}/{branch}/{picked}", timeout=60)
    raw.raise_for_status()
    # ASCII 清洗：pip-audit 在 GBK locale 下遇到非 ASCII 行会崩，统一只留 ASCII 行
    lines = []
    for line in raw.text.splitlines():
        try:
            line.encode("ascii")
            lines.append(line)
        except UnicodeEncodeError:
            continue
    out_path = os.path.join(BASE, f"req_{slug(repo)}.txt")
    with open(out_path, "w", encoding="ascii", errors="ignore") as f:
        f.write("\n".join(lines))
    return out_path, stars


def count_deps(path: str) -> int:
    n = 0
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if s and not s.startswith("#"):
                n += 1
    return n


# ---------- 2. 本工具 ----------
def run_our_tool(repo: str, path: str) -> dict:
    cache = os.path.join(BASE, f"cache_real_{slug(repo)}.json")
    if os.path.isfile(cache):
        return json.load(io.open(cache, encoding="utf-8"))
    from modules.engine import ScanEngine
    t0 = time.perf_counter()
    engine = ScanEngine()
    result = engine.run_full_scan(path, "auto", use_nvd=True, do_epss=True)
    secs = time.perf_counter() - t0
    ids = sorted({(v.get("cve_id") or "").strip() for v in result.get("vulns", [])
                  if (v.get("cve_id") or "").strip()})
    out = {"vulns": ids, "seconds": secs}
    json.dump(out, io.open(cache, "w", encoding="utf-8"), ensure_ascii=False)
    return out


# ---------- 3. pip-audit ----------
def run_pip_audit(path: str) -> dict:
    if not PY311:
        return {"vulns": [], "seconds": 0, "note": "未找到 Python 3.11"}
    t0 = time.perf_counter()
    try:
        p = subprocess.run(
            [PY311, "-m", "pip_audit", "-r", path, "-f", "json",
             "--no-deps", "--progress-spinner", "off"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=600)
    except Exception as e:
        return {"vulns": [], "seconds": time.perf_counter() - t0, "note": f"失败: {e}"}
    secs = time.perf_counter() - t0
    try:
        data = json.loads(p.stdout)
    except json.JSONDecodeError:
        return {"vulns": [], "seconds": secs, "note": p.stderr.strip()[-120:]}
    vulns = set()
    for d in data.get("dependencies", []):
        for v in d.get("vulns", []):
            vid = v.get("id", "")
            if vid.upper().startswith(("CVE", "PYSEC", "GHSA")):
                vulns.add(vid)
    return {"vulns": sorted(vulns), "seconds": secs, "note": ""}


# ---------- 4. Trivy ----------
def run_trivy(repo: str) -> dict:
    cache = os.path.join(BASE, f"trivy_real_{slug(repo)}.json")
    if os.path.isfile(cache):
        data = json.load(io.open(cache, encoding="utf-8"))
    else:
        # Trivy 只识别名为 requirements*.txt 的文件，复制到独立目录
        workdir = os.path.join(BASE, f"trivy_{slug(repo)}")
        os.makedirs(workdir, exist_ok=True)
        dst = os.path.join(workdir, "requirements.txt")
        shutil.copyfile(os.path.join(BASE, f"req_{slug(repo)}.txt"), dst)
        t0 = time.perf_counter()
        proc = subprocess.run(
            [TRIVY, "fs", "--scanners", "vuln", "--format", "json",
             "--cache-dir", TRIVY_CACHE, "--skip-db-update", "--no-progress",
             workdir],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=900)
        secs = time.perf_counter() - t0
        if proc.returncode not in (0, 1):
            return {"vulns": [], "seconds": secs, "note": f"trivy 退出码 {proc.returncode}: {proc.stderr[:200]}"}
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return {"vulns": [], "seconds": secs, "note": "trivy 输出非 JSON"}
        json.dump(data, io.open(cache, "w", encoding="utf-8"), ensure_ascii=False)
    ids = set()
    for r in data.get("Results", []):
        for v in r.get("Vulnerabilities", []):
            vid = v.get("VulnerabilityID", "")
            if vid.upper().startswith("CVE"):
                ids.add(vid)
    return {"vulns": sorted(ids), "seconds": 0, "note": ""}


def main():
    rows = []
    for repo in REPOS:
        log(f"=== {repo} ===")
        try:
            path, stars = fetch_requirements(repo)
        except Exception as e:
            log(f"  下载失败: {e}")
            rows.append({"repo": repo, "error": f"下载失败: {e}"})
            continue
        deps = count_deps(path)
        try:
            our = run_our_tool(repo, path)
        except Exception as e:
            our = {"vulns": [], "seconds": 0, "note": f"本工具失败: {e}"}
        log(f"  本工具: {len(our['vulns'])} 条 ({our['seconds']:.0f}s)")
        pa = run_pip_audit(path)
        log(f"  pip-audit: {len(pa['vulns'])} 条 ({pa['seconds']:.0f}s)")
        tr = run_trivy(repo)
        log(f"  Trivy: {len(tr['vulns'])} 条")
        rows.append({
            "repo": repo, "stars": stars, "deps": deps,
            "ours": len(our["vulns"]), "pipaudit": len(pa["vulns"]), "trivy": len(tr["vulns"]),
            "our_secs": round(our["seconds"], 1), "pa_secs": round(pa["seconds"], 1),
            "note": our.get("note") or pa.get("note") or tr.get("note") or "",
        })

    json.dump(rows, io.open(os.path.join(BASE, "real_compare_results.json"), "w",
                            encoding="utf-8"), ensure_ascii=False, indent=2)
    out = io.StringIO()
    out.write("| 项目 | 依赖数 | 本工具 | pip-audit | Trivy |\n|---|---|---|---|---|\n")
    so = sp = st = 0
    for r in rows:
        if "error" in r:
            out.write(f"| {r['repo']} | 下载失败: {r['error']} | - | - | - |\n")
            continue
        out.write(f"| {r['repo']} ({r['stars']} star) | {r['deps']} | "
                  f"{r['ours']} | {r['pipaudit']} | {r['trivy']} |\n")
        so += r["ours"]; sp += r["pipaudit"]; st += r["trivy"]
    out.write(f"| **合计** | | **{so}** | **{sp}** | **{st}** |\n")
    print(out.getvalue())
    log("结果已存 samples/vuln_reqs/real_projects/real_compare_results.json")


if __name__ == "__main__":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    main()
