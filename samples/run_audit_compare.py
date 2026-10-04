"""
依赖检测量化对比（2026-09-09 新增）
=====================================
对 3 个已知漏洞版本的 requirements.txt 样本，
对比 pip-audit（OSV 单源）与本工具（OSV+NVD+GitHub+EPSS 四源）的检测结果。

本工具的扫描结果缓存到 cache_<样本名>.json（四源扫描较慢，避免重复联网）。
用法：
  python samples/run_audit_compare.py            # 完整跑（本工具结果缺缓存时联网扫描）
  python samples/run_audit_compare.py --cached   # 只跑 pip-audit，本工具用缓存
"""
import io
import json
import os
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SAMPLE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_reqs")
SAMPLES = ["sample_serious", "sample_mixed", "sample_clean"]


def _find_python311() -> str | None:
    """自动探测 Python 3.11 解释器路径（pip-audit 在 3.13 下构建失败，需用 3.11）"""
    # 1. 直接命令
    p = shutil.which("python3.11")
    if p:
        return p
    # 2. Windows py launcher
    try:
        r = subprocess.run(
            ["py", "-3.11", "-c", "import sys;print(sys.executable)"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0 and r.stdout.strip() and os.path.isfile(r.stdout.strip()):
            return r.stdout.strip()
    except Exception:
        pass
    # 3. 常见安装路径
    username = os.environ.get("USERNAME", "")
    candidates = [
        r"C:\Python311\python.exe",
        rf"C:\Users\{username}\AppData\Local\Programs\Python\Python311\python.exe",
        r"D:\dev_jieshiqi\python\python3.11.9\python.exe",
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


PY311 = _find_python311()


def run_pip_audit(req_file: str) -> dict:
    """pip-audit 扫描，返回 {"vulns": [...], "seconds": float, "note": str}"""
    if not PY311:
        return {"vulns": [], "seconds": 0, "note": "未找到 Python 3.11（pip-audit 需 3.11 环境），请安装后重试；本工具结果仍可从缓存读取"}
    t0 = time.perf_counter()
    try:
        p = subprocess.run(
            [PY311, "-m", "pip_audit", "-r", req_file, "-f", "json",
             "--no-deps", "--progress-spinner", "off"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=600,
        )
    except Exception as e:
        return {"vulns": [], "seconds": time.perf_counter() - t0, "note": f"运行失败: {e}"}
    secs = time.perf_counter() - t0
    # pip-audit 发现漏洞时退出码为 1（安全工具惯例），只要 JSON 解析成功就是有效结果
    try:
        data = json.loads(p.stdout)
    except json.JSONDecodeError:
        return {"vulns": [], "seconds": secs, "note": p.stderr.strip()[-150:]}
    vulns = []
    for d in data.get("dependencies", []):
        for v in d.get("vulns", []):
            vulns.append(v.get("id", ""))
    return {"vulns": vulns, "seconds": secs, "note": ""}


def run_our_tool(name: str, req_file: str, use_cache: bool) -> dict:
    """本工具扫描（四源交叉验证），结果缓存。"""
    cache_path = os.path.join(SAMPLE_DIR, f"cache_{name}.json")
    if use_cache and os.path.isfile(cache_path):
        data = json.load(io.open(cache_path, encoding="utf-8"))
        return {"vulns": data["vulns"], "seconds": data["seconds"], "note": ""}
    from modules.engine import ScanEngine
    t0 = time.perf_counter()
    try:
        engine = ScanEngine()
        result = engine.run_full_scan(req_file, "auto", use_nvd=True, do_epss=True)
    except Exception as e:
        return {"vulns": [], "seconds": time.perf_counter() - t0, "note": f"运行失败: {e}"}
    secs = time.perf_counter() - t0
    ids = sorted({(v.get("cve_id") or "").strip() for v in result.get("vulns", [])
                  if (v.get("cve_id") or "").strip()})
    json.dump({"vulns": ids, "seconds": secs},
              io.open(cache_path, "w", encoding="utf-8"), ensure_ascii=False)
    return {"vulns": ids, "seconds": secs, "note": ""}


def main():
    use_cache = "--cached" in sys.argv
    rows = []
    for name in SAMPLES:
        path = os.path.join(SAMPLE_DIR, name + ".txt")
        pa = run_pip_audit(path)
        our = run_our_tool(name, path, use_cache)
        pa_ids = {v for v in pa["vulns"] if v.upper().startswith(("CVE", "PYSEC", "GHSA"))}
        our_ids = set(our["vulns"])
        rows.append({
            "样本": name, "依赖数": sum(1 for l in open(path, encoding="utf-8")
                                      if l.strip() and not l.startswith("#")),
            "pa检出": len(pa_ids), "本工具检出": len(our_ids),
            "pa耗时": round(pa["seconds"], 1), "本工具耗时": round(our["seconds"], 1),
            "说明": pa["note"] or our["note"] or "",
        })
    out = io.StringIO()
    out.write("| 样本 | 依赖数 | pip-audit检出 | 本工具检出 | pip-audit耗时 | 本工具耗时 |\n")
    out.write("|---|---|---|---|---|---|\n")
    for r in rows:
        out.write(f"| {r['样本']} | {r['依赖数']} | {r['pa检出']} | {r['本工具检出']} "
                  f"| {r['pa耗时']}s | {r['本工具耗时']}s |\n")
    total_pa = sum(r["pa检出"] for r in rows)
    total_our = sum(r["本工具检出"] for r in rows)
    out.write(f"\n合计检出：pip-audit {total_pa} 条，本工具 {total_our} 条。\n")
    out.write("本工具额外覆盖：NVD 标准CVE详情 + GitHub Advisory + EPSS 利用概率 + 置信度证据链；"
              "pip-audit 仅 OSV 单源。\n")
    for r in rows:
        if r["说明"]:
            out.write(f"注：{r['样本']} {r['说明']}\n")
    return out.getvalue()


if __name__ == "__main__":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    print(main())
