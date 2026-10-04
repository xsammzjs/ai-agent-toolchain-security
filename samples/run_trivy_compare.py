# -*- coding: utf-8 -*-
"""Trivy vs 本工具 横向对比（2026-09-09）
口径与 run_audit_compare.py 一致：同三个样本，统计去重后的漏洞条数。
Trivy 结果按 CVE 去重；结果缓存到 samples/vuln_reqs/cache_trivy_*.json。
"""
import json
import os
import shutil
import subprocess

# Trivy 可执行文件（自动探测 PATH，找不到则在运行时提示安装）
TRIVY = shutil.which("trivy")

SAMPLES = {
    "serious": "samples/vuln_reqs/sample_serious.txt",
    "mixed": "samples/vuln_reqs/sample_mixed.txt",
    "clean": "samples/vuln_reqs/sample_clean.txt",
}
# 本工具与 pip-audit 结果（2026-09-09 实测，与 run_audit_compare.py 一致）
OUR_TOOL = {"serious": 60, "mixed": 29, "clean": 13}
PIP_AUDIT = {"serious": 58, "mixed": 29, "clean": 9}


def run_trivy(path: str, cache_path: str) -> dict:
    if os.path.isfile(cache_path):
        with open(cache_path, encoding="utf-8") as f:
            return json.load(f)
    if not TRIVY:
        raise RuntimeError("未找到 trivy 命令，请先安装：winget install AquaSecurity.Trivy（安装后重开终端）")
    proc = subprocess.run(
        [TRIVY, "fs", "--scanners", "vuln", "--format", "json", path],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=900,
    )
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"trivy 退出码 {proc.returncode}: {proc.stderr[:300]}")
    data = json.loads(proc.stdout)
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    return data


def count_ids(trivy_json: dict) -> int:
    """按漏洞编号去重统计（CVE 与 GHSA 统一计数）"""
    ids = set()
    for r in trivy_json.get("Results", []):
        for v in r.get("Vulnerabilities", []):
            ids.add(v.get("VulnerabilityID", ""))
    ids.discard("")
    return len(ids)


def main():
    rows = {}
    for name, path in SAMPLES.items():
        cache_path = f"samples/vuln_reqs/cache_trivy_{name}.json"
        try:
            data = run_trivy(path, cache_path)
            rows[name] = count_ids(data)
        except Exception as e:
            print(f"{name}: 失败 - {e}")
            rows[name] = None

    print("\n===== Trivy vs pip-audit vs 本工具（去重漏洞条数）=====")
    print(f"{'样本':<10}{'Trivy':>8}{'pip-audit':>12}{'本工具':>10}")
    t_sum = p_sum = o_sum = 0
    for name in SAMPLES:
        t = rows.get(name)
        t_disp = "-" if t is None else str(t)
        print(f"{name:<10}{t_disp:>8}{PIP_AUDIT[name]:>12}{OUR_TOOL[name]:>10}")
        if t is not None:
            t_sum += t
        p_sum += PIP_AUDIT[name]
        o_sum += OUR_TOOL[name]
    print(f"{'合计':<10}{t_sum:>8}{p_sum:>12}{o_sum:>10}")


if __name__ == "__main__":
    main()
