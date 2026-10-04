"""三个样本开间接依赖推断重扫并更新缓存（口径与pip-audit对齐，2026-09-09）"""
import io
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules.engine import ScanEngine

BASE = os.path.dirname(os.path.abspath(__file__))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

for name in ["sample_serious", "sample_mixed", "sample_clean"]:
    path = os.path.join(BASE, "vuln_reqs", name + ".txt")
    t0 = time.perf_counter()
    engine = ScanEngine()
    result = engine.run_full_scan(path, "auto", use_nvd=True, do_epss=True,
                                  include_transitive=True)
    secs = time.perf_counter() - t0
    ids = sorted({(v.get("cve_id") or "").strip() for v in result["vulns"]
                  if (v.get("cve_id") or "").strip()})
    json.dump({"vulns": ids, "seconds": secs},
              io.open(os.path.join(BASE, "vuln_reqs", f"cache_{name}.json"),
                      "w", encoding="utf-8"), ensure_ascii=False)
    print(f"{name}: {len(ids)} 条, {secs:.1f}s（含间接依赖推断）", flush=True)
print("全部缓存已更新")
