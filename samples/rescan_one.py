"""单样本重扫并更新缓存（内部工具，2026-09-09）"""
import io
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules.engine import ScanEngine

name = sys.argv[1]
path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_reqs", name + ".txt")
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

t0 = time.perf_counter()
engine = ScanEngine()
result = engine.run_full_scan(path, "auto", use_nvd=True, do_epss=True)
secs = time.perf_counter() - t0
print(f"{name}: {len(result['vulns'])} 条, {secs:.1f}s")
for v in result["vulns"]:
    print(f"  {v.get('cve_id')} {v.get('package')}=={v.get('version')} "
          f"{v.get('severity')} conf={v.get('confidence', {}).get('level')}")
json.dump({"vulns": sorted({(v.get("cve_id") or "").strip() for v in result["vulns"]
                            if (v.get("cve_id") or "").strip()}), "seconds": secs},
          io.open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_reqs",
                               f"cache_{name}.json"), "w", encoding="utf-8"),
          ensure_ascii=False)
print("缓存已更新", flush=True)
