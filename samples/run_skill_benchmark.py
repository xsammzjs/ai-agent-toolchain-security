"""
Skill 检测引擎基准测试（2026-09-09 新增，2026-09-14 扩样）
==========================================
对内置样本库做全量检测率测试，输出答辩可用数据：
- 30 个恶意样本（基于公开披露的恶意模式构造：ClawHavoc/Snyk ToxicSkills/OWASP/Cisco）
- 20 个正常样本（对照，验证无误报）
只跑静态规则引擎（本地毫秒级），不调用 AI。
"""
import io
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules import skill_scanner

SAMPLE_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "skill_samples")
MALICIOUS = [
    # 原有 5 个（2026-09-09）
    "pdf-toolkit", "image-compressor", "crypto-assistant",
    "system-cleaner", "docs-translator",
    # 新增 25 个（2026-09-14，改编自公开报告的攻击模式，样本内标注来源）
    "excel-formatter", "voice-transcriber", "meeting-notes", "video-editor", "code-formatter",
    "wallpaper-changer", "stock-analyzer", "email-writer", "file-organizer", "weather-bot",
    "translation-helper", "csv-merger", "screen-recorder", "to-do-manager", "password-generator",
    "pdf-converter", "music-downloader", "spreadsheet-analyzer", "chat-history-cleaner", "file-converter",
    "markdown-previewer", "qr-code-generator", "news-digest", "calendar-helper", "terminal-theme",
]
BENIGN = [
    # 原有 2 个（2026-09-09）
    "code-review-helper", "pdf-summarizer",
    # 新增 18 个（2026-09-14，常见开发辅助类正常技能）
    "markdown-table-generator", "git-commit-helper", "json-formatter", "csv-to-json",
    "unit-test-writer", "readme-generator", "code-commenter", "changelog-helper",
    "api-doc-generator", "sql-query-helper", "regex-helper", "file-renamer",
    "image-resizer", "time-converter", "text-summarizer", "meeting-agenda",
    "data-visualizer", "code-snippet-library",
]


def run():
    results = []
    t0 = time.perf_counter()
    for name in MALICIOUS + BENIGN:
        path = os.path.join(SAMPLE_ROOT, name)
        r = skill_scanner.scan_skill_package(path)
        results.append((name, r))
    elapsed = time.perf_counter() - t0

    malicious_hit = 0
    benign_clean = 0
    out = io.StringIO()
    out.write(f"{'样本名':<20}{'类型':<6}{'文件数':<6}{'命中规则':<8}{'严重':<5}{'高危':<5}{'中危':<5}{'低危':<5}{'判定'}\n")
    for name, r in results:
        sev = {s: 0 for s in ("严重", "高危", "中危", "低危")}
        for f in r["findings"]:
            s = f["severity"]
            if s in sev:
                sev[s] += 1
        verdict = r["verdict"]
        is_mal = name in MALICIOUS
        if is_mal and r["findings"]:
            malicious_hit += 1
        if not is_mal and not r["findings"]:
            benign_clean += 1
        out.write(f"{name:<20}{'恶意' if is_mal else '正常':<6}{r['files']:<6}"
                  f"{len(r['findings']):<8}{sev['严重']:<5}{sev['高危']:<5}{sev['中危']:<5}{sev['低危']:<5}{verdict}\n")
    out.write(f"\n恶意样本检出率: {malicious_hit}/{len(MALICIOUS)}"
              f"  正常样本无误报: {benign_clean}/{len(BENIGN)}"
              f"  总耗时: {elapsed*1000:.0f}ms（纯本地规则引擎，零费用）")
    return out.getvalue()


if __name__ == "__main__":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    print(run())
