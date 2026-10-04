# -*- coding: utf-8 -*-
"""补下载擂台赛4个失败项目的requirements.txt（GitHub raw断连重试）"""
import io
import os
import re
import sys
import time
import json
import urllib.request

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_reqs", "real_projects")
FAILED = ["FoundationAgents/MetaGPT", "unclecode/crawl4ai",
          "home-assistant/core", "Comfy-Org/ComfyUI"]
HDR = {"User-Agent": "Mozilla/5.0 (sbom-security-tool research)"}


def api(url):
    req = urllib.request.Request(url, headers=HDR)
    return json.loads(urllib.request.urlopen(req, timeout=30).read().decode("utf-8"))


def pick_requirements(files):
    """过滤dev/test/docs/ci，优先根目录requirements.txt"""
    good = [f for f in files
            if f.startswith("requirements") and f.endswith(".txt")
            and not re.search(r"dev|test|docs|ci|lint|build", f, re.I)]
    if not good:
        return None
    root_req = [f for f in good if "/" not in f]
    return (root_req or good)[0]


def ascii_clean(text):
    return "\n".join(
        l for l in text.splitlines()
        if l.strip() and not l.strip().startswith("#")
        and all(ord(c) < 128 for c in l.strip()))


for repo in FAILED:
    slug = repo.split("/")[1]
    try:
        tree = api("https://api.github.com/repos/%s/git/trees/HEAD?recursive=1" % repo)
        files = [t["path"] for t in tree.get("tree", []) if t.get("type") == "blob"]
        rel = pick_requirements(files)
        if not rel:
            print(repo, "跳过: 无requirements*.txt")
            continue
        raw = "https://raw.githubusercontent.com/%s/HEAD/%s" % (repo, rel)
        for attempt in range(3):
            try:
                req = urllib.request.Request(raw, headers=HDR)
                text = urllib.request.urlopen(req, timeout=60).read().decode("utf-8", "replace")
                break
            except Exception as e:
                print(repo, "重试%d: %s" % (attempt + 1, e))
                time.sleep(10)
                text = None
        if not text:
            print(repo, "最终失败")
            continue
        cleaned = ascii_clean(text)
        with io.open(os.path.join(OUT, "req_%s.txt" % slug), "w", encoding="utf-8") as f:
            f.write(cleaned)
        print(repo, "OK:", rel, len(cleaned.splitlines()), "行")
    except Exception as e:
        print(repo, "失败:", e)
