"""
真实 Skill 语料下载器（codeload/gh-proxy 通道版）
==================================================
从公开仓库拉取**含完整正文的**真实 Skill 样本，用于实测检出率与误报率。

【为什么需要】
手工构造的样例只能证明「功能能跑」，无法回答评委最可能问的：
「你的规则在真实数据上有效吗？会不会大量误报？」
2026-10-17 实测发现：在真实良性语料上误报率一度高达 58.6%，
这个数字只有靠真实语料才能测出来。

【通道选择与踩坑记录】
本机环境实测（2026-10-17，加速器已开启）：

  通道                  结果
  ────────────────────────────────────────────────
  api.github.com ✅  但未认证时限额 60 次/小时，177 个文件必然触发限流
                     （登录后有 token 可提额到 5000/小时，但本脚本不依赖 token）
  raw.githubusercontent  ❌ 被加速器阻断（读超时）
  codeload.github.com   ⚠️ 可连但限速极��（实测 4 分钟仅 255KB，约 1KB/s）
  gh-proxy.com      ✅✅ 0.8 秒 / 15KB，最快且最稳→ 本脚本采用

因此本脚本优先走 gh-proxy，失败时回退 codeload（仅在文件数很少时可用）。
这样无需 GitHub token，也不受 API 限额影响。

【语料说明】
1. benign_scientific（K-Dense-AI/scientific-agent-skills）
   真实科研类技能（科学计算 / 生物信息 / 临床研究工作流），无恶意载荷。
   该语料是论文 T-Zevin/SkillGuardrail 的评测来源，可视为明确良性样本。
   用途：测**误报率（FPR）**。

2. toxic_skills（snyk-labs/toxicskills-goof）
   Snyk ToxicSkills 论文配套恶意样本库，含真实恶意正文。
   用途：测**检出率（TPR）**。

【数据合规】
- 样本来自公开仓库，仅用于防御性安全研究
- 恶意样本只做静态分析，不执行
- 每个语料目录生成 _manifest.json，记录来源 URL 便于溯源复现
"""
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request

# 加速器用自签证书转发，本机环境关闭校验
# 连接目标仍为 gh-proxy 转发服务，不影响数据来源真实性
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE

BASE = os.path.dirname(os.path.abspath(__file__))

# ==========================================================
# 语料定义
# ==========================================================
CORPORA = [
    {
        "repo": "K-Dense-AI/scientific-agent-skills",
        "branch": "main",
        "out": "benign_scientific",
        "label": "benign",
        "desc": "真实科研类技能，无恶意载荷，用作误报率测试集",
    },
    {
        "repo": "snyk-labs/toxicskills-goof",
        "branch": "HEAD",
        "out": "toxic_skills",
        "label": "malicious",
        "desc": "Snyk ToxicSkills 论文配套恶意样本库，含真实恶意正文",
    },
]

# ==========================================================
# 取文件清单
# ===========================================���==============
def list_via_api(repo: str, branch: str = "HEAD") -> list:
    """通道 A：GitHub API（未认证时限额 60/小时，容易 403）"""
    url = f"https://api.github.com/repos/{repo}/git/trees/{branch}?recursive=1"
    req = urllib.request.Request(url, headers={"User-Agent": "skillguard-research"})
    d = json.load(urllib.request.urlopen(req, timeout=60, context=_CTX))
    if "tree" not in d:
        raise RuntimeError(f"无法读取仓库树：{str(d)[:120]}")
    return [t["path"] for t in d["tree"] if t["path"].endswith("SKILL.md")]


def list_via_web(repo: str, branch: str = "main") -> list:
    """
    通道 B：抓 GitHub 网页目录页（经 gh-proxy 转发，不受 API 限额）
    适用于「所有 SKILL.md 都在同一个父目录下」的情况——
    网页会平铺列出该目录下的全部子目录名，拼成 <dir>/SKILL.md 即可。
    """
    import re as _re
    out = []
    page_url = f"https://github.com/{repo}/tree/{branch}/skills"
    for proxy in (f"https://gh-proxy.com/{page_url}",
                  page_url):
        try:
            req = urllib.request.Request(proxy, headers={"User-Agent": "Mozilla/5.0"})
            html = urllib.request.urlopen(req, timeout=45, context=_CTX).read().decode(
                "utf-8", "replace")
        except Exception:
            continue
        # 目录页里每个子目录对应 /tree/<branch>/skills/<name>
        names = set(_re.findall(
            r"/tree/" + _re.escape(branch) + r"/skills/([A-Za-z0-9_.\-]+)", html))
        if names:
            out = [f"skills/{n}/SKILL.md" for n in sorted(names)]
            return out
    return out


def list_skill_paths(repo: str, branch: str = "HEAD") -> list:
    """先试 API，失败回退网页目录页"""
    for fn, b in ((list_via_api, branch), (list_via_web, "main")):
        try:
            paths = fn(repo, b)
            if paths:
                return paths
        except Exception:
            continue
    raise RuntimeError("所有通道均无法获取文件清单")


# ==========================================================
# 取单个文件正文（多通道依次尝试）
# ==========================================================
def fetch_content(repo: str, branch: str, path: str, timeout: int = 30):
    """
    按优先级尝试多个通道下载一个文件。
    返回正文字符串；全部失败返回 None。
    """
    # 通道 1：gh-proxy 转发 raw（实测最快最稳）
    raw_url = (f"https://raw.githubusercontent.com/{repo}/{branch}/{path}")
    proxies = [
        f"https://gh-proxy.com/{raw_url}",
        f"https://ghproxy.net/{raw_url}",
    ]
    for p in proxies:
        try:
            req = urllib.request.Request(p, headers={"User-Agent": "Mozilla/5.0"})
            data = urllib.request.urlopen(req, timeout=timeout, context=_CTX).read()
            if data:
                return data.decode("utf-8", "replace")
        except (urllib.error.URLError, OSError, TimeoutError):
            continue

    # 通道 2：GitHub API（未认证时限额，用完会 403）
    try:
        import base64
        import urllib.parse as _up
        u = ("https://api.github.com/repos/" + repo + "/contents/"
             + _up.quote(path) + (f"?ref={branch}" if branch != "HEAD" else ""))
        req = urllib.request.Request(u, headers={"User-Agent": "skillguard-research"})
        d = json.load(urllib.request.urlopen(req, timeout=timeout, context=_CTX))
        return base64.b64decode(d["content"]).decode("utf-8", "replace")
    except Exception:
        return None


def fetch_corpus(c: dict) -> dict:
    repo, branch = c["repo"], c["branch"]
    out_dir = os.path.join(BASE, "real_corpus", c["out"])
    os.makedirs(out_dir, exist_ok=True)

    print(f"\n{'=' * 72}")
    print(f"语料：{c['out']}")
    print(f"仓库：https://github.com/{repo}")
    print(f"说明：{c['desc']}")
    print("=" * 72)

    try:
        paths = list_skill_paths(repo, branch)
    except Exception as e:
        print(f"  [失败] 读取文件清单出错：{type(e).__name__} {e}")
        return {"out": c["out"], "ok": 0, "fail": 0}

    # 跳过已存在的（支持断点续传）
    existing = {fn for fn in os.listdir(out_dir) if fn.endswith(".md")}
    print(f"  共{len(paths)} 个 SKILL.md，已存在 {len(existing)} 个，需下载 {len(paths) - len(existing)} 个")

    ok = fail = skip = 0
    manifest = []
    t0 = time.time()

    for i, p in enumerate(paths, 1):
        owner = repo.split("/")[0]
        slug = p.replace(owner, "", 1).replace("/", "__")
        slug = slug.replace(".md", "").lstrip(".")
        fn = slug + ".md"

        # 溯源信息
        item = {
            "file": fn, "source_path": p,
            "url": f"https://github.com/{repo}/blob/{branch}/{p}",
            "label": c["label"], "corpus": c["out"],
        }

        if fn in existing:
            size = os.path.getsize(os.path.join(out_dir, fn))
            item["chars"] = size
            manifest.append(item)
            skip += 1
            continue

        text = fetch_content(repo, branch, p)
        if text:
            with open(os.path.join(out_dir, fn), "w", encoding="utf-8") as f:
                f.write(text)
            item["chars"] = len(text)
            ok += 1
        else:
            fail += 1
            continue

        manifest.append(item)

        # 进度提示
        if i % 20 == 0 or i == len(paths):
            el = time.time() - t0
            rate = ok / el if el > 0 else 0
            eta = (len(paths) - i) / rate if rate > 0 else 0
            print(f"    {i}/{len(paths)}  成功 {ok}  失败 {fail}"
                  f"  {rate:.1f} 文件/秒  预计剩余 {eta:.0f}s")

    with open(os.path.join(out_dir, "_manifest.json"), "w", encoding="utf-8") as f:
        json.dump({"repo": repo, "branch": branch, "label": c["label"],
                   "desc": c["desc"], "count": len(manifest), "items": manifest},
                  f, ensure_ascii=False, indent=2)

    print(f"  完成：新下载 {ok}，跳过 {skip}，失败 {fail}，共 {len(manifest)}")
    return {"out": c["out"], "ok": ok, "skip": skip, "fail": fail,
            "total": len(manifest)}


def main():
    print("下载真实 Skill 语料（仅静态分析，不执行任何样本内容）")
    print(f"工作目录：{os.path.join(BASE, 'real_corpus')}")
    results = []
    for c in CORPORA:
        try:
            results.append(fetch_corpus(c))
        except KeyboardInterrupt:
            print("\n  已中断（已下载的文件保留，可再次运行续传）")
            break
        except Exception as e:
            print(f"  [异常] {c['out']}: {type(e).__name__} {e}")
            results.append({"out": c["out"], "ok": 0, "fail": 0, "total": 0})

    print(f"\n{'=' * 72}")
    print("汇总")
    print("=" * 72)
    for r in results:
        print(f"  {r['out']:22s} 共 {r.get('total', 0):4d} 个"
              f"（新下载 {r.get('ok', 0)}，失败 {r.get('fail', 0)}）")
    print()
    print("下一步：运行 samples/run_corpus_eval.py 计算真实检出率与误报率")
    print("=" * 72)


if __name__ == "__main__":
    main()