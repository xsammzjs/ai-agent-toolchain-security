# -*- coding: utf-8 -*-
"""校验文档里引用的 `文件路径:行号` 是否仍然指向正确的符号。

背景：重构拆分文件后，文档里的行号引用会悄悄失效 ——
老师/评委按文档去翻代码却对不上，材料可信度直接受损。

用法：
    python samples/check_code_refs.py
退出码非 0 表示有失效引用。
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 文档范围
DOCS = [
    "README.md",
    "docs/项目讲解手册.md",
    "docs/作品报告.md",
    "docs/项目说明书.md",
    "docs/模板1填写对照表.md",
    "docs/发给老师的说明.md",
    "docs/项目学习材料.md",
    "docs/项目实况理解.md",
    "docs/汇报前最小清单.md",
    "docs/CodeArts审计实践.md",
    "docs/汇报话术一页卡.md",
]

# 匹配形如 `path/to/file.py:123` 或 `file.py:123` 的引用
# 第二个捕获组是符号名（如 evaluate_confidence:389）
REF_RE = re.compile(
    r"`?([A-Za-z0-9_./\\-]+\.py):(\d+)`?"
    r"(?:\s*`?([A-Za-z_][A-Za-z0-9_]*)`?)?"
)

# 匹配形如 `symbol_name:123` 的裸引用（不知道在哪个文件，需要全仓库找）
SYMBOL_REF_RE = re.compile(r"`([A-Za-z_][A-Za-z0-9_]*):(\d+)`")

# 全仓库源码（用于裸符号查找）
SRC_ROOTS = ["modules", "views", "samples", "tests", "."]
SKIP_DIRS = {".git", ".venv", ".workbuddy", "samples/real_corpus", "temp_shots",
             "data_store", "trivy_cache", "temp_upload", "docs"}


def collect_symbols():
    """扫描全仓库，建立 符号名 -> [(文件, 真实行号)] 索引"""
    index = {}
    for root in SRC_ROOTS:
        base = os.path.join(ROOT, root)
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            rel_dir = os.path.relpath(dirpath, ROOT).replace("\\", "/")
            if any(rel_dir == s or rel_dir.startswith(s + "/") for s in SKIP_DIRS):
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames
                           if not any((rel_dir + "/" + d) == s or
                                      (rel_dir + "/" + d).startswith(s + "/")
                                      for s in SKIP_DIRS)]
            for fn in filenames:
                if not fn.endswith(".py"):
                    continue
                fp = os.path.join(dirpath, fn)
                try:
                    with open(fp, encoding="utf-8", errors="ignore") as f:
                        for n, line in enumerate(f, 1):
                            st = line.strip()
                            if st.startswith(("def ", "class ", "async def ")):
                                name = st.split("(")[0].replace("def ", "") \
                                         .replace("class ", "").replace("async ", "").strip()
                                if name and name[0].isalpha() or name.startswith("_"):
                                    index.setdefault(name, []).append((fp, n))
                            elif st.startswith(("RULE_TABLE", "PARSER_MAP", "CAPABILITY_MAP",
                                                "CHAIN_TEMPLATES", "NODE_TYPES",
                                                "EDGE_TYPES", "SEV_COLOR")) and "=" in st:
                                name = st.split("=")[0].strip()
                                index.setdefault(name, []).append((fp, n))
                except OSError:
                    continue
    return index

# 允许跨平台路径分隔符
def norm(p: str) -> str:
    return p.replace("\\", "/")


def resolve(path: str) -> str | None:
    """把文档里的路径解析成仓库内的绝对路径"""
    path = norm(path)
    cands = [path, os.path.join("modules", path), os.path.join("views", path),
             os.path.join("samples", path), os.path.join("tests", path)]
    for c in cands:
        full = os.path.join(ROOT, c)
        if os.path.isfile(full):
            return full
    return None


def main() -> int:
    bad = []
    checked = 0
    symbol_index = collect_symbols()

    for rel in DOCS:
        p = os.path.join(ROOT, rel)
        if not os.path.isfile(p):
            continue
        with open(p, encoding="utf-8") as f:
            lines = f.read().split("\n")
        for i, line in enumerate(lines, 1):
            for m in REF_RE.finditer(line):
                raw_path, lineno, symbol = m.group(1), int(m.group(2)), m.group(3)
                # 跳过明显不是代码引用的
                if "/" in raw_path and not raw_path.endswith(".py"):
                    continue
                full = resolve(raw_path)
                if full is None:
                    continue          # 引用了不存在的文件 —— 单独报告
                checked += 1
                with open(full, encoding="utf-8", errors="ignore") as f:
                    content = f.read().split("\n")
                if lineno > len(content):
                    bad.append(f"{rel}:{i}  {raw_path}:{lineno}  行号超出文件范围"
                               f"（实际 {len(content)} 行）")
                    continue
                if symbol:
                    # 符号名必须在该行附近出现（±3 行，允许装饰器/多行签名）
                    window = "\n".join(content[max(0, lineno - 4):lineno + 3])
                    if symbol not in window:
                        bad.append(f"{rel}:{i}  {raw_path}:{lineno}  "
                                   f"该处附近没有 `{symbol}`（可能行号已漂移）")

            # 裸符号引用 `symbol:123`
            for m in SYMBOL_REF_RE.finditer(line):
                symbol, lineno = m.group(1), int(m.group(2))
                if symbol not in symbol_index:
                    continue          # 不是代码符号（如 "1:30" 之类）
                checked += 1
                hits = symbol_index[symbol]
                if not any(abs(n - lineno) <= 3 for _, n in hits):
                    where = ", ".join(f"{os.path.relpath(fp, ROOT)}:{n}"
                                      for fp, n in hits[:3])
                    bad.append(f"{rel}:{i}  `{symbol}:{lineno}`  "
                               f"实际在 {where}（行号已漂移）")

    print("=" * 70)
    print("文档代码引用校验")
    print("=" * 70)
    print(f"检查了 {checked} 处代码引用（{len(DOCS)} 份文档）\n")
    if bad:
        print(f"🔴 发现 {len(bad)} 处失效引用：\n")
        for b in bad:
            print("  " + b)
        print("\n  修法：打开对应文件找到符号的真实行号，替换文档里的数字。")
        return 1
    print("✅ 全部引用有效")
    return 0


if __name__ == "__main__":
    sys.exit(main())
