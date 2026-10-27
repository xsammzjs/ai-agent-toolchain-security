"""校验 SVG：XML 合法性 + text 坐标是否超出 viewBox + 文本估算宽度是否超出所在矩形。"""
import re
import sys
import unicodedata
import xml.etree.ElementTree as ET

SVG_NS = "{http://www.w3.org/2000/svg}"
FIGS = [
    # 现行口径图（对外材料用）
    "docs/figures/05_三段式流水线架构图.svg",
    "docs/figures/06_组合风险原理图.svg",
    # 🔴 2026-10-28：旧口径存档图（01~04）也纳入检查。
    #    这 4 张图从 2026-10-28 起在 SVG 内部加了存档水印
    #    「⚠️ 旧口径存档图 · 仅供对照 · 不得插入对外材料」，
    #    水印是 <text> 元素，同样可能溢出 viewBox —— 只检查 05/06 的话，
    #    水印写坏了也不会有人发现（守卫有盲区）。
    #    同时它们各自带一个**先前就存在**的越界文本（见 04 的「SBOM · …」行，
    #    原文 y=486 而 viewBox 高 480，渲染时会被裁掉），一并修正。
    "docs/figures/01_系统架构图.svg",
    "docs/figures/02_攻击链原理图.svg",
    "docs/figures/03_资产图谱示意图.svg",
    "docs/figures/04_扫描流程图.svg",
]


def char_width(ch: str) -> float:
    """估算字符宽度（以 font-size 为单位的倍数）。"""
    if unicodedata.east_asian_width(ch) in ("W", "F"):
        return 1.0
    if ch == " ":
        return 0.30
    if ch in ".,:;'|!":
        return 0.28
    if ch.isdigit():
        return 0.55
    if ch.isupper():
        return 0.66
    return 0.55


def text_width(text: str, font_size: float) -> float:
    return sum(char_width(c) for c in text) * font_size


def check(path: str) -> bool:
    ok = True
    tree = ET.parse(path)
    root = tree.getroot()
    vb = [float(v) for v in root.get("viewBox").split()]
    vx, vy, vw, vh = vb
    print(f"\n=== {path} ===")
    print(f"viewBox = {vb}  width={root.get('width')} height={root.get('height')}")

    # 收集所有矩形（含 <rect> 与嵌套），供 text 归属判定
    rects = []
    for el in root.iter():
        if el.tag == SVG_NS + "rect":
            try:
                rx = float(el.get("x", 0))
                ry = float(el.get("y", 0))
                rw = float(el.get("width", 0))
                rh = float(el.get("height", 0))
            except ValueError:
                continue
            rects.append((rx, ry, rw, rh, el.get("fill", "")))
    # 背景整幅画布视作可容纳区域
    rects.append((vx, vy, vw, vh, "#bg"))

    texts = list(root.iter(SVG_NS + "text"))
    print(f"text 元素数 = {len(texts)}, rect 元素数 = {len(rects) - 1}")

    problems = []
    for t in texts:
        content = "".join(t.itertext()).strip()
        if not content:
            continue
        try:
            tx = float(t.get("x", 0))
            ty = float(t.get("y", 0))
        except ValueError:
            problems.append(f"坐标非法: {content!r}")
            continue
        fs = float(t.get("font-size", 12))
        anchor = t.get("text-anchor", "start")
        w = text_width(content, fs)
        if anchor == "middle":
            x0, x1 = tx - w / 2, tx + w / 2
        elif anchor == "end":
            x0, x1 = tx - w, tx
        else:
            x0, x1 = tx, tx + w
        y0, y1 = ty - fs * 0.85, ty + fs * 0.25

        # 1) 是否超出 viewBox
        if x0 < vx - 0.5 or x1 > vx + vw + 0.5:
            problems.append(
                f"超出 viewBox 水平范围: {content!r} x=[{x0:.1f},{x1:.1f}] (允许 {vx}..{vx+vw})"
            )
        if y0 < vy - 0.5 or y1 > vy + vh + 0.5:
            problems.append(
                f"超出 viewBox 垂直范围: {content!r} y=[{y0:.1f},{y1:.1f}] (允许 {vy}..{vy+vh})"
            )

        # 2) 是否溢出其所属矩形（找所有能"合理包含"该文本的矩形，取最紧的一个）
        best = None
        for rx, ry, rw, rh, fill in rects:
            if rx <= x0 + 1 and x1 <= rx + rw - 1 and ry <= y0 + 1 and y1 <= ry + rh - 1:
                area = rw * rh
                if best is None or area < best[0]:
                    best = (area, rx, ry, rw, rh, fill)
        # 未找到容纳矩形时，退而检查是否与某个矩形明显相交
        if best is None:
            for rx, ry, rw, rh, fill in rects:
                if rx <= x0 < rx + rw and ry <= ty < ry + rh:
                    over = max(0.0, (x1 - (rx + rw)))
                    if over > 1.0:
                        problems.append(
                            f"文本疑似溢出矩形: {content!r} 右溢出 {over:.1f}px "
                            f"(rect x={rx} w={rw}, 文本 x=[{x0:.1f},{x1:.1f}])"
                        )
                    break
    if problems:
        ok = False
        print(f"发现 {len(problems)} 个问题:")
        for p in problems:
            print("  - " + p)
    else:
        print("检查通过：无 text 越界 / 无文本溢出")
    return ok


if __name__ == "__main__":
    all_ok = True
    for f in FIGS:
        all_ok = check(f) and all_ok
    print("\nRESULT:", "PASS" if all_ok else "FAIL")
    sys.exit(0 if all_ok else 1)
