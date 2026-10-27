"""校验 SVG：XML 合法性 + text 坐标是否超出 viewBox + 文本估算宽度是否超出所在矩形。"""
import re
import sys
import unicodedata
import xml.etree.ElementTree as ET

SVG_NS = "{http://www.w3.org/2000/svg}"
# 箭头 marker 的高度约 9、锚点在连线端点 → 端点外扩约 3.5px，取 4 保守
MARKER_EXT = 4.0
# 连线被后画矩形遮住 ≥ 这个比例就算「视觉上消失」
OCCLUSION_THRESHOLD = 0.90
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

    problems.extend(check_occlusion(root, vb))
    if problems:
        ok = False
        print(f"发现 {len(problems)} 个问题:")
        for p in problems:
            print("  - " + p)
    else:
        print("检查通过：无 text 越界 / 无文本溢出 / 无连线被遮挡")
    return ok


def check_occlusion(root, vb) -> list:
    """检查连线（<line>）是否被**后画的不透明矩形**遮住而消失。

    🔴 2026-10-28 新增（QA 复验发现）：前两项检查只看「text vs viewBox /
    text vs rect」，**查不出元素之间的遮挡**。于是出现过一次真实回归：
    04_扫描流程图 里 ⑥ 产出盒从 y=446 上移到 y=424 后，⑤→⑥ 的连接箭头
    （<line y1=424 y2=444>）正好落在盒子范围内，而盒子是不透明填充、
    又排在 line 之后 → 箭头被整个盖住，渲染出来两盒直接贴在一起，
    「箭头消失」。当时 check_svg_overflow.py 报的是 RESULT: PASS
    —— 守卫有盲区。

    判据：把连线算成细长 bbox（含描边宽度与箭头 marker 的外扩量），
    若某个**在它之后绘制**的矩形（背景整幅除外）盖住了它 bbox 面积的
    ≥90%，视觉上这条连线已经消失 → 报错。

    阈值 90% 而非 100%：线宽与 marker 的实际外扩量是估出来的，
    要求「完全包含」会因为 1px 的计算误差漏判（实测回归场景覆盖率是 96%，
    而线顶有约 1px 露在盒子外面，严格包含会判成「没被盖住」）。
    """
    problems = []
    order = list(root.iter())
    idx = {id(el): i for i, el in enumerate(order)}
    for el in root.iter(SVG_NS + "line"):
        x1, y1 = float(el.get("x1", 0)), float(el.get("y1", 0))
        x2, y2 = float(el.get("x2", 0)), float(el.get("y2", 0))
        sw = float(el.get("stroke-width", 1.0))
        ext = MARKER_EXT if el.get("marker-end") else 0.0
        bx0, bx1 = min(x1, x2) - sw / 2, max(x1, x2) + sw / 2
        by0, by1 = min(y1, y2) - sw / 2, max(y1, y2) + sw / 2 + ext
        area = max(1e-9, (bx1 - bx0) * (by1 - by0))
        for r in root.iter(SVG_NS + "rect"):
            rx = float(r.get("x", 0))
            ry = float(r.get("y", 0))
            rw = float(r.get("width", 0))
            rh = float(r.get("height", 0))
            if rx == 0 and ry == 0 and rw == vb[2] and rh == vb[3]:
                continue                       # 整幅背景
            if idx[id(r)] <= idx[id(el)]:
                continue                       # 画在连线之前，不遮挡
            ox = max(0.0, min(bx1, rx + rw) - max(bx0, rx))
            oy = max(0.0, min(by1, ry + rh) - max(by0, ry))
            ratio = (ox * oy) / area
            if ratio >= OCCLUSION_THRESHOLD:
                problems.append(
                    f"连线被矩形遮挡（视觉上已消失）: "
                    f"line({x1:.0f},{y1:.0f}→{x2:.0f},{y2:.0f}) 被 "
                    f"rect(x={rx:.0f} y={ry:.0f} w={rw:.0f} h={rh:.0f}) "
                    f"遮住 {ratio * 100:.0f}%"
                )
    return problems


if __name__ == "__main__":
    all_ok = True
    for f in FIGS:
        all_ok = check(f) and all_ok
    print("\nRESULT:", "PASS" if all_ok else "FAIL")
    sys.exit(0 if all_ok else 1)
