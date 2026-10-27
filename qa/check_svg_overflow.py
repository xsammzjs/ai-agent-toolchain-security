"""校验 SVG：XML 合法性 + 四类几何缺陷。

四项检查（每项都会报出问题并让退出码置 1）：
  ① text 超出 viewBox（画布）
  ② text 越过「逻辑所在框」的边线（正文/标注跑出自己那个盒子）
  ③ text 与 text 互相压字（y 方向重叠 ≥ 30% × 较小字号）
  ④ 连线（<line>）被后画的不透明矩形盖住而消失

【守卫设计的核心原则】用结果判，不用位置猜
------------------------------------------------
「边注」不是缺陷的判据，「边注造成压字」才是。

2026-10-28 之前，本脚本用「锚点是否落在框的右侧 15%」来区分「边注标注」
与「正文越框」——结果它**豁免的正是肇事者**：04 图里那 5 条灰色代码引用标注
（锚点全在 x=660）本就越框 + 压正文，却因为落在豁免区而全部被放过，
于是守卫对一张肉眼可见有 2 处压字的图报 RESULT: PASS —— 制造假安全感。
而且同一段溢出文本，锚点 615 报、620 不报，1px 的位移就能翻转结论。

现在改成**用结果判**：
  · ② 用「锚点落在哪个最小非背景框里」定位逻辑所在框，看文字有没有越过它的边线；
  · ③ 直接量文字与文字的实际重叠面积占比。
两者都不需要猜意图，也就不需要豁免。

【字符宽度模型的标定】
------------------------------------------------
text_width() 用的是**估算模型**（脚本要保持零第三方依赖，不能靠浏览器）。
这组系数不是拍脑袋，是用 headless Edge 的 `getComputedTextLength()`
对 6 张图全部 280 条 text 实测后最小二乘标定出来的：
  相对误差 平均 3.3% / 最大 24.9%（标定前是 平均 3.6% / 最大 30.0%）。
关键的一条是 **lower 0.4985**（原 0.55）—— 小写字母原来被高估最多，
正是 04 图那批代码标注（detect_vulnerabilities_concurrent() 等）被算宽的原因。
判据阈值都按「相对字号的比例」定，不贴着估算误差走。
"""
import sys
import unicodedata
import xml.etree.ElementTree as ET

SVG_NS = "{http://www.w3.org/2000/svg}"

# 箭头 marker 的高度约 9、锚点在连线端点 → 端点外扩约 3.5px，取 4 保守
MARKER_EXT = 4.0
# 连线被后画矩形遮住 ≥ 这个比例就算「视觉上消失」
OCCLUSION_THRESHOLD = 0.90
# 两段文字 y 方向重叠 ≥ 较小字号的这个比例，就算「真的压字了」
# （标定：≥10% ~ ≥50% 结果完全稳定，都是 04 那 2 处真碰撞；
#   03 那对 y 重叠仅 5.6%、04 那两对上下错开的 10.0%/9.2% 都被正确排除）
TEXT_OVERLAP_THRESHOLD = 0.30

FIGS = [
    # 现行口径图（对外材料用）
    "docs/figures/05_三段式流水线架构图.svg",
    "docs/figures/06_组合风险原理图.svg",
    # 🔴 2026-10-28：旧口径存档图（01~04）也纳入检查。
    #    这 4 张图从 2026-10-28 起在 SVG 内部加了存档水印
    #    「⚠️ 旧口径存档图 · 仅供对照 · 不得插入对外材料」，
    #    水印是 <text> 元素，同样可能溢出 viewBox —— 只检查 05/06 的话，
    #    水印写坏了也不会有人发现（守卫有盲区）。
    "docs/figures/01_系统架构图.svg",
    "docs/figures/02_攻击链原理图.svg",
    "docs/figures/03_资产图谱示意图.svg",
    "docs/figures/04_扫描流程图.svg",
]

# 字符宽度系数（单位：× font-size），由浏览器 getComputedTextLength() 标定
_CHAR_WIDTH = {
    "cjk": 1.0056,     # 全角/宽字符（含中文、全角标点）
    "space": 0.3784,
    "digit": 0.5788,
    "upper": 0.6340,
    "lower": 0.4985,
    "punct": 0.3885,
}


def _char_class(ch: str) -> str:
    """把字符分到 6 类宽度系数里。"""
    if unicodedata.east_asian_width(ch) in ("W", "F"):
        return "cjk"
    if ch == " ":
        return "space"
    if ch.isdigit():
        return "digit"
    if ch.isupper():
        return "upper"
    if ch.islower():
        return "lower"
    return "punct"


def char_width(ch: str) -> float:
    """估算字符宽度（以 font-size 为单位的倍数）。

    系数由 headless Edge 的 getComputedTextLength() 对 6 张图全部 280 条
    text 实测后最小二乘标定（相对误差 平均 3.3% / 最大 24.9%）。
    """
    return _CHAR_WIDTH[_char_class(ch)]


def text_width(text: str, font_size: float) -> float:
    return sum(char_width(c) for c in text) * font_size


def _logical_box(rects, tx, ty):
    """找出锚点 (tx, ty) 落在的**最小非背景矩形**（文本的逻辑所在框）。

    背景（整幅画布）不参与：任何画布内的锚点都会落进背景，
    那样就分不出文本「属于哪个盒子」了。找不到就是不属于任何框，返回 None。
    """
    cands = [r for r in rects
             if r[4] != "#bg" and r[0] <= tx < r[0] + r[2] and r[1] <= ty < r[1] + r[3]]
    if not cands:
        return None
    b = min(cands, key=lambda r: r[2] * r[3])
    return (b[0], b[1], b[2], b[3])


def _text_boxes(root):
    """取出所有 <text> 的包围盒与元信息，供 ② ③ 两项检查共用。"""
    out = []
    for t in root.iter(SVG_NS + "text"):
        content = "".join(t.itertext()).strip()
        if not content:
            continue
        try:
            tx = float(t.get("x", 0))
            ty = float(t.get("y", 0))
        except ValueError:
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
        out.append({
            "text": content, "tx": tx, "ty": ty, "fs": fs,
            "x0": x0, "x1": x1,
            "y0": ty - fs * 0.85, "y1": ty + fs * 0.25,
        })
    return out


def check_out_of_box(texts, rects) -> list:
    """② 检查文字是否越过「逻辑所在框」的边线。

    语义：**锚点落在某个框里**（说明它「属于」这个框），但文字本身伸出了
    那个框的边线 → 报。锚点不落在任何框里的文字（05/06 那种故意放在框外的
    支线说明、图例）不属于任何框，不按越框处理。

    ⚠️ 背景整幅画布**不参与**归属判定。它只参与 ① 的 viewBox 检查。
    （早期版本把背景也当候选容器，于是任何画布内的文字都能被它「包含」，
      越框检测形同虚设 —— 这正是 04 图那批文字缺陷长期存活的原因。）
    """
    problems = []
    for t in texts:
        box = _logical_box(rects, t["tx"], t["ty"])
        if box is None:
            continue
        lx, ly, lw, lh = box
        over_r = t["x1"] - (lx + lw)
        over_l = lx - t["x0"]
        if over_r > 1.0:
            problems.append(
                f"文字越过所在框的右边线: {t['text']!r} 右端 {t['x1']:.1f} 越过 "
                f"{lx + lw:.1f} 达 {over_r:.1f}px "
                f"(框 x=[{lx:.1f},{lx + lw:.1f}] y=[{ly:.1f},{ly + lh:.1f}])"
            )
        if over_l > 1.0:
            problems.append(
                f"文字越过所在框的左边线: {t['text']!r} 左端 {t['x0']:.1f} 越过 "
                f"{lx:.1f} 达 {over_l:.1f}px "
                f"(框 x=[{lx:.1f},{lx + lw:.1f}] y=[{ly:.1f},{ly + lh:.1f}])"
            )
    return problems


def check_text_overlap(texts) -> list:
    """③ 检查两段文字是否真的「压字」。

    判据：x 方向有重叠，且 **y 方向重叠 ≥ 较小字号的 30%**。
    用相对字号的比例而不是绝对像素，是因为估算模型有百分之几的误差，
    绝对阈值会紧贴误差边界（实测同一对文字用绝对阈值会在 0.5px/0.9px 上误报）。

    这项检查**不需要任何豁免**：它量的是「结果」（有没有真的压在一起），
    而不是「位置像不像边注」。
    """
    problems = []
    for i in range(len(texts)):
        for j in range(i + 1, len(texts)):
            a, b = texts[i], texts[j]
            ox = min(a["x1"], b["x1"]) - max(a["x0"], b["x0"])
            oy = min(a["y1"], b["y1"]) - max(a["y0"], b["y0"])
            if ox <= 0 or oy <= 0:
                continue
            smaller = min(a["fs"], b["fs"])
            ratio = oy / smaller
            if ratio >= TEXT_OVERLAP_THRESHOLD:
                problems.append(
                    f"文字互相压字: {a['text']!r} × {b['text']!r} "
                    f"(x 重叠 {ox:.1f}px, y 重叠 {oy:.1f}px = 较小字号的 {ratio * 100:.0f}%)"
                )
    return problems


def check_occlusion(root, vb) -> list:
    """④ 检查连线（<line>）是否被**后画的不透明矩形**遮住而消失。

    🔴 2026-10-28 新增（QA 复验发现）：前几项检查只看「text vs viewBox /
    text vs rect / text vs text」，**查不出元素之间的遮挡**。于是出现过一次
    真实回归：04_扫描流程图 里 ⑥ 产出盒从 y=446 上移到 y=424 后，⑤→⑥ 的
    连接箭头正好落在盒子范围内，而盒子是不透明填充、排在 line 之后 →
    箭头被整个盖住，渲染出来两盒直接贴在一起、「箭头消失」。
    当时本脚本报的是 RESULT: PASS —— 守卫有盲区。

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
    # 背景整幅画布视作可容纳区域（只参与 viewBox 判定，不参与「属于哪个框」）
    rects.append((vx, vy, vw, vh, "#bg"))

    texts = _text_boxes(root)
    print(f"text 元素数 = {len(texts)}, rect 元素数 = {len(rects) - 1}")

    problems = []

    # ① text 是否超出 viewBox
    for t in texts:
        if t["x0"] < vx - 0.5 or t["x1"] > vx + vw + 0.5:
            problems.append(
                f"超出 viewBox 水平范围: {t['text']!r} "
                f"x=[{t['x0']:.1f},{t['x1']:.1f}] (允许 {vx}..{vx + vw})"
            )
        if t["y0"] < vy - 0.5 or t["y1"] > vy + vh + 0.5:
            problems.append(
                f"超出 viewBox 垂直范围: {t['text']!r} "
                f"y=[{t['y0']:.1f},{t['y1']:.1f}] (允许 {vy}..{vy + vh})"
            )

    problems.extend(check_out_of_box(texts, rects))
    problems.extend(check_text_overlap(texts))
    problems.extend(check_occlusion(root, vb))

    if problems:
        ok = False
        print(f"发现 {len(problems)} 个问题:")
        for p in problems:
            print("  - " + p)
    else:
        print("检查通过：无 text 越界 / 无文字越框 / 无文字压字 / 无连线被遮挡")
    return ok


if __name__ == "__main__":
    # 🔴 2026-10-28：每张图**独立** try/except。
    #    原来写的是 `all_ok = check(f) and all_ok` —— check(f) 一旦抛异常，
    #    整个 for 循环中断，**后面的图一张都不会被检查**。
    #    FIGS 顺序是 [05,06,01,02,03,04]，04 在最后所以暂时没掩盖别的图；
    #    但 05/06 一旦出同类崩溃，01~04 就完全失去检查。
    #    现在某张图抛异常 → 记为该图 FAIL → 打印清楚是哪张图、什么异常 →
    #    继续检查下一张；所有图跑完后统一汇总。
    results = []
    all_ok = True          # 先初始化，避免 `and` 短路时未绑定（NameError）
    for f in FIGS:
        try:
            ok = check(f)
        except Exception as e:                       # noqa: BLE001
            ok = False
            print(f"\n=== {f} ===")
            print(f"  ❌ 检查过程中抛出异常：{type(e).__name__}: {e}")
            print("  （该图判定为 FAIL，继续检查后面的图）")
        results.append((f, ok))
        all_ok = all_ok and ok

    print("\n" + "=" * 76)
    print("逐图结果：")
    for f, ok in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {f}")
    print("\nRESULT:", "PASS" if all_ok else "FAIL")
    sys.exit(0 if all_ok else 1)
