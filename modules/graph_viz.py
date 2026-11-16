# -*- coding: utf-8 -*-
"""风险关系图可视化（资产关系视图）。

把 modules/asset_graph.build_graph() 的 {nodes, edges} 渲染为：
  · 交互版：networkx → pyvis → HTML 片段（Streamlit 内嵌）
  · 静态版：networkx → matplotlib → SVG（供 PPT / 录屏引用）

措辞纪律：全篇用「关系图 / 资产关系视图 / 节点 / 边」，
不出现「图计算 / 图神经网络 / GNN / 图算法」。
缺库时优雅降级（返回 None），不阻断主流程。
"""
from __future__ import annotations

import os

# 节点类型 → 填充色（与 main.py 主题一致）
_NODE_COLOR = {"依赖": "#2563eb", "技能": "#7c3aed", "工具": "#059669"}
# 严重度 → 描边色（语义色）
_SEV_RING = {"严重": "#e11d48", "高危": "#d97706", "中危": "#f59e0b",
             "低危": "#059669", "安全": "#8395a8"}
# 边关系 → 颜色
_EDGE_COLOR = {"依赖": "#c7d7fe", "调用": "#f59e0b", "引用": "#e2e8f0", "共用": "#a7f3d0"}


def to_pyvis_html(graph: dict, height: int = 540) -> str | None:
    """交互版：把 {nodes, edges} 渲染成 pyvis HTML。缺 pyvis 时返回 None。"""
    try:
        from pyvis.network import Network
    except Exception:
        return None

    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    if not nodes:
        return None

    net = Network(height=f"{height}px", width="100%", bgcolor="#f7f9fc",
                  font_color="#16202e", directed=False, cdn_resources="in_line")
    ids = set()
    for n in nodes:
        ids.add(n["node_id"])
        net.add_node(
            n["node_id"],
            label=str(n.get("name", "")),
            title=(f"{n.get('node_type', '')}｜{n.get('severity', '')}"
                   f"｜风险点 {n.get('risk_count', 0)}"),
            color={"background": _NODE_COLOR.get(n.get("node_type"), "#8395a8"),
                   "border": _SEV_RING.get(n.get("severity"), "#8395a8")},
            borderWidth=2,
            shape="dot",
            size=14 + 3 * int(n.get("risk_count", 0) or 0),
        )
    for e in edges:
        if e.get("src") in ids and e.get("dst") in ids:
            net.add_edge(e["src"], e["dst"],
                         color=_EDGE_COLOR.get(e.get("relation"), "#dfe6ef"),
                         title=str(e.get("relation", "")), width=1.2)
    try:
        return net.generate_html()
    except Exception:
        return getattr(net, "html", None)


def _layout(G):
    """节点布局。

    目标：静态图与网页端的可交互图（pyvis）视觉一致——**每个技能自己成一簇**，
    它的依赖围着它，不同技能互不干扰。

    - 节点少（≤8）：按类型分层（技能 / 依赖 / 工具 各占一列），最紧凑易读；
    - 节点多：按**连通分量**分簇——每个「技能 + 它的依赖」是一个独立分量，
      簇内用 spring_layout，簇与簇横向排开。
      （全局 spring_layout 会把所有叶子甩到四周、不同技能的依赖混在一起，
        与 pyvis 的分簇效果不一致。）
    """
    import networkx as nx
    n = G.number_of_nodes()
    if n <= 8:
        order = ["技能", "依赖", "工具", "其他"]
        layers = {}
        for node in G.nodes:
            t = G.nodes[node].get("node_type", "其他")
            layers.setdefault(t, []).append(node)
        keys = [k for k in order if k in layers] + [k for k in layers if k not in order]
        ncol = max(1, len(keys))
        pos = {}
        for ci, key in enumerate(keys):
            members = layers[key]
            x = (ci / (ncol - 1)) if ncol > 1 else 0.5
            cnt = len(members)
            for i, node in enumerate(members):
                y = 1 - (i + 1) / (cnt + 1)
                pos[node] = (x, y)
        return pos

    # 节点多：按连通分量分簇（技能 + 它的依赖 = 一个簇）
    und = G.to_undirected()
    comps = list(nx.connected_components(und))
    comps.sort(key=len, reverse=True)
    pos = {}
    gap = 1.9           # 簇间距（要放得开，避免相邻簇的标签互相压盖）
    span = 0.8          # 单簇归一化后的宽度
    per_row = 3 if len(comps) > 4 else len(comps)
    for idx, comp in enumerate(comps):
        sub = G.subgraph(comp)
        if sub.number_of_nodes() == 1:
            local = {list(comp)[0]: (0.0, 0.0)}
        else:
            # k 调大 → 簇内斥力增强、节点散得更开，标签不易重叠
            local = nx.spring_layout(sub, seed=42, k=1.25)
        xs = [float(v[0]) for v in local.values()]
        ys = [float(v[1]) for v in local.values()]
        cx = (min(xs) + max(xs)) / 2.0
        cy = (min(ys) + max(ys)) / 2.0
        w = max(1e-6, max(xs) - min(xs))
        h = max(1e-6, max(ys) - min(ys))
        row, col = divmod(idx, per_row)
        off_x = col * gap
        off_y = -row * gap
        for node, (x, y) in local.items():
            pos[node] = (off_x + (float(x) - cx) / w * span,
                         off_y + (float(y) - cy) / h * span)
    return pos


def to_static_svg(graph: dict, path: str) -> str | None:
    """静态版：把 {nodes, edges} 渲染成 SVG 文件。缺 matplotlib/networkx 返回 None。"""
    try:
        import networkx as nx
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        matplotlib.rcParams["font.sans-serif"] = ["Microsoft YaHei"]
        matplotlib.rcParams["axes.unicode_minus"] = False
    except Exception:
        return None

    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    if not nodes:
        return None

    G = nx.DiGraph()
    for n in nodes:
        G.add_node(n["node_id"], name=str(n.get("name", "")),
                   node_type=str(n.get("node_type", "其他")),
                   color=_NODE_COLOR.get(n.get("node_type"), "#8395a8"))
    for e in edges:
        if G.has_node(e.get("src")) and G.has_node(e.get("dst")):
            G.add_edge(e["src"], e["dst"], relation=e.get("relation", ""))
    if G.number_of_nodes() == 0:
        return None

    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fig, ax = plt.subplots(figsize=(11, 7))
    pos = _layout(G)
    ncolors = [G.nodes[n].get("color", "#8395a8") for n in G.nodes]
    nx.draw_networkx_edges(G, pos, ax=ax, edge_color="#c7d7fe",
                           arrows=True, arrowsize=8, width=0.8)
    nx.draw_networkx_nodes(G, pos, ax=ax, node_color=ncolors, node_size=200,
                           edgecolors="#ffffff", linewidths=0.6)
    # 标签手工绘制并上移一点（networkx 的 draw_networkx_labels 不支持 label_pos，
    # 且默认会把文字压在节点圆点正中）——白底保证与连线重叠时仍可读
    for n in pos:
        nx_, ny_ = pos[n]
        ax.text(nx_, ny_ + 0.055, G.nodes[n].get("name", "")[:14],
                fontsize=7.5, color="#16202e", ha="center", va="bottom",
                bbox=dict(facecolor="white", edgecolor="none", alpha=0.92, pad=0.6))
    ax.set_axis_off()
    if pos:
        xs = [float(v[0]) for v in pos.values()]
        ys = [float(v[1]) for v in pos.values()]
        pad = 0.22
        ax.set_xlim(min(xs) - pad, max(xs) + pad)
        ax.set_ylim(min(ys) - pad, max(ys) + pad)
    fig.tight_layout()
    try:
        fig.savefig(path, format="svg", bbox_inches="tight", transparent=True)
    finally:
        plt.close(fig)
    return path