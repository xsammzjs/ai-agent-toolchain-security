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
                   color=_NODE_COLOR.get(n.get("node_type"), "#8395a8"))
    for e in edges:
        if G.has_node(e.get("src")) and G.has_node(e.get("dst")):
            G.add_edge(e["src"], e["dst"], relation=e.get("relation", ""))
    if G.number_of_nodes() == 0:
        return None

    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fig, ax = plt.subplots(figsize=(11, 7))
    pos = nx.spring_layout(G, seed=42, k=0.9)
    ncolors = [G.nodes[n].get("color", "#8395a8") for n in G.nodes]
    nx.draw_networkx_edges(G, pos, ax=ax, edge_color="#c7d7fe",
                           arrows=True, arrowsize=8, width=0.8)
    nx.draw_networkx_nodes(G, pos, ax=ax, node_color=ncolors, node_size=200,
                           edgecolors="#ffffff", linewidths=0.6)
    labels = {n: G.nodes[n].get("name", "")[:14] for n in G.nodes}
    nx.draw_networkx_labels(G, pos, labels=labels, ax=ax, font_size=7,
                            font_color="#16202e")
    ax.set_axis_off()
    fig.tight_layout()
    try:
        fig.savefig(path, format="svg", bbox_inches="tight", transparent=True)
    finally:
        plt.close(fig)
    return path