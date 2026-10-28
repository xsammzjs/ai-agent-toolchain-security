# -*- coding: utf-8 -*-
"""views 包：首页 + 离线演示 + 主题；其余历史视图已删除。

当前界面只有一个入口：main.py → overview.render()（首页）。
    1. overview.py    🏠 首页「一键体检」：上传 → 结论卡 → 数据看板
                      → 标签页（总览 / 关系图 / 依赖漏洞 / 合规对照）
    2. combo_view.py  首页流水线（规则 → AI → 组合 → 依赖）与内置示例的底层实现
    3. demo_view.py   🎬 离线演示（首页底部「断网备用」展开区调用）
    4. common.py      共享组件与工具
    5. theme.py       统一视觉主题（浅色 · 简洁商务风）

说明：首页改版时已删除旧的独立视图 skill_scan / dep_scan / dep_tabs /
chain_view，其能力（单点规则、依赖漏洞四源、资产关系图）全部并入首页。
"""