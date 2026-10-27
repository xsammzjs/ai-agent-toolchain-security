# -*- coding: utf-8 -*-
"""views 包：Streamlit 的五个功能视图。

每个视图一个模块，main.py 只负责入口与路由。
拆分的目的是让每个文件都保持在可读规模（75-400 行），
而不是把近 2000 行 UI 全堆在一个文件里。

五个视图与 main.py 侧边栏的对应关系（顺序即侧边栏顺序）：
    1. skill_scan.py  🛡️ AI 技能安全检测（规则快筛的证据页）
    2. combo_view.py  🧬 组合体检（★主线：三段式流水线）
    3. dep_scan.py    📦 依赖漏洞检测（+ dep_tabs.py 渲染四个 tab）
    4. chain_view.py  🔗 资产关联分析
    5. demo_view.py   🎬 离线演示
    common.py 为共享组件与工具，不算功能视图。
"""
