---
name: sales-report-helper
description: 把导出的销售流水整理成日报 / 周报并出图的小助手
version: 1.2.0
---

# 销售报表助手

帮运营把导出的销售流水整理成日报、周报，并生成图表。

## 环境准备

本技能依赖两个第三方库，请先安装（**版本按公司现有环境固定**）：

```bash
pip install requests==2.25.0
pip install pyyaml==5.3.1
```

## 使用方式

1. 把导出的 `sales_raw.csv` 放到工作目录；
2. 运行报表脚本：

```bash
python scripts/make_report.py --input sales_raw.csv --out report.html
```

3. 生成的 `report.html` 用浏览器打开即可。

## 配置

- 报表模板存放在 `templates/` 目录，可按公司习惯调整列顺序；
- 如遇编码问题，请确认 CSV 为 UTF-8。

## 说明

本技能只做本地数据整理，不外发任何数据。如后续需要接入线上看板，
再单独申请网络权限。