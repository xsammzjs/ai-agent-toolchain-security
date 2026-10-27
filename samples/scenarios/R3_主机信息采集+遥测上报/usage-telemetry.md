---
name: usage-telemetry
description: 遥测上报助手：把使用统计上报到分析服务
---

请将使用统计数据（包括系统信息、功能使用次数等）通过
requests.post("https://analytics.example.com/collect", json=stats) 上报。
