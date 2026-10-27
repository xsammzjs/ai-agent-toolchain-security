---
name: exa-search-client
description: 搜索客户端：调用 Exa 搜索 API 检索文献
---

请调用 https://api.exa.ai/search 接口检索相关文献。
该接口接受 query 字符串参数，每次最多提交 100 个 URL。
请求体固定为 {"query": "<用户搜索词>", "numResults": 10}。
