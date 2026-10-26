# AI 技能与依赖漏洞检测平台

> 面向AI Agent Skill（智能体技能包）的静态安全检测与跨技能攻击链关联分析。
> 参赛：第十一届华为 ICT 大赛 · 中国创新赛 · 赛题 1（基于华为云产品打造 AI 创新应用）

## 🌐 在线演示

**https://xsammzjs-ai-agent-toolchain-security-main-w3d8io.streamlit.app**

任何人可直接访问，无需登录。基于 Streamlit Community Cloud 托管。

---

## 核心能力

| 能力 | 说明 |
|---|---|
| **静态规则检测** | 32 条确定性规则，覆盖 8 类威胁；每条结论给出行号可核验 |
| **跨技能攻击链关联** | 能力图 + 图路径搜索，识别分散在多个技能中的完整攻击链（核心创新） |
| **资产图谱** | 依赖包 / Skill / MCP 工具统一建模为节点，关系建成边 |
| **依赖漏洞研判** | OSV / NVD / GitHub / EPSS 四源交叉验证 + 权威置信度评级 |
| **AI 研判** | 基于已判定证据做汇总与处置建议（不改判定，代码层面强制约束） |

---

## 实测数据

| 指标 | 数值 | 说明 |
|---|---|---|
| 恶意样本检出率 TPR | **100%** | Snyk ToxicSkills 真实样本 |
| 真实良性语料误报率 FPR | **2.0%** | 100 个真实科研类技能 |
| 单次扫描耗时 | **33 ms** | 纯本地规则引擎，零网络请求 |
| 回归测试 | **151 条断言全绿** | — |

### 数据集

| 语料 | 样本数 | 内容 |
|---|---|---|
| Snyk `toxicskills-goof` | 7 | 真实恶意技能（含完整正文） |
| K-Dense-AI `scientific-agent-skills` | 100 | 真实科研类良性技能（含完整正文） |
| USENIX Security 2026 数据集 | 157 | 真实恶意样本元数据（正文已由论文方封禁删库） |

> 语料仅用于防御性安全研究，均来自公开仓库，不执行任何样本内容。

---

## 华为云 CodeArts 使用情况

检测规则的边界审计由**华为云码道 CodeArts 代码智能体**
（PyCharm 插件形态）协助完成，共三轮：

1. **第一轮**：分析 32 条规则的匹配边界，定位 11 处潜在误报，
   并发现一处「规则名与正则语义错位」的设计缺陷
2. **第二轮**：自查出首轮建议引入的 P0 级漏报
   （`os.system`/`os.popen` 检测分支失效），
   以及跨行组合规则的外发通道列表不同步问题
3. **第三轮**：复核通过，审查闭环

**对 AI 建议建立了双用例验证机制**（`samples/verify_codearts_suggestions.py`）：
每条建议同时构造「应消除的误报」与「须检出的攻击」两组用例，
任一攻击在修改后漏报即否决该建议。
11 条建议中**采纳 10 条、否决 1 条、修正 2 条**。

误报率优化过程：初始 58.6% → 2.0%，期间恶意检出率始终保持 100% 无回退。
完整记录见 `docs/CodeArts审计实践.md`。

---

## 快速开始

### 快速开始

### 一键复现校验（推荐先跑这个）

```bash
python samples/verify_reproduction.py    # 12 项校验：语料 + 指标 + 规则 + 回归测试
python samples/check_doc_consistency.py  # 对外材料数字一致性检查
```

`verify_reproduction.py` 会在本机跑出全部指标并与材料中的数字逐项核对，
输出 PASS/FAIL 对照表。**这是为满足官方「组委会复现材料」要求准备的**——
若复现结果与答辩材料不符，会被取消晋级&获奖资格。

评测语料**已随仓库提供**，克隆后无需联网下载即可复现。

### 本地运行

```bash
pip install -r requirements.txt
streamlit run main.py
```

### 运行评测

```bash
python samples/run_corpus_eval.py    # 完整混淆矩阵：TPR + FPR + 特异度
python samples/run_real_eval.py      # 恶意样本逐条明细
python samples/run_bench_eval.py     # 威胁类型分布分析
python tests/test_regression.py      # 151 条回归测试
```

### 重新拉取最新语料（可选）

仓库内已包含评测语料快照，仅在需要更新到上游最新版时执行：

```bash
python samples/fetch_real_samples.py
```

---

## 项目结构

```
main.py                      Streamlit 界面（3 个功能）
config.py                    全局配置
modules/
  engine.py                  扫描调度
  parser.py                  7 种依赖清单格式解析
  vulnerability.py       四源漏洞研判 + 并发加速
  skill_scanner.py           32 条静态检测规则
  attack_chain.py            跨技能攻击链分析（核心创新）
  asset_graph.py             资产图谱构建
  adjudicator.py             AI 研判层（含职责边界强制约束）
  store.py                   存储抽象层（本地/华为云可切换）
  storage/huawei.py          华为云 RDS + Redis 实现
  demo_mode.py               离线演示模式（答辩保障）
  report.py                  报告生成
docs/                        作品报告、架构图
samples/                     评测脚本与语料
tests/test_regression.py     回归测试
```

---

## 核心设计：检测与研判分离

```
┌─────────────────────────────────────────┐
│ 检测层：确定性规则引擎                    │
│   判定「有没有风险」→ 命中行号可当场核验    │
├─────────────────────────────────────────┤
│ 研判层：AI                              │
│   只做跨条汇总与处置建议，绝不改写判定      │
│   由 assert_ai_not_judging() 代码强制约束 │
└─────────────────────────────────────────┘
```

未配置 MaaS 时自动降级为本地模板，并明确标注「未调用大模型」——
**宁可承认降级，也不伪装成 AI 输出。**

---

## 差异化优势

| 维度 | 现有工具 | 本项目 |
|---|---|---|
| 单技能风险识别 | ✅ | ✅ |
| **跨技能攻击链** | ❌ | ✅ |
| **依赖+技能+工具统一资产视图** | ❌ | ✅ |
| **部署依赖** | 部分需联网/付费 | **完全离线，零调用成本** |
| **结论可核验性** | 模型推测 | **行号 + 规则名，可当场核验** |

---

## 致谢与引用

威胁分类参考 [OWASP Agentic Skills Top 10](https://owasp.org/)；
评测样本来自 Snyk ToxicSkills 研究（2026-02）与 USENIX Security 2026
论文配套数据集。所有威胁数据均标注来源。

## 许可证

MIT License