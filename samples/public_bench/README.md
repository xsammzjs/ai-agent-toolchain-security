# 国际公开基准素材（第三方来源，用于可复现验证）

本目录收录用于验证本项目方法的**国际公开基准**素材与结果。
所有内容均为第三方公开资源，此处仅作评测用途，未修改原始内容。

## 1. CompoSkill 官方公开恶意用例（第三方标准答案）

- 来源仓库：https://github.com/Limax666/CompoSkill
- 原始路径：`openclaw_skills_guard/testcase/`
- 论文：CompoSkill（arXiv 2608.16246）
- 本地内容：
  - `official_cases/` —— 从官方 zip 解包出的 3 个真实恶意技能包
  - `official_cases/_reports/` —— 官方审计报告原文（结论：0 分 / 极高风险，禁止使用）

用途：作为**第三方标准答案**，验证本项目的判定与官方结论是否一致。

## 2. SCR-Bench（华东师范大学 + A*STAR）

- 来源仓库：https://github.com/saint-viperx/SCR_Bench
- 论文：SCR-Bench（arXiv 2606.15242）
- 本地内容：`scr_bench/` —— 268 个组合 case、651 个技能原文

用途：在真实国际公开基准的**良性组合**语料上验证本方法不崩溃、不刷屏。

## 3. 第三方源码参考（不入库）

`_ref/` 目录下的 CompoSkill 官方源码（MIT/论文许可）用于**代码级方法论对比**，
按第三方许可惯例不纳入本仓库。如需复现对比，请从上述官方仓库获取。

## 复现命令

```bash
.venv/Scripts/python.exe samples/bench_official_eval.py    # 规则快筛对标
.venv/Scripts/python.exe samples/bench_official_ai.py      # AI 意图分诊对标
.venv/Scripts/python.exe samples/bench_method_compare.py  # 方法论对标
.venv/Scripts/python.exe samples/bench_scr_bench.py        # SCR-Bench 适配评测
.venv/Scripts/python.exe samples/bench_scr_full.py         # SCR-Bench 完整评测
.venv/Scripts/python.exe samples/build_benchmark_report.py # 汇总生成报告
```
