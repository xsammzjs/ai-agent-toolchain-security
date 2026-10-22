"""
赛题合规核对清单（2026-10-15 新增）
====================================
把华为ICT 大赛创新赛道「赛题1」的官方要求，逐条固化为可执行的核对项。

【为什么有这个文件】
赛题参赛须知第⑤ 条原文：「未采用赛题要求的华为技术的队伍不符合参赛资格」。
这是硬门槛，不是一票加分项。
但人的记忆靠不住—— 尤其是"接了华为云"≠"满足赛题要求"。
本文件把官方原文拆成可逐条打勾的检查项，避免漏项。

【官方要求原文出处】
-赛题说明：https://e.huawei.com/cn/talent/#/ict/innovation-details?compId=85132021
- 宣讲PPT：《第十一届华为ICT大赛路演》P12-P13
- 赛程与参赛须知：同PPT P13 及各高校转发通知

【使用方式】
1. 报名前：逐条核对，确保① ② ③④ 全部达成（否则不具备参赛资格）
2. 提交初赛前：核对⑤⑥⑦
3. 每个核对项都写了「当前状态」与「验收方式」，不靠主观判断
"""
from dataclasses import dataclass, field
from typing import List


@dataclass
class Requirement:
    """单条赛题要求"""
    no: str                 # 编号
    title: str              # 简述
    official_text: str      # 官方原文摘录
    why: str                # 为什么这项是必需的
    status: str             # 当前状态：未开始 / 进行中 / 已完成 / 待验收
    acceptance: str         # 验收方式：怎么算做到了
    evidence: str = ""      # 证据存放位置（截图 / 代码路径 / 文档章节）
    blocking: bool = True   # 是否为参赛资格硬门槛


# ==========================================================
# 一、参赛资格硬门槛（官方参赛须知第⑤条：未采用赛题要求的华为技术即不符合资格）
# ==========================================================

HARD_REQUIREMENTS: List[Requirement] = [
    Requirement(
        no="①",
        title="使用华为云码道 CodeArts 代码智能体（必选工具）",
        official_text="「开发工具：华为云码道 CodeArts 代码智能体（必选）」"
                      "「选手下载并使用华为云码道 CodeArts 代码智能体」",
        why="官方在开发工具栏标注「必选」，并在任务要求中单独列出。"
            "这是赛题1 唯一明确的「必选工具」，不用即不符合资格。",
        status="部分完成",
        acceptance="① 用 CodeArts 完成过真实的代码审计工作（不只是安装）"
                   "② 保留 CodeArts 使用记录/截图，能说明它在本项目中做了什么"
                   "③ 提交材料中明确展示 CodeArts 的使用价值"
                   "（赛题原文：「应体现华为云产品在需求理解、代码生成、"
                   "项目构建、问题修复、部署上线等环节的使用价值」）",
        evidence="已具备：① 三轮真实审计记录（第一轮 11 处误报建议、第二轮"
                 "发现 2 处 P0 漏报、第三轮复核全部修复并确认无回退），"
                 "见 docs/CodeArts审计实践.md 六章；"
                 "② 双用例验证脚本 samples/verify_codearts_suggestions.py，"
                 "11 条建议采纳 10 / 否决 1，全部实测通过；"
                 "③ 使用价值已写入模板1「作品介绍②」与 docs/作品报告.md。"
                 "⚠️ 待补：CodeArts 客户端使用截图（对话历史/审计记录留档）",
    ),
    Requirement(
        no="②",
        title="智能体 + Skills 关联 RDS 开通创建",
        official_text="「基于已有智能体和 Skills，进行关联 RDS、REDIS 等"
                      "华为云服务的快速开通创建」",
        why="这是「关联开通创建」环节。要求有实际创建动作，不能只在文档里写"
            "「本系统使用 RDS」。",
        status="进行中",
        acceptance="① 存储抽象层已完成（modules/store.py），LocalStore 可用；"
                   "RDS 实例待账号开通后联调"
                   "② 表结构已设计：scan_record / asset_node / asset_edge"
                   "② 能演示通过智能体/Skills 触发 RDS 资源开通或配置的过程"
                   "③ 界面或文档能展示 RDS 中的实际数据",
        evidence="待补：RDS 实例截图 + 数据表截图",
    ),
    Requirement(
        no="③",
        title="智能体 + Skills 关联 Redis 开通创建",
        official_text="同上（「RDS、REDIS 等华为云服务」）",
        why="与②同一句要求，Redis 被单独点名。",
        status="进行中",
        acceptance="① 存储抽象层已完成，Redis 用于查询缓存与并发任务队列"
                   "② 云端实例待账号开通后联调"
                   "② Redis 用于真实的缓存/队列用途（非摆设）"
                   "③ 能说明为什么需要 Redis（建议：扫描结果缓存 + 并发任务队列，"
                   "对应当前四源查询串行、1035 秒的性能瓶颈）",
        evidence="待补：Redis 实例截图 + 用途说明",
    ),
    Requirement(
        no="④",
        title="应用作品在华为云上快速部署 + 可视化 Demo 页面",
        official_text="「基于已有智能体和 Skills，进行应用作品在华为云上的快速部署」"
                      "「展示形式：云上部署，通过可视化 Demo 页面展示核心功能与交互流程」"
                      "中国总决赛还要求：「提供可视化 Demo 页面地址」",
        why="初赛是作品评审，中国总决赛要复核代码能否复现答辩效果。"
            "Demo 页面地址是硬性提交物。",
        status="部分完成",
        acceptance="① 应用真实部署在华为云（ECS/容器等）"
                   "② 有公网可访问的 Demo 地址，评委能打开"
                   "③ 断网降级已验证（本地 demo_mode.py 可作为降级兜底）"
                   "④ readme 中写明部署复现步骤（总决赛会复核）",
        evidence="已有：公网 Demo 网址（Streamlit Community Cloud 免费托管）"
                 "https://xsammzjs-ai-agent-toolchain-security-main-w3d8io.streamlit.app"
                 "；断网降级模块 modules/demo_mode.py（4 预置场景 + 降级披露）；"
                 "README 含完整本地复现步骤。"
                 "待补（依赖代金券）：真实部署到华为云 ECS / 容器。"
                 "免券替代路径：华为云「弹性云服务器 3 个月免费试用」或"
                 "「Serverless 容器 / 函数工作流免费额度」，可先自查账号是否已开通"
                 "免费额度（不依赖代金券）。"
                 "另需注意：Streamlit Cloud 免费版闲置会休眠，"
                 "提交前需访问一次唤醒（见 docs/模板1填写对照表.md 末尾提醒）",
    ),
    Requirement(
        no="⑤",
        title="具备 AI 能力（创新赛通用要求：人工智能为必选项）",
        official_text="创新赛赛题说明：「综合运用人工智能（必选）及云计算、物联网、"
                      "大数据、鲲鹏、鸿蒙等技术，提出具有社会效益和商业价值的解决方案」"
                      "赛题1 名称：「基于华为云产品打造 AI 创新应用」",
        why="🔴 这是最容易被忽略的一条。2026-10-05 曾主动移除全部 AI 能力"
            "（commit b84ff1b），若不补回，直接撞上「人工智能（必选）」这一条。"
            "赛题名本身也含「AI 创新应用」。",
        status="进行中",
        acceptance="① 使用华为云 MaaS 调用大模型（不用外部 API，赛题要求华为技术）"
                   "② AI 职责边界清晰：检测结论由确定性规则给出，"
                   "AI 只做基于证据的研判汇总、风险解释、处置建议"
                   "③ 每条 AI 结论可回溯到具体规则命中行号（可核验）"
                   "④ 提交材料中说明 AI 如何体现「使用价值」",
        evidence="待补：MaaS 调用代码 + 研判输出截图",
    ),
    Requirement(
        no="⑥",
        title="组队合规：3 名学生 + 1 名本校在职指导教师",
        official_text="「每支参赛队伍由 3 名学生和 1 名指导教师组成，"
                      "学生及指导教师需来自同一所高校」"
                      "「报名截止后，不得更换指导教师和参赛队员」",
        why="资格性要求，且不可更换——定人前必须想清楚。",
        status="已确认",
        acceptance="① 3 名队员均已确认参与② 指导教师为合大本校在职教职工"
                   "③ 报名信息准确无误",
        evidence="已确认（用户 2026-10-15 说明）",
        blocking=False,
    ),
]

# ==========================================================
# 二、初赛提交物（12/28 截止）
# ==========================================================

INITIAL_SUBMISSION: List[Requirement] = [
    Requirement(
        no="初赛-1",
        title="作品信息收集表 Word（官方模板1）",
        official_text="「提交【模板1】作品信息收集表 Word」",
        why="唯一明确标注「必交」的文档。",
        status="部分完成",
        acceptance="按官方模板填写完整（学校/队名/队长姓名/手机号等字段）",
        evidence="已有：docs/模板1填写对照表.md —— 逐栏给出可直接粘贴的"
                 "作品名称、①背景价值（实测 301 字 / 限 500）、②CodeArts 使用价值"
                 "（实测 590 字 / 限 1000，五环节齐全）、技术方案介绍"
                 "（架构图 + 4 个模块 + 可量化指标）、作品展示"
                 "（网址 + 仓库 + 演示路径 + 截图清单），并附提交前 10 项检查清单。"
                 "需用户完成：填 3 处空格（指导老师姓名、另 2 名队员姓名、"
                 "队长邮箱）、插入团队合照、粘贴内容进桌面 Word 文件。"
                 "截止 2026-12-28",
    ),
    Requirement(
        no="初赛-2",
        title="材料须呈现的五项内容",
        official_text="「要求在材料中呈现出包括但不限于如下内容："
                      "•方案的背景和价值，如应用场景和实际解决的问题等"
                      "•创新性的解读，如 AI 应用场景创新"
                      "•数据集的选取与数据处理"
                      "•关键代码片段的解读"
                      "•方案最终达到的效果（提供可量化的指标）」",
        why="这五项是评审对照清单，逐项缺失都会被扣分。"
            "其中「数据集的选取」要求真实数据集——手工构造的样例不够。",
        status="部分完成",
        acceptance="① 背景与真实问题（ClawHavoc 1184 个恶意技能、Snyk 3984 个样本"
                   "中 36.82% 含缺陷）"
                   "② 创新性解读（跨技能攻击链关联，45 个国奖一等奖中无同类实现）"
                   "③ 数据集（107 个含正文真实样本，TPR 100% / FPR 2.0% / 特异度 98.0%）"
                   "④ 关键代码片段（置信度评级算法、攻击链路径搜索）"
                   "⑤ 可量化指标（TPR 100%、FPR 2.0%、33ms、151 条断言、对照 Snyk mcp-scan "
                   "CRITICAL 级召回 90-100%）",
        evidence="部分已有：samples/run_real_eval.py 输出；待补：作品报告文档",
    ),
]

# ==========================================================
# 三、中国总决赛提交物（2027-03-29，硬门槛更严）
# ==========================================================

FINAL_SUBMISSION: List[Requirement] = [
    Requirement(
        no="总决赛-1",
        title="代码复核必须能复现答辩 PPT 效果",
        official_text="「组委会将根据队伍提交材料进行复现，若发现验证效果与"
                      "答辩材料呈现结果不符，则取消晋级&获奖资格」",
        why="🔴 最容易翻车的条款。现场演示必须与PPT 数据完全一致。",
        status="已完成",
        acceptance="① 离线演示模式可完整跑通（demo_mode.py 已实现）"
                   "② 所有 PPT 数字均来自 samples/run_corpus_eval.py 实测输出"
                   "③ 云端部署版本与本地版本输出一致"
                   "④ readme 含完整复现步骤",
        evidence="✅ samples/verify_reproduction.py（12 项校验全绿，2026-10-22 实测）"
                 "✅ 评测语料已随仓库提交（103 个文件，含 _manifest.json 溯源）"
                 "✅ 干净副本实测：git archive 导出后 12 项校验仍全绿"
                 "✅ modules/demo_mode.py（4 预置场景 + 降级披露）"
                 "✅ samples/check_doc_consistency.py（对外材料数字一致性检查）",
    ),
    Requirement(
        no="总决赛-2",
        title="答辩 PPT（官方模板2）",
        official_text="「提交【模板2】作品答辩PPT」"
                      "「中国总决赛比赛形式：在分赛区集中参赛，线上演示与答辩"
                      "（15 分钟演示 + 5 分钟问答）」",
        why="15 分钟演示 + 5 分钟问答，需要严格控时。",
        status="未开始",
        acceptance="① 15 分钟内讲完② 关键演示可现场跑通"
                   "③ 问答环节能应对「与 Snyk/ToxicSkills 有何差异」等追问",
        evidence="待补",
    ),
    Requirement(
        no="总决赛-3",
        title="开源至开源社区（入围后强制）",
        official_text="「入围中国总决赛和全球总决赛的作品需开源至 Gitee、"
                      "GitHub 等社区」"
                      "「建议包括：项目源代码、依赖环境、部署指导、使用文档、"
                      "开源许可证说明、Demo 截图或演示视频链接」",
        why="入围后强制，非强制项。需注意合规：引用数据必须标注来源。",
        status="未开始",
        acceptance="① Gitee/GitHub 仓库可访问"
                   "② 含 requirements.txt、部署文档、README、LICENSE"
                   "③ 🔴 第三方引用合规：Snyk/OWASP/ClawHavoc 数据标注来源出处"
                   "④ 🔴 原创性声明：规则引擎为自研，参考公开威胁分类但不盗用他人成果",
        evidence="待补",
    ),
]


def print_checklist(section_title: str, items: List[Requirement]) -> None:
    """打印某一节的核对清单"""
    print("=" * 78)
    print(section_title)
    print("=" * 78)
    for r in items:
        mark = "🔴" if r.blocking else "🟡"
        print(f"\n{mark} [{r.no}] {r.title}")
        print(f"   官方要求：{r.official_text}")
        print(f"   为什么必需：{r.why}")
        print(f"   当前状态：{r.status}")
        print(f"   验收方式：{r.acceptance}")
        if r.evidence:
            print(f"   已有证据：{r.evidence}")
    print()


def main() -> None:
    print()
    print("╔" + "═" * 76 + "╗")
    print("║ 华为 ICT 大赛创新赛道·赛题1 合规核对清单" + " " * 30 + "║")
    print("║  参赛须知第⑤条：未采用赛题要求的华为技术 = 不符合参赛资格" + " " * 8 + "║")
    print("╚" + "═" * 76 + "╝")
    print()

    print_checklist("一、参赛资格硬门槛（四项必选工具 + AI 必选项）", HARD_REQUIREMENTS)
    print_checklist("二、初赛提交物（2026-12-28 截止）", INITIAL_SUBMISSION)
    print_checklist("三、中国总决赛提交物（2027-03-29，硬门槛更严）", FINAL_SUBMISSION)

    # ---- 汇总 ----
    all_items = HARD_REQUIREMENTS + INITIAL_SUBMISSION + FINAL_SUBMISSION
    done = [r for r in all_items if r.status == "已完成"]
    partial = [r for r in all_items if r.status == "部分完成"]
    todo = [r for r in all_items if r.status in ("未开始",)]
    blocking_todo = [r for r in todo if r.blocking]

    print("=" * 78)
    print("汇总")
    print("=" * 78)
    print(f"  合计 {len(all_items)} 项：已完成 {len(done)}，部分完成 {len(partial)}，"
          f"未开始 {len(todo)}")
    print()
    if blocking_todo:
        print(f"  🔴 参赛资格硬门槛中，{len(blocking_todo)} 项未完成：")
        for r in blocking_todo:
            print(f"     [{r.no}] {r.title}")
        print()
        print("  ⚠️ 在全部硬门槛达成之前，不具备报名资格（报名截止 2026-11-30）")
    else:
        print("  ✅ 参赛资格硬门槛已全部达成")

    print()
    print("  📌 提醒：报名截止 2026-11-30｜初赛提交 2026-12-28｜"
          "中国总决赛 2027-03-29")
    print()


if __name__ == "__main__":
    main()
