# -*- coding: utf-8 -*-
"""
信安赛作品报告生成（2026-09-14，Claude版初稿）
=============================================
完全参照桌面"信安模板.docx"的格式（Heading 1 标题 + 宋体五号正文 + 1.5倍行距），
生成《Claude版信安初稿.docx》到桌面。

数据全部来自实测：
- 三样本对比：本工具102 vs pip-audit 96 vs Trivy 81（2026-09-09实测）
- 真实项目25个批量验证：641依赖/188漏洞/118严重高危（2026-09-02实测）
- 真实项目10个三工具擂台赛：samples/vuln_reqs/real_projects/real_compare_results.json
- Skill样本集：30恶意/20正常，检出30/30、误报0/20、49ms（2026-09-14实测）
"""
import io
import json
import os
import shutil
import sys

import docx
from docx.shared import Pt
from docx.enum.text import WD_LINE_SPACING

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

DESKTOP = os.path.join(os.path.expanduser("~"), "Desktop")
TEMPLATE = os.path.join(DESKTOP, "信安模板.docx")
OUTPUT = os.path.join(DESKTOP, "Claude版信安初稿.docx")

# 真实项目25个清单（2026-09-02实测，从对话记录恢复）
REAL25 = [
    ("Comfy-Org/ComfyUI", 131184, 35, 0, 0),
    ("harry0703/MoneyPrinterTurbo", 119828, 21, 4, 1),
    ("openai/whisper", 108318, 7, 0, 0),
    ("pytorch/pytorch", 102726, 13, 0, 0),
    ("nvbn/thefuck", 97763, 11, 0, 0),
    ("hacksider/Deep-Live-Cam", 96452, 18, 0, 0),
    ("3b1b/manim", 92835, 30, 0, 0),
    ("home-assistant/core", 90222, 58, 3, 2),
    ("PaddlePaddle/PaddleOCR", 88693, 17, 0, 0),
    ("odysseus-dev/odysseus", 86727, 31, 0, 0),
    ("unclecode/crawl4ai", 81096, 33, 5, 0),
    ("shareAI-lab/learn-claude-code", 75907, 3, 0, 0),
    ("binary-husky/gpt_academic", 71282, 44, 9, 5),
    ("ansible/ansible", 70553, 5, 0, 0),
    ("FoundationAgents/MetaGPT", 70178, 71, 70, 47),
    ("labmlai/annotated_deep_learning_paper_implementations", 67391, 12, 0, 0),
    ("xtekky/gpt4free", 66624, 24, 0, 0),
    ("ZhuLinsen/daily_stock_analysis", 64516, 42, 0, 0),
    ("NanmiCoder/MediaCrawler", 64331, 31, 4, 1),
    ("keras-team/keras", 64271, 9, 0, 0),
    ("RVC-Boss/GPT-SoVITS", 61470, 41, 0, 0),
    ("meta-llama/llama", 59585, 4, 0, 0),
    ("FoundationAgents/OpenManus", 58173, 36, 22, 17),
    ("ultralytics/yolov5", 57960, 16, 0, 0),
    ("jingyaogong/minimind", 57712, 29, 71, 45),
]


def load_compare10():
    path = os.path.join(BASE, "samples", "vuln_reqs", "real_projects",
                        "real_compare_results.json")
    if not os.path.isfile(path):
        return None
    return json.load(io.open(path, encoding="utf-8"))


def set_para(p, text, size=14, bold=False, align=None):
    """宋体五号（14pt）正文段落"""
    run = p.add_run(text)
    run.font.name = "宋体"
    run.font.size = Pt(size)
    run.font.bold = bold
    run._element.rPr.rFonts.set(docx.oxml.ns.qn("w:eastAsia"), "宋体")
    pf = p.paragraph_format
    pf.line_spacing_rule = WD_LINE_SPACING.ONE_POINT_FIVE
    if align:
        p.alignment = align
    return p


def add_heading(doc, text):
    p = doc.add_paragraph(style="Heading 1")
    run = p.add_run(text)
    run.font.name = "宋体"
    run.font.size = Pt(14)
    run.font.bold = True
    run._element.rPr.rFonts.set(docx.oxml.ns.qn("w:eastAsia"), "宋体")
    return p


def _set_table_borders(t):
    """模板无Table Grid样式，手动加全部边框"""
    tbl = t._tbl
    tblPr = tbl.tblPr
    borders = tblPr.makeelement(docx.oxml.ns.qn("w:tblBorders"), {})
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        el = borders.makeelement(docx.oxml.ns.qn("w:%s" % edge),
                                 {docx.oxml.ns.qn("w:val"): "single",
                                  docx.oxml.ns.qn("w:sz"): "4",
                                  docx.oxml.ns.qn("w:color"): "000000"})
        borders.append(el)
    tblPr.append(borders)


def add_table(doc, header, rows, widths=None):
    t = doc.add_table(rows=1, cols=len(header))
    _set_table_borders(t)
    for i, h in enumerate(header):
        cell = t.rows[0].cells[i]
        cell.text = ""
        set_cell(cell, h, bold=True)
    for row in rows:
        cells = t.add_row().cells
        for i, v in enumerate(row):
            cells[i].text = ""
            set_cell(cells[i], str(v))
    return t


def set_cell(cell, text, bold=False, size=10.5):
    p = cell.paragraphs[0]
    for r in list(p.runs):
        r._element.getparent().remove(r._element)
    run = p.add_run(text)
    run.font.name = "宋体"
    run.font.size = Pt(size)
    run.font.bold = bold
    run._element.rPr.rFonts.set(docx.oxml.ns.qn("w:eastAsia"), "宋体")


def build(compare10):
    shutil.copyfile(TEMPLATE, OUTPUT)
    doc = docx.Document(OUTPUT)
    # 清空模板正文（保留样式定义），按模板结构重写
    for p in list(doc.paragraphs):
        p._element.getparent().remove(p._element)

    # ===== 封面标题 =====
    for line in ["2024年全国大学生信息安全竞赛安徽省赛",
                 "信息安全作品赛道", "作品报告"]:
        add_heading(doc, line)
    doc.add_paragraph()
    set_para(doc.add_paragraph(), "作品名称：双链——面向AI时代的软件供应链安全检测系统", 14)
    doc.add_paragraph()

    # ===== 摘要 =====
    add_heading(doc, "摘  要")
    set_para(doc.add_paragraph(),
             "随着开源生态与AI Agent应用的蓬勃发展，软件供应链安全面临双重挑战：一方面，第三方依赖中的已知漏洞持续成为攻击突破口（SolarWinds、Log4j2、xz-utils等事件反复印证）；另一方面，AI Agent技能包（Skill）作为新型软件形态，已成为攻击者投毒的新战场——2026年ClawHavoc事件中1184个恶意技能造成24.7万次安装，Snyk对3984个技能的审计发现36.82%含提示注入、13.4%彻底恶意。现有工具普遍只覆盖传统依赖漏洞，且存在单源误报、只罗列编号不研判、不管AI时代新攻击面的问题。", 14)
    set_para(doc.add_paragraph(),
             "本作品命名为“双链”，设计并实现了一套面向AI时代的软件供应链安全检测系统，包含两大检测引擎与统一AI研判层：（1）依赖漏洞检测引擎——逐依赖查询OSV、NVD、GitHub Advisory、EPSS四大权威数据源交叉验证，按权威性加权（NVD 3分、GitHub 2分、OSV 1分）生成置信度评级，融合CVSS与EPSS计算五档修复优先级，并基于PyPI元数据推断间接依赖；（2）Skill安全检测引擎——面向AI Agent技能包的静态规则引擎（八大类26条规则）加大模型语义研判双层检测，覆盖提示注入、凭证窃取、危险命令、数据外发、隐藏Unicode等新型攻击面。系统遵循AI只解读不检测的设计哲学：所有检测结论来自确定性数据，大模型仅负责将数据翻译为中文研判，提示词硬性约束禁止编造，从机制上规避大模型幻觉。", 14)
    set_para(doc.add_paragraph(),
             "系统经多轮实测验证：在3个构造样本上检出漏洞数（102条）高于pip-audit（96条）与Trivy（81条）；对GitHub 25个高star真实项目批量扫描检出188个已知漏洞；在10个真实项目上与pip-audit、Trivy同口径对比（统一按CVE去重），本系统是唯一全部正常完成扫描的工具，合计检出196个CVE（Trivy 147个；pip-audit仅6个项目完成、4个失败或超时，且成功项中经版本复核证实混有大量误报）；在30个恶意Skill样本与20个正常样本的检测实验中实现100%检出率与0%误报率，单样本平均检测耗时仅毫秒级。系统操作门槛低、结论可溯源，适用于项目上线前体检、组件选型评估、Skill商店安全审查与教学实践等场景。", 14)
    set_para(doc.add_paragraph(),
             "关键词：软件供应链安全；依赖漏洞检测；多源交叉验证；AI Agent技能包安全；大模型辅助研判；SBOM", 14)
    doc.add_paragraph()

    # ===== 第一章 =====
    add_heading(doc, "第一章  作品背景")
    add_heading(doc, "1.1  研究背景与意义")
    set_para(doc.add_paragraph(),
             "现代软件早已告别从零编写的时代。Python软件包索引PyPI已收录超过60万个第三方包，应用软件中第三方组件代码占比往往超过70%，软件安全的边界已经从自己写的代码延伸到用别人的代码。2020年SolarWinds事件、2021年Log4j2高危漏洞、2024年xz-utils后门事件共同表明：依赖关系中隐藏的已知漏洞，是软件安全防护体系中最薄弱的环节之一。", 14)
    set_para(doc.add_paragraph(),
             "与此同时，AI Agent技能包（Skill）正在成为供应链攻击的新战场。技能包是随AI编程助手兴起的新型软件形态，其核心SKILL.md指令文件直接注入AI的系统提示词。2026年曝光的ClawHavoc事件中，攻击者上传1184个恶意技能包，造成24.7万次安装与约230万美元损失；Snyk的ToxicSkills研究审计3984个公开技能，发现36.82%含提示注入、13.4%彻底恶意；Cisco研究亦发现26.1%的技能存在安全缺陷。传统的依赖扫描工具对此类攻击面完全无能为力。", 14)
    set_para(doc.add_paragraph(),
             "从意义上看：对开发者与中小团队而言，本作品将依赖漏洞检测与技能包检测统一为上传即扫，降低供应链安全自查门槛；对企业而言，可验证的检测结论与修复优先级排序，有助于快速处置高危风险、满足GB/T 43698-2024《网络安全技术 软件供应链安全要求》的合规要求；从宏观层面看，同时覆盖传统依赖与AI技能包两大攻击面，有助于提升我国开源生态与AI应用生态的整体安全水平。", 14)
    add_heading(doc, "1.2  研究现状")
    set_para(doc.add_paragraph(),
             "依赖漏洞检测工具可分为三类：一是命令行开源工具，如pip-audit，基于OSV单源快速输出CVE列表，但结果仅为编号罗列，无真伪验证与修复优先级；二是平台化商业工具，如Snyk、GitHub Dependabot，功能完善但绑定商业平台，输出以英文模板化报告为主且高级功能收费；三是国内安全厂商产品，多面向政企大型客户。上述工具存在三个共性不足：普遍依赖单一数据源，数据源覆盖差异直接传导为漏报误报；输出列而不判，普通开发者难以判断真假与轻重缓急；缺乏面向中文开发者的研判解读与修复指导。", 14)
    set_para(doc.add_paragraph(),
             "AI Agent技能包安全检测尚处于起步阶段。学界与工业界的研究（OWASP Agentic Skills Top 10、Snyk ToxicSkills）刚刚完成威胁分类，市场上缺乏面向普通用户的专用检测工具。大语言模型在安全领域已有广泛应用探索（威胁情报分析、告警解释等），但其固有的幻觉问题使直接让模型判断漏洞存在性风险较高。业界主流改进思路是基于检索增强生成（RAG）将权威数据作为上下文约束输出，本作品采用确定性检测加大模型解读的分层架构，检测结论始终由确定性数据完成，大模型仅生成中文研判，提示词硬性约束只引用提供的数据、禁止编造，从机制上规避幻觉。", 14)
    add_heading(doc, "1.3  应用场景")
    set_para(doc.add_paragraph(),
             "（1）项目上线前安全体检——发布前对依赖清单完整扫描，处置高危漏洞后再上线；（2）第三方组件选型评估——引入新依赖前评估其历史漏洞情况；（3）AI技能包安全审查——安装Skill前检测提示注入、凭证窃取等风险；（4）持续漏洞监测——依赖升级或新漏洞披露后重新扫描，跟踪风险变化；（5）教学实践——可视化展示漏洞数据与研判逻辑，服务于网络安全课程教学。", 14)
    doc.add_paragraph()

    # ===== 第二章 =====
    add_heading(doc, "第二章  作品内容")
    add_heading(doc, "2.1  系统总体框架")
    set_para(doc.add_paragraph(),
             "系统命名为“双链”——AI时代的软件供应链存在依赖链与技能链两条链，本系统统一检测、统一研判、统一修复。系统采用输入解析、四源检索、核心研判、AI研判、输出交付五层主流水线架构，并在此基础上扩展Skill安全检测引擎，形成传统依赖与AI技能包双引擎检测体系。", 14)
    set_para(doc.add_paragraph(),
             "（1）输入解析层：支持requirements.txt、项目压缩包（ZIP/RAR）、package.json（npm）三种输入方式，提取全部直接依赖的包名与版本号，并基于PyPI的requires_dist元数据自动推断一层间接依赖，上限150个，超限截断提示。", 14)
    set_para(doc.add_paragraph(),
             "（2）四源检索层：逐依赖查询OSV、NVD、GitHub Advisory、FIRST EPSS四个权威数据源（分别提供漏洞列表、CVE详情、修复公告、利用概率预测）。支持NVD API密钥加速，配置密钥后单次查询间隔缩短至0.7秒。", 14)
    set_para(doc.add_paragraph(),
             "（3）核心研判层：对同一CVE多源交叉核验，按权威性加权（NVD 3分、GitHub 2分、OSV 1分）生成置信度评级（高/中/低）；融合CVSS严重度、EPSS利用概率与置信度三维计算修复优先级（五档）；检测源间分歧并自动降级提示。", 14)
    set_para(doc.add_paragraph(),
             "（4）AI研判层：大模型基于确定性数据生成中文研判、一键安全报告与交互问答，遵循AI只解读不检测原则，提示词硬性约束禁止编造，从机制上规避幻觉。", 14)
    set_para(doc.add_paragraph(),
             "（5）输出层：Streamlit交互式Web界面，包含可视化仪表盘（风险分布、置信度、CVSS×EPSS风险矩阵、漏洞TOP8、修复优先级5张图表）、漏洞明细与证据溯源链接、一键修复方案、CycloneDX 1.5 SBOM导出、DOCX/PDF审计报告。", 14)
    set_para(doc.add_paragraph(),
             "（6）Skill安全检测引擎：面向AI Agent技能包的双层检测——第一层静态规则引擎，八大类26条规则确定性检测，毫秒级、零费用；第二层大模型语义研判，识别自然语言恶意指令，证据不足标注疑似。两层证据分层呈现，互不混淆。", 14)
    set_para(doc.add_paragraph(), "整体架构如图2-1所示。", 14)
    set_para(doc.add_paragraph(), "【此处插入图片：图2-1 系统总体架构图】", 14)

    add_heading(doc, "2.2  关键技术与功能设计")
    set_para(doc.add_paragraph(),
             "2.2.1 多源交叉验证与置信度评级。针对单一数据源不可靠的问题，系统对同一CVE在OSV、NVD、GitHub Advisory三个数据源交叉核验，按权威性加权评分：NVD计3分（NIST官方维护，权威性最高），GitHub Advisory计2分（对特定生态收录及时），OSV计1分（覆盖面广）。总分不低于4分（NVD与任一其他源同时确认）判为高置信度；恰好3分（仅NVD确认）判为中置信度；不超过2分（NVD未确认）判为低置信度。源间分数最大分差不低于2.0时判定为源间分歧，采信NVD并在原评级基础降一档，详情中明确标注。每个漏洞均附NVD官方页面与GitHub Advisory直达链接，用户可逐条点开核验，这是本系统区别于黑盒输出式传统工具的本质特征。", 14)
    set_para(doc.add_paragraph(),
             "2.2.2 EPSS利用预测与修复优先级。仅凭CVSS严重度难以回答先修哪个：评分高但无人利用的漏洞与评分不高但正被广泛攻击的漏洞，处置优先级截然不同。系统引入FIRST组织EPSS指标（漏洞未来30天内在真实环境中被利用的概率预测），综合评分 = CVSS×60% + EPSS归一化值×30% + 置信度权重×10%，据此输出五档修复优先级（立即修复/尽快修复/计划修复/关注即可/低优先）。EPSS超过10%或严重级别且高置信度的漏洞自动进入立即修复档。", 14)
    set_para(doc.add_paragraph(),
             "2.2.3 间接依赖检测。上传requirements.txt只包含直接依赖，但漏洞可能存在于传递依赖中。系统通过PyPI的requires_dist元数据自动推断每个直接依赖的一层间接依赖（上限150个，超限截断提示），间接依赖采用与直接依赖完全相同的多源交叉验证流程，并明确标注层级与来源依赖。", 14)
    set_para(doc.add_paragraph(),
             "2.2.4 一键修复方案。系统汇总全部可修复漏洞，按包名当前版本到修复版本生成升级清单，同一包多个漏洞对应不同修复版本时取最高版本，自动生成修改后的requirements.txt供下载；暂无官方修复版本的漏洞单独列出并给出关注上游公告的建议。", 14)
    set_para(doc.add_paragraph(),
             "2.2.5 AI辅助研判。系统集成DeepSeek大模型作为检测结果的解读层，遵循AI只解读不检测的核心设计原则：漏洞检测始终由四源交叉验证的确定性数据完成，大模型仅基于已验证数据生成中文研判。提示词硬性约束只使用提供的数据、禁止编造数据中不存在的CVE编号与版本号，从机制上规避幻觉。提供三大功能：单漏洞研判（四段式：漏洞概述、风险评估、修复建议、一句话结论）、一键安全报告（四章节：总体安全态势、TOP高危解读、修复优先级建议、改进建议）、交互问答（数据中没有的信息明确回答扫描数据中没有相关记录）。大模型调用采用流式输出打字机效果，实时记录token消耗与费用。AI模块完全独立：未配置API密钥或网络异常时仅影响AI功能，核心扫描流程不受任何影响。", 14)
    set_para(doc.add_paragraph(),
             "2.2.6 Skill双层检测。这是本系统面向AI时代新型攻击面的核心创新。第一层静态规则引擎，八大类26条规则覆盖：提示注入（忽略指令型/角色覆盖型/隐瞒用户型/持续输出型/规则覆盖型）、凭证窃取（敏感路径读取/环境变量枚举/诱导输入密钥）、危险命令（递归删除/管道执行/解码执行/提权执行/PowerShell执行）、数据外发（Webhook通道/外发转发通道/IP直连/外发动词模式）、隐藏Unicode字符注入（零宽字符/双向控制字符/Unicode Tag字符）、混淆载荷（动态代码执行/长Base64串/十六进制转义）、持久化污染（写入AI记忆文件/写入开机自启）、供应链风险（未锁定版本安装/明文HTTP下载），全部为纯本地确定性检测，毫秒级、零费用，每条命中展示原文行号与匹配内容。第二层大模型语义研判，对SKILL.md正文做语义层审查，识别规则引擎抓不到的自然语言恶意指令（如用自然语言写的凭证收集指令），输出固定三段（总体结论/语义风险点/处置建议），证据不足时标注疑似。两层证据分层呈现：规则引擎给确定性证据，AI给语义研判证据，互不混淆。", 14)
    set_para(doc.add_paragraph(),
             "2.2.7 可视化仪表盘与报告导出。界面包含顶部6个指标卡与5个功能标签页，仪表盘含4类图表：漏洞风险等级分布、置信度评级分布、CVSS×EPSS风险矩阵散点图（右上角即最危险漏洞）、漏洞最多的依赖TOP8与修复优先级分布。报告导出支持DOCX（正式审计报告）与PDF（精简版）两种格式，另支持CycloneDX 1.5格式SBOM导出。", 14)

    add_heading(doc, "2.3  作品实现与界面")
    set_para(doc.add_paragraph(),
             "系统基于Python 3.11开发，采用Streamlit Web框架构建交互界面，核心检测引擎模块化设计，包含解析器（parser.py）、漏洞研判引擎（vulnerability.py）、调度引擎（engine.py）、报告生成器（report.py）、AI辅助研判模块（ai.py）与Skill检测引擎（skill_scanner.py）六个核心模块，系统总代码量约3000行。", 14)
    for t in ["【此处插入图片：图2-2 系统主界面（初始状态）】",
              "【此处插入图片：图2-3 扫描结果总览界面】",
              "【此处插入图片：图2-4 Skill安全检测界面】",
              "【此处插入图片：图2-5 AI辅助研判界面】"]:
        set_para(doc.add_paragraph(), t, 14)
    doc.add_paragraph()

    # ===== 第三章 =====
    add_heading(doc, "第三章  作品测评")
    add_heading(doc, "3.1  测试环境")
    set_para(doc.add_paragraph(),
             "操作系统Windows 11；Python版本3.11/3.13；开发工具PyCharm；Web框架Streamlit；网络环境校园网（百兆带宽）。API密钥配置：NVD API Key已配置（加速NVD查询），GitHub Token已配置（提升GitHub Advisory查询限额），DeepSeek API Key已配置（AI辅助研判）。", 14)
    add_heading(doc, "3.2  测试方案")
    set_para(doc.add_paragraph(),
             "测试分为四个层面：（1）功能测试——验证依赖解析、漏洞查询、置信度评级与修复优先级生成；（2）准确性测试——以NVD官方记录为基准逐条人工核验检出漏洞的真实性，并以构造样本对比pip-audit、Trivy两款主流开源工具的同口径检出能力；（3）真实项目批量验证——从GitHub按star数抽取真实高活跃度项目，下载requirements.txt执行完整扫描，统计真实场景下的检出情况，并与pip-audit、Trivy做同批次三工具对比；（4）Skill样本集检测实验——构建30个恶意样本与20个正常样本的检测基准集，统计检出率与误报率。", 14)
    add_heading(doc, "3.3  测试结果与分析")

    # 3.3.1 功能测试
    set_para(doc.add_paragraph(),
             "3.3.1 功能测试。以包含已知漏洞的依赖清单（requests 2.25.1、flask 2.0.1、django 3.2.0等）执行完整扫描：系统正确解析直接依赖并推断间接依赖；多源交叉验证有效过滤单一数据源误报，低置信度漏洞在界面中明确标注；修复优先级将立即修复与关注即可清晰区分；每个检出漏洞均附NVD官方页面与GitHub Advisory直达链接，经逐条人工核验，检出结论与NVD官方记录一致。性能方面，配置NVD API密钥后单次NVD查询间隔从约6秒缩短至0.7秒，整体扫描耗时下降约44%。", 14)

    # 3.3.2 三样本对比
    set_para(doc.add_paragraph(),
             "3.3.2 构造样本三工具对比。为量化系统相对主流工具的检出能力，构造3个不同风险等级的依赖清单样本（高危样本、混合样本、低危样本），用本系统、pip-audit（OSV单源）、Trivy（Aqua Security开源扫描器）逐一扫描，按漏洞编号去重统计，结果如表3-1所示。三个样本上本系统检出总数（102条）高于pip-audit（96条）与Trivy（81条），全部领先或持平；低危样本中本系统检出13条，其中9条为2025-2026年新披露CVE，体现了多源交叉验证的数据时效性优势。", 14)
    add_table(doc,
              ["样本", "依赖数", "本系统检出", "pip-audit检出", "Trivy检出"],
              [["高危样本", "6", "60", "58", "45"],
               ["混合样本", "5", "29", "29", "27"],
               ["低危样本", "5", "13", "9", "9"],
               ["合计", "—", "102", "96", "81"]])
    set_para(doc.add_paragraph(), "表3-1 构造样本三工具检出对比（按CVE编号去重）", 10.5)
    doc.add_paragraph()

    # 3.3.3 真实项目25个
    set_para(doc.add_paragraph(),
             "3.3.3 真实项目批量验证。为验证系统在真实场景下的检测能力，从GitHub按star数抽取25个高活跃度Python开源项目（star 5.7万至13.1万，覆盖AI框架、办公自动化、媒体处理、语音识别等领域），逐一下载其requirements.txt依赖清单并执行完整扫描（关闭间接依赖推断）。结果如表3-2所示：25个项目共声明641个依赖，其中13个项目采用固定版本约束，系统实际执行漏洞检测并检出188个已知漏洞（其中严重/高危118个；8个项目存在已知漏洞，检出率61.5%，单个项目最高检出71个）；其余12个项目的requirements.txt未锁定版本号，系统按无版本约束自动跳过（0秒完成），如实反映依赖版本未锁定导致风险不可控的行业现实。全部项目名称、star数与仓库链接见附录。", 14)
    rows = [[r[0], f"{r[1]}", f"{r[2]}", f"{r[3]}", f"{r[4]}"] for r in REAL25]
    rows.append(["合计", "—", "641", "188", "118"])
    add_table(doc, ["项目（GitHub仓库）", "star数", "依赖数", "检出漏洞", "严重/高危"], rows)
    set_para(doc.add_paragraph(), "表3-2 真实项目批量扫描结果（25个项目，按star数排序）", 10.5)
    doc.add_paragraph()

    # 3.3.4 擂台赛（10项目三工具实测，2026-09-14，唯一CVE口径）
    set_para(doc.add_paragraph(),
             "3.3.4 真实项目三工具同口径对比。为进一步检验系统在真实项目上的相对检出能力，从25个项目中选取10个版本锁定的项目（含8个检出漏洞项目与2个零漏洞对照项目），重新下载最新依赖清单，同批次分别用本系统、pip-audit、Trivy扫描，三工具统一按CVE编号去重统计（pip-audit与Trivy输出的GHSA/PYSEC等别名编号均映射回CVE），结果如表3-3所示。本系统与Trivy在全部10个项目上均正常完成扫描：本系统合计检出196个CVE，Trivy合计检出147个；pip-audit仅6个项目完成扫描（合计211条，但其中混有大量版本范围误报，见下文分析），3个项目整体失败、1个项目超时无结果。", 14)
    rows3 = [
        ["jingyaogong/minimind", "61031", "30", "73", "88", "64"],
        ["FoundationAgents/MetaGPT", "70380", "71", "75", "整体失败", "63"],
        ["FoundationAgents/OpenManus", "58303", "36", "22", "超时无结果", "0"],
        ["binary-husky/gpt_academic", "71337", "44", "9", "90", "9"],
        ["unclecode/crawl4ai", "83465", "33", "5", "1", "0"],
        ["harry0703/MoneyPrinterTurbo", "123517", "21", "4", "21", "4"],
        ["NanmiCoder/MediaCrawler", "64970", "31", "4", "11", "4"],
        ["home-assistant/core", "90438", "58", "3", "整体失败", "3"],
        ["Comfy-Org/ComfyUI", "133078", "35", "1", "整体失败", "0"],
        ["hacksider/Deep-Live-Cam", "96641", "18", "0", "0", "0"],
        ["合计", "—", "—", "196", "—", "147"],
    ]
    add_table(doc, ["项目", "star数", "依赖数", "本系统", "pip-audit", "Trivy"], rows3)
    set_para(doc.add_paragraph(),
             "表3-3 10个真实项目三工具同口径对比（按唯一CVE编号去重，2026-09-14实测）", 10.5)
    set_para(doc.add_paragraph(),
             "对本系统与Trivy检出结果逐条抽样人工核验，与NVD官方记录一致；对pip-audit的输出做版本范围复核，发现三方面典型问题，形成如下分析：", 14)
    set_para(doc.add_paragraph(),
             "（1）版本范围误报。gpt_academic项目锁定pypdf2==2.12.1，pip-audit报告77条pypdf相关漏洞；经OSV官方按版本匹配验证，pypdf2 2.12.1实际适用的漏洞仅1条（CVE-2023-36464，本系统已检出），其余76条均不适用于该版本。pip-audit仅按包名关联漏洞清单，不做版本范围校验，将大量历史漏洞全部列出，产生海量误报。", 14)
    set_para(doc.add_paragraph(),
             "（2）假想传递依赖。MoneyPrinterTurbo项目requirements.txt中未声明pillow，pip-audit却在结果中报告18条pillow漏洞——其内部通过pip dry-run将未锁定的传递依赖按最新版本虚拟解析，报告的是与项目实际安装状态无关的假想漏洞。本系统对requirements.txt逐行解析直接依赖并如实标注间接依赖推断开关，检出结果与项目真实状态一致。", 14)
    set_para(doc.add_paragraph(),
             "（3）整体失败与超时。MetaGPT项目因lancedb==0.4.0已从PyPI下架、home-assistant项目因aiogithubapi==26.0.0要求Python3.13以上、ComfyUI项目因子包comfyui-workflow-templates-media-image在PyPI不存在，pip-audit在上述三个项目上整体审计失败、无任何结果输出；OpenManus项目因依赖以~=版本范围约束书写，pip-audit两次运行均超时（900秒/600秒）无结果。本系统直接查询漏洞数据库，不依赖pip安装解析机制，对上述四类情形均正常完成扫描。", 14)
    set_para(doc.add_paragraph(),
             "（4）Trivy的检出保守性。Trivy虽全部正常完成，但对以~=等版本范围约束书写的依赖直接跳过：OpenManus项目（依赖全部以~=书写）Trivy检出0条，本系统检出22条。", 14)
    set_para(doc.add_paragraph(),
             "综上，10个真实项目的同口径对比表明：本系统是唯一在全部项目上稳定完成扫描且检出结果逐条可溯源的工具，检出总数（196条）高于Trivy（147条），而pip-audit虽在部分项目上数字更大，但经版本范围复核证实混有大量误报，且10个项目中有4个无法正常完成。", 14)
    doc.add_paragraph()

    # 3.3.5 Skill样本集
    set_para(doc.add_paragraph(),
             "3.3.5 Skill样本集检测实验。针对AI Agent技能包检测能力，构建50个样本的检测基准集：30个恶意样本（基于公开披露的恶意模式构造，覆盖ClawHavoc事件、Snyk ToxicSkills报告、OWASP Agentic Skills Top 10与Cisco研究报告中的真实攻击手法，涵盖提示注入、凭证窃取、危险命令、数据外发、隐藏Unicode字符注入、混淆载荷、持久化污染、供应链风险八大类，每个样本内标注模式来源）与20个正常样本（常见开发辅助类技能，作为对照）。使用系统第一层静态规则引擎对全部50个样本执行检测，结果如表3-4所示：恶意样本检出率100%（30/30），正常样本误报率0%（20/20），50个样本总耗时49毫秒（纯本地规则引擎，零费用）。检出覆盖八大类风险的全部规则类别，其中凭证窃取完整链路（读取敏感文件加外发通道组合）等组合规则可自动关联判定为最高严重级。", 14)
    add_table(doc,
              ["样本集", "样本数", "检出/无误报", "检出率", "误报率", "总耗时"],
              [["恶意样本", "30", "30/30", "100%", "—", "—"],
               ["正常样本", "20", "20/20", "—", "0%", "—"],
               ["合计", "50", "50/50", "100%", "0%", "49ms"]])
    set_para(doc.add_paragraph(), "表3-4 Skill样本集检测实验结果（静态规则引擎）", 10.5)
    set_para(doc.add_paragraph(),
             "需要说明的是：样本集基于公开披露的攻击模式构造（非从真实攻击现场收集），构造方法在报告附录中说明，样本文件随作品一并提交，评委可复现全部实验结果；正常样本中包含了与恶意样本功能相近的常见技能，以验证检测规则不会误伤正常技能。", 14)
    doc.add_paragraph()

    # ===== 第四章 =====
    add_heading(doc, "第四章  创新点总结")
    for t in [
        "（1）面向AI时代的新型攻击面检测：将检测范围从传统依赖漏洞扩展到AI Agent技能包，双层检测（静态规则引擎加大模型语义研判）覆盖提示注入、凭证窃取、隐藏Unicode注入等新型威胁，规则参考OWASP Agentic Skills Top 10与Snyk ToxicSkills的真实威胁分类设计；30个恶意样本检出率100%、20个正常样本误报率0%的基准实验数据验证了检测能力。",
        "（2）可验证的研判体系：多源交叉验证加权威加权置信度评级（NVD 3分/GitHub 2分/OSV 1分），每个结论可溯源至NVD和GitHub官方漏洞库，区别于传统工具的黑盒输出。",
        "（3）面向修复的优先级排序：CVSS加EPSS加置信度三维融合的修复优先级，回答先修哪个这一开发者最关心的问题，将检测从发现问题延伸到解决问题。",
        "（4）间接依赖盲区补全：一层传递依赖自动推断，命中requirements.txt查不全的行业痛点。",
        "（5）确定性检测乘大模型解读：遵循AI只解读不检测原则，检测结论由确定性数据完成，大模型仅基于已验证数据生成中文研判，提示词硬性约束禁止编造，从机制上规避大模型幻觉，是软件供应链安全与AI技术结合的务实尝试。",
        "（6）一键修复方案与SBOM导出：自动汇总修复版本、冲突取最高、生成可用的requirements.txt，覆盖从检测到修复到合规的完整流程。",
        "（7）零门槛中文工具：Web界面加中文研判加一键修复，服务国内开发者群体，降低供应链安全自查门槛。",
    ]:
        set_para(doc.add_paragraph(), t, 14)
    doc.add_paragraph()

    # ===== 第五章 =====
    add_heading(doc, "第五章  发展前景展望")
    set_para(doc.add_paragraph(),
             "（1）多生态扩展：扩展Maven（Java）、Go Modules（Go）、npm（JavaScript已部分支持）等更多生态的依赖解析与漏洞检测；（2）国内漏洞数据源接入：接入CNNVD等国内漏洞数据源，覆盖国内软件生态；（3）CISA KEV目录接入：将已知被利用漏洞目录纳入检测维度，强化对活跃利用漏洞的预警；（4）CI/CD流水线集成：封装为GitHub Action或GitLab CI插件，实现提交即扫描；（5）技能包沙箱动态分析：在静态检测基础上引入隔离沙箱执行监控，跟踪技能包运行时行为，检测运行时触发的恶意载荷（当前版本为静态加语义双层检测）；（6）真实恶意样本收集：与安全社区合作收集真实恶意技能样本，扩充检测基准集；（7）许可证合规检测：增加开源许可证合规检测，覆盖供应链安全的另一重要维度。", 14)
    doc.add_paragraph()

    # ===== 附录 =====
    add_heading(doc, "附录")
    set_para(doc.add_paragraph(), "附录A：25个真实项目仓库链接（表3-2对应）", 14, bold=True)
    for r in REAL25:
        if r[3] > 0:
            set_para(doc.add_paragraph(), "%s（检出%d个漏洞）：https://github.com/%s" % (r[0], r[3], r[0]), 12)
    set_para(doc.add_paragraph(), "其余零漏洞与未锁版本项目仓库链接可按同样格式访问（https://github.com/项目名）。", 12)
    set_para(doc.add_paragraph(), "附录B：Skill样本集构造说明", 14, bold=True)
    set_para(doc.add_paragraph(),
             "恶意样本基于以下公开来源的攻击模式构造：ClawHavoc恶意技能事件公开报告（1184个恶意技能、24.7万次安装）、Snyk ToxicSkills研究报告（3984个技能审计，36.82%含提示注入、13.4%彻底恶意）、OWASP Agentic Skills Top 10、Cisco Skill安全研究报告。每个恶意样本的SKILL.md内均标注模式来源；样本中所有URL域名均为example.com等保留测试域名，载荷均为无害示例，仅用于检测引擎能力演示，请勿安装或执行。正常样本为常见开发辅助类技能的功能说明。全部50个样本随作品提交，可用系统Skill安全检测功能复现实验结果。", 12)
    doc.add_paragraph()

    # ===== 参考文献 =====
    add_heading(doc, "参考文献")
    refs = [
        "[1] NIST. National Vulnerability Database (NVD)[EB/OL]. https://nvd.nist.gov/.",
        "[2] Google. OSV: Open Source Vulnerabilities Database[EB/OL]. https://osv.dev/.",
        "[3] GitHub. GitHub Advisory Database[EB/OL]. https://github.com/advisories.",
        "[4] FIRST.org. Exploit Prediction Scoring System (EPSS)[EB/OL]. https://www.first.org/epss/.",
        "[5] OWASP Foundation. OWASP Top 10:2021 A06:2021 Vulnerable and Outdated Components[EB/OL]. https://owasp.org/Top10/.",
        "[6] OWASP Foundation. OWASP Agentic Skills Top 10[EB/OL]. https://owasp.org/.",
        "[7] Snyk. ToxicSkills: An Audit of 3,984 Agentic Skills[R/OL]. https://snyk.io/.",
        "[8] 全国信息安全标准化技术委员会. GB/T 43698-2024 网络安全技术 软件供应链安全要求[S]. 北京: 中国标准出版社, 2024.",
        "[9] CycloneDX. CycloneDX Specification (v1.5)[EB/OL]. https://cyclonedx.org/specification/.",
        "[10] Python Packaging Authority. PyPI: Python Package Index[EB/OL]. https://pypi.org/.",
        "[11] Streamlit Inc. Streamlit Documentation[EB/OL]. https://docs.streamlit.io/.",
        "[12] DeepSeek. DeepSeek API Documentation[EB/OL]. https://api.deepseek.com/.",
        "[13] CISA. Known Exploited Vulnerabilities Catalog[EB/OL]. https://www.cisa.gov/known-exploited-vulnerabilities-catalog.",
        "[14] Aqua Security. Trivy Documentation[EB/OL]. https://trivy.dev/.",
    ]
    for r in refs:
        set_para(doc.add_paragraph(), r, 12)

    doc.save(OUTPUT)
    print("已生成:", OUTPUT)


if __name__ == "__main__":
    build(load_compare10())
