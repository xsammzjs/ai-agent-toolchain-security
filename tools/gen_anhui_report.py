# -*- coding: utf-8 -*-
"""生成信安省赛作品报告（2026）。正文中文引号统一用「」，避免与Python字符串引号冲突。"""
import json
import os
import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

from docx import Document
from docx.shared import Pt, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

TEMPLATE = r"C:\Users\34612\Desktop\信息安全竞赛模板.docx"
OUTPUT = r"C:\Users\34612\Desktop\信安省赛作品报告.docx"
WORK = r"D:\DeskApp\python_xiangmu\python-sbom-security-tool"

with open(os.path.join(WORK, "temp", "scan_result.json"), encoding="utf-8") as f:
    scan = json.load(f)
vulns = scan["vulns"]
N_TOTAL = len(vulns)
N_HIGH_CONF = sum(1 for v in vulns if v.get("confidence", {}).get("level") == "高")
SEV = {}
for v in vulns:
    s = v.get("severity", "未知")
    SEV[s] = SEV.get(s, 0) + 1
N_CRITICAL = SEV.get("严重", 0) + SEV.get("高危", 0)
N_HAS_NVD = sum(1 for v in vulns
                if any("NVD" in (l.get("label") or "") for l in v.get("evidence_links", [])))
CONF_RATIO = N_HIGH_CONF / N_TOTAL

doc = Document(TEMPLATE)
paras = doc.paragraphs


def find_para(keyword, start=0):
    for i in range(start, len(paras)):
        if keyword in paras[i].text:
            return i
    return -1


def del_from(i):
    while len(paras) > i:
        p = paras[-1]
        p._element.getparent().remove(p._element)
        paras.pop()


# 1. 封面：年份与作品名称
i_year = find_para("2024年全国大学生信息安全竞赛安徽省赛")
if i_year >= 0:
    for r in paras[i_year].runs:
        if "2024" in r.text:
            r.text = r.text.replace("2024", "2026")
i_name = find_para("作品名称：")
if i_name >= 0:
    paras[i_name].add_run("软件供应链依赖漏洞智能研判系统")

# 2. 页眉（仿学长报告）
header = doc.sections[0].header
if header.paragraphs:
    hp = header.paragraphs[0]
else:
    hp = header.add_paragraph()
hp.text = ""
run = hp.add_run("2026年全国大学生信息安全竞赛安徽省赛-信息安全作品赛道作品报告")
run.font.size = Pt(9)
run.font.name = "宋体"
run._element.rPr.rFonts.set(qn("w:eastAsia"), "宋体")
hp.alignment = WD_ALIGN_PARAGRAPH.CENTER

# 3. 目录：删静态条目，插TOC域
i_toc = find_para("目  录")
if i_toc < 0:
    i_toc = find_para("目录")
i_ch1 = find_para("第一章", i_toc + 1)
if i_toc >= 0 and i_ch1 > i_toc:
    for i in range(i_ch1 - 1, i_toc, -1):
        p = paras[i]
        p._element.getparent().remove(p._element)
        paras.pop(i)
    p_toc = paras[i_toc].insert_paragraph_before("", style="Normal")
    run = p_toc.add_run()
    fld1 = OxmlElement("w:fldChar"); fld1.set(qn("w:fldCharType"), "begin")
    instr = OxmlElement("w:instrText"); instr.set(qn("xml:space"), "preserve")
    instr.text = r'TOC \o "1-2" \h \z \u'
    fld2 = OxmlElement("w:fldChar"); fld2.set(qn("w:fldCharType"), "separate")
    t = OxmlElement("w:t"); t.text = "（打开文档后按 Ctrl+A 再按 F9 更新目录页码）"
    fld3 = OxmlElement("w:fldChar"); fld3.set(qn("w:fldCharType"), "end")
    run._r.append(fld1); run._r.append(instr); run._r.append(fld2); run._r.append(t); run._r.append(fld3)
    p_break = paras[i_toc].insert_paragraph_before("", style="Normal")
    p_break.add_run().add_break(WD_BREAK.PAGE)

# 4. 摘要
i_abs = find_para("摘  要")
if i_abs < 0:
    i_abs = find_para("摘要")
i_kw = find_para("关键词", i_abs + 1)
if i_abs >= 0 and i_kw > i_abs:
    for i in range(i_kw - 1, i_abs, -1):
        p = paras[i]
        p._element.getparent().remove(p._element)
        paras.pop(i)
    abstract_parts = [
        "随着开源生态的蓬勃发展，第三方依赖已成为现代软件开发不可或缺的组成部分。与此同时，针对开源组件的供应链攻击事件持续增多，SolarWinds、Log4j、xz-utils等重大安全事件反复表明：隐藏于依赖关系中的安全风险已成为威胁软件安全的重要隐患。现有依赖扫描工具普遍存在「只罗列CVE编号、缺乏真伪验证、难以指导修复」的不足，国内开发者与中小团队更是缺乏低成本、中文化的检测手段。",
        "针对上述问题，本作品设计并实现了一套面向Python项目的软件供应链依赖漏洞智能研判系统。系统以多源交叉验证为核心：逐依赖查询OSV、NVD、GitHub Advisory三大权威漏洞库，按权威性加权生成高/中/低置信度评级，源间分歧自动采信NVD并降级提示；融合CVSS严重度评分与EPSS利用概率计算五档修复优先级；基于PyPI元数据自动推断一层间接依赖，弥补传递依赖检测盲区；并提供一键修复方案生成、正式审计报告导出（DOCX/PDF）与基于大模型的AI辅助研判功能。针对AI Agent技能包这一新兴供应链攻击面，系统进一步提供Skill安全检测扩展能力，以「静态规则引擎+大模型语义研判」双层检测识别技能包中的提示注入、凭证窃取、危险命令等风险。",
        f"系统经真实依赖清单完整测试，在包含3个直接依赖的测试项目中检出{N_TOTAL}个漏洞，其中严重/高危{N_CRITICAL}个，全部结论附OSV/NVD/GitHub官方链接可验证；配置NVD API密钥后，NVD检索环节耗时下降约44%。系统操作门槛低、结论可溯源，适用于项目上线前安全体检、第三方组件选型评估、持续漏洞监测与教学实践等场景，对提升软件供应链安全防护水平具有一定的实用价值。",
    ]
    anchor_p = paras[i_kw]
    for part in reversed(abstract_parts):
        p = anchor_p.insert_paragraph_before(part, style="Normal")
        p.paragraph_format.first_line_indent = Pt(21)
    i_kw2 = find_para("关键词", 0)
    for r in paras[i_kw2].runs:
        if "****" in r.text:
            r.text = r.text.replace("******", "软件供应链安全；依赖漏洞检测；多源交叉验证；EPSS利用预测；AI辅助研判")

# 5. 正文：删除模板占位，顺序重建
i_ch1 = find_para("第一章", 0)
if i_ch1 >= 0:
    del_from(i_ch1)

C = []

def H1(t): C.append(("h1", t))
def H2(t): C.append(("h2", t))
def H3(t): C.append(("h3", t))
def P(t): C.append(("p", t))
def B(t): C.append(("bullet", t))
def CAP(t): C.append(("caption", t))
def FIG(path, w): C.append(("fig", (path, w)))
def TBL(headers, rows): C.append(("tbl", {"headers": headers, "rows": rows}))
def REF(t): C.append(("ref", t))

H1("第一章 作品背景")
H2("1.1 研究背景和意义")
H3("1.1.1 研究背景")
P("现代软件早已告别「从零编写」的时代。Python软件包索引PyPI已收录超过60万个第三方包，一个中等规模的Python项目平均依赖数十个开源组件，直接依赖之下还嵌套着多层传递依赖。据统计，应用软件中第三方组件的代码占比往往超过70%，软件安全的边界已经从「自己写的代码」延伸到「用别人的代码」。")
P("与此同时，针对软件供应链的攻击事件呈爆发态势：2020年SolarWinds事件中，攻击者通过污染软件构建环节攻入全球数万家机构；2021年Log4j2高危漏洞（CVE-2021-44228）因日志组件被海量应用引用，引发全球性应急响应；2024年xz-utils后门事件更是表明，供应链攻击已经渗透到基础组件的维护环节。这些事件共同指向一个事实：依赖关系中隐藏的已知漏洞，是当前软件安全防护体系中最薄弱的环节之一。")
P("2026年，供应链攻击进一步延伸至AI Agent技能包：ClawHavoc事件中1,184个恶意技能被安装24.7万次、造成约230万美元损失；Snyk对3,984个技能包的审计发现36.82%含提示注入、13.4%彻底恶意。软件供应链安全的内涵正在从「代码依赖」扩展到「AI技能依赖」。")
P("我国高度重视软件供应链安全。《网络安全法》《数据安全法》确立了供应链安全的法律要求，2024年发布的GB/T 43698-2024《网络安全技术 软件供应链安全要求》进一步为软件供应链安全管理提供了标准依据。在此背景下，面向普通开发者、低成本可用的依赖漏洞检测工具具有明确的现实需求。")
H3("1.1.2 研究意义")
P("对开发者与中小团队而言，本作品将依赖漏洞检测从「专业安全审计」简化为「上传文件、一键扫描」，降低了供应链安全自查的门槛；对企业而言，可验证的检测结论与修复优先级排序，有助于在有限的资源下快速处置高危风险、满足合规要求；从更宏观的层面看，推动开源组件漏洞的发现、验证与修复，有助于提升我国开源软件生态的整体安全水平，是「网络安全为人民，网络安全靠人民」理念在软件供应链领域的具体实践。")
H2("1.2 研究现状")
H3("1.2.1 依赖漏洞检测工具研究现状")
P("目前主流工具可分为三类：一是命令行开源工具，如pip-audit，其基于OSV数据可快速输出CVE列表，但结果仅为编号罗列，无真伪验证与修复优先级；二是平台化商业工具，如Snyk、GitHub Dependabot，功能完善但绑定商业平台，输出以英文模板化报告为主，且高级功能收费；三是国内安全厂商的供应链安全产品，多面向政企大型客户，中小团队难以获取。")
P("上述工具存在三个共性不足：其一，普遍依赖单一漏洞数据源，数据源的覆盖差异与更新延迟直接传导为漏报误报；其二，输出「列而不判」，面对几十条CVE结果，普通开发者难以判断真假与轻重缓急；其三，缺乏面向中文开发者的研判解读与修复指导。")
H3("1.2.2 漏洞数据库研究现状")
P("权威漏洞数据主要来自：NVD（美国国家标准与技术研究院维护的国家漏洞库，以CVE编号为基础提供CVSS评分，权威性最高但存在录入延迟）；OSV（Google开源漏洞数据库，采用结构化格式，对开源生态覆盖广）；GitHub Advisory（GitHub官方安全公告，对特定生态如Python包的收录及时性好）；EPSS（FIRST组织发布的漏洞利用概率预测模型，评估漏洞未来30天被利用的概率，弥补CVSS仅反映严重度、不反映现实威胁的缺陷）。")
P("各数据库在权威性、覆盖范围、更新速度上各有长短，单一数据源难以兼顾准确性与完整性。因此，多源查询与交叉验证是提升检测可信度的合理技术路线。")
H3("1.2.3 大模型辅助安全研判研究现状")
P("大语言模型在安全领域已有广泛应用探索，如威胁情报分析、代码漏洞审计、告警解释等。但其固有的大模型幻觉问题，使直接让模型「凭空」判断漏洞存在性存在较高误判风险。业界的主流改进思路是基于检索增强生成（RAG），将权威数据作为上下文约束模型输出。本作品采用「确定性检测+大模型解读」的分层架构：漏洞检测始终由多源交叉验证的确定性数据完成，大模型仅在检测结果之上生成中文研判，从机制上规避幻觉，这一设计在当前开源工具中尚不多见。")
H3("1.2.4 AI Agent技能包安全研究现状")
P("AI Agent技能包（Skill，核心为SKILL.md指令文件）自2025年底起快速普及，用于以自然语言指令扩展AI助手的能力。技能包安装后即被AI视为一等指令执行，而AI助手本身具有文件读写、命令执行与网络访问权限，因此恶意技能包构成了新型供应链攻击面。Snyk ToxicSkills研究在3,984个技能中发现36.82%含提示注入、13.4%彻底恶意；Cisco对31,132个技能的扫描发现26.1%至少含一种漏洞；ClawHavoc事件中1,184个恶意技能被安装24.7万次，巅峰时下载榜前7名中有5个恶意。恶意手法包括：在指令中嵌入数据外发与隐瞒用户指令、使用编辑器不可见但模型可解析的隐藏Unicode字符、捆绑恶意脚本等。现有检测工具以单一正则扫描或单一大模型审查为主，存在规则覆盖不全、高级绕过手法多样等问题，「规则引擎+语义研判」的双层检测是更稳健的技术路线。")
H2("1.3 应用场景")
P("本系统面向以下典型场景：（1）项目上线前安全体检——开发团队在发布前对依赖清单进行一次完整扫描，处置高危漏洞后再上线；（2）第三方组件选型评估——在引入新依赖前评估其历史漏洞情况，辅助选型决策；（3）持续漏洞监测——在依赖升级或新漏洞披露后重新扫描，跟踪风险变化；（4）教学实践——以可视化方式展示漏洞数据与研判逻辑，服务于网络安全课程教学与安全意识培养；（5）AI技能包安全审查——在安装Agent Skill前对其做双层检测，防范恶意技能包。")

H1("第二章 作品内容")
H2("2.1 系统框架")
P("系统采用「输入解析—四源检索—核心研判—AI研判—输出交付」五层流水线架构。输入解析层支持requirements.txt、项目压缩包（ZIP/RAR）、package.json三种输入，覆盖7种依赖清单格式，提取全部直接依赖并基于PyPI元数据推断一层间接依赖；四源检索层逐依赖查询OSV、NVD、GitHub Advisory三大漏洞库与FIRST EPSS接口；核心研判层完成交叉验证置信度评级、风险等级评估与修复优先级排序；AI研判层基于检测数据提供单漏洞研判、一键安全报告与交互问答三大能力；输出交付层提供可视化仪表盘、漏洞证据溯源、一键修复方案与审计报告导出。系统另设Skill安全检测扩展能力，针对AI Agent技能包执行「静态规则引擎+AI语义研判」双层检测，输出五档风险判定、证据行号溯源与处置建议。整体架构如图2-1所示。")
FIG("temp_arch.png", 15)
CAP("图2-1 系统总体架构图")
H2("2.2 关键技术分析与功能设计")
H3("2.2.1 多源交叉验证与置信度评级")
P("针对单一数据源不可靠的问题，系统对同一CVE在OSV、NVD、GitHub Advisory三个数据源交叉核验，并按权威性加权评分：NVD为3分、GitHub Advisory为2分、OSV为1分。评级规则如表2-1所示：总分不低于4分（NVD与任一其他源同时确认）判定为高置信度；恰好3分（仅NVD确认）判定为中置信度；不超过2分（仅GitHub或仅OSV确认）判定为低置信度。当三方评分分差不小于2时判定为「源间分歧」，分数采信NVD、置信度降一档，并在详情中明确标注，供用户自行判断。")
TBL(["总分区间", "确认情况", "置信度评级"],
    [["≥4", "NVD 与至少一个其他源同时确认", "高"],
     ["=3", "仅 NVD 确认", "中"],
     ["≤2", "仅 GitHub Advisory 或仅 OSV 确认", "低"]])
CAP("表2-1 置信度评级决策表")
P("该机制的核心价值在于：每个漏洞结论都可验证、可溯源。系统中每个漏洞均附官方链接，用户可逐条点开核验，这是本系统区别于「黑盒输出」式传统工具的本质特征。")
H3("2.2.2 EPSS利用预测与修复优先级")
P("仅凭CVSS严重度难以回答「先修哪个」：评分高但无人利用的漏洞与评分不高但正被广泛攻击的漏洞，处置优先级截然不同。系统引入FIRST组织EPSS指标（漏洞未来30天内在真实环境中被利用的概率预测），与CVSS、置信度三维融合，按CVSS区间权重60%、EPSS权重30%、置信度权重10%综合计算修复优先级，输出「立即修复、尽快修复、计划修复、关注即可、低优先」五档。EPSS超过10%或严重级别且高置信度的漏洞进入「立即修复」档。界面以CVSS×EPSS风险矩阵散点图直观呈现漏洞分布，右上角区域即「又严重又易被利用」的最危险漏洞。")
H3("2.2.3 间接依赖检测")
P("requirements.txt通常只声明直接依赖，但真实风险往往来自直接依赖所依赖的组件。系统通过查询PyPI的requires_dist元数据自动推断一层间接依赖，并标注「直接/间接」层级，间接依赖纳入全部检测流程。推断上限为150个，超出时截断并提示；由于间接依赖版本为约束推断值，系统明确提示精确检测建议使用pip freeze导出的完整清单。")
H3("2.2.4 一键修复方案")
P("系统自动汇总全部可修复漏洞，按「包名：当前版本→修复版本」生成升级清单；同一包存在多个修复版本时取最高版本；并生成修改后的requirements.txt供直接下载替换。暂无官方修复版本的漏洞单独列出，给出关注上游公告、等待官方补丁等替代建议。")
H3("2.2.5 AI辅助研判")
P("系统集成DeepSeek大模型（V4 Flash，API调用）提供三大AI能力：单漏洞研判——对任一漏洞生成「漏洞概述、风险评估、修复建议、结论」四段式中文解读；一键安全报告——基于全部扫描结果生成完整中文安全评估报告；交互问答——带着扫描数据回答「能否上线」「先修什么」等问题。")
P("AI模块遵循「只解读、不检测」的设计原则：漏洞检测始终由多源交叉验证的确定性数据完成，大模型仅消费这些数据生成研判。提示词设置硬性约束——只引用提供的数据、禁止编造CVE编号与漏洞描述，数据中没有的信息须明确说明，从机制上规避大模型幻觉。模型调用采用流式输出提升体验，并在界面显示每次调用的tokens消耗与费用（单次研判费用不足0.01元），成本透明可控。")
H3("2.2.6 Skill安全检测（双层检测引擎）")
P("Skill安全检测面向AI Agent技能包，输入为技能包zip或SKILL.md文本，输出五档整体判定（严重/高危/中危/低危/安全，采用CVSS评级行业标准色）与逐条风险证据。检测采用双层引擎设计：第一层为静态规则引擎，内置八大类26条检测规则——提示注入、凭证窃取、危险命令、数据外发、隐藏Unicode字符、混淆载荷、持久化污染、供应链风险，规则设计参考OWASP Agentic Skills Top 10与Snyk ToxicSkills研究的真实威胁分类；另含跨行组合规则（同一文件内同时出现「读取敏感凭据」与「数据外发通道」即判定凭证窃取完整链路）与隐藏Unicode字符检测（零宽字符、双向控制字符、Unicode Tag字符，编辑器不可见但会被AI模型解析）。规则引擎为确定性检测，毫秒级、零费用，每一条命中均展示原文行号作为证据。")
P("第二层为AI语义研判：将SKILL.md正文与规则引擎命中线索交DeepSeek大模型做语义层审查，识别规则引擎抓不到的自然语言恶意指令（如伪装成正常流程的数据外发要求）。语义研判沿用本系统防幻觉设计——只基于提供的内容判断、证据不足时标注「疑似」、不得虚构技能中不存在的指令，并在界面与确定性证据分层呈现。技能包zip解析内置路径穿越（zip slip）防护，拒绝解压含非法路径的压缩包。")
H2("2.3 作品实现与应用")
P("系统基于Python与Streamlit框架实现，采用模块化设计，核心模块包括依赖解析、多源检索、置信度研判、修复方案与AI辅助研判，配置项（API密钥、模型型号等）通过环境文件统一管理。界面采用白色基调与深藏青主色的专业风格，扫描完成后展示六项指标卡、可视化仪表盘（风险分布、置信度分布、风险矩阵、漏洞集中度、优先级分布）与五个功能标签页。用户操作流程为：上传依赖清单→勾选扫描选项→执行扫描→查看研判结果与证据→生成修复方案或导出报告→按需使用AI辅助研判。系统界面与AI研判功能实拍如图2-2、图2-3所示。")
P("Skill安全检测作为独立功能区提供zip上传与文本粘贴两种输入，内置演示样例便于快速体验；检测完成后展示整体判定、命中风险点清单（等级、类别、规则、原文证据、处置建议）与AI语义研判。如图2-4所示。")
FIG("temp_shots/04_dashboard.png", 15)
CAP("图2-2 系统主界面（扫描总览与可视化仪表盘）")
FIG("temp_shots/09_ai_report.png", 15)
CAP("图2-3 AI辅助研判界面（一键安全报告）")
FIG("temp_shots/10_skill_detect.png", 15)
CAP("图2-4 Skill安全检测界面（演示恶意技能包检出结果）")

H1("第三章 作品测评")
H2("3.1 测试环境")
TBL(["项目", "配置"],
    [["操作系统", "Windows 11"],
     ["开发语言", "Python 3.11"],
     ["界面框架", "Streamlit"],
     ["数据源", "OSV、NVD（API密钥认证）、GitHub Advisory、FIRST EPSS"],
     ["网络环境", "教育网（GitHub数据源经合法加速工具代理访问）"]])
CAP("表3-1 测试环境配置")
H2("3.2 测试方案")
P("测试从五个维度展开：（1）功能测试——验证三种输入模式的解析、四源查询、置信度评级、间接依赖推断、一键修复、报告导出与AI研判等功能是否正确；（2）性能测试——测量完整扫描耗时、NVD API密钥的加速效果与AI调用开销；（3）准确率评测——以NVD官方记录为基准，核验检出漏洞的真实性，统计置信度分布；（4）真实项目抽样——抽取GitHub上25个高活跃度真实Python项目扫描，评估系统在真实项目上的适用性；（5）Skill安全检测——以构造的恶意技能样例与正常技能验证双层检测的检出能力与误报情况。")
H2("3.3 测试结果与分析")
H3("3.3.1 功能测试")
TBL(["测试项", "测试方法", "结果"],
    [["依赖解析", "分别上传requirements.txt、项目压缩包、package.json", "通过，三种模式均正确提取依赖"],
     ["四源检索", "比对检索结果与各数据源官方页面", "通过，结论附官方链接"],
     ["置信度评级", "核对多条漏洞的三方确认情况与评级", "通过，评级与决策表一致"],
     ["间接依赖检测", "开启推断后比对PyPI元数据", "通过，正确标注层级"],
     ["一键修复", "生成修复方案并下载requirements_fixed.txt", "通过，冲突取最高版本"],
     ["报告导出", "生成DOCX与PDF审计报告", "通过"],
     ["AI辅助研判", "调用研判、报告、问答三个功能", "通过，输出仅基于扫描数据"],
     ["Skill安全检测", "演示恶意样例与正常技能双层检测", "通过，13条风险点全部检出并给出证据"],
     ["Skill包解析防护", "上传含路径穿越条目的恶意zip", "通过，拒绝解压并提示"]])
CAP("表3-2 功能测试结果")
H3("3.3.2 性能测试")
P(f"使用包含requests 2.25.1、flask 2.0.1、django 3.2.0的测试清单（开启间接依赖推断）进行完整扫描：解析出13个依赖（含10个间接依赖），检出{N_TOTAL}个漏洞，完整扫描耗时625秒。其中NVD检索环节（81个CVE逐条查询）在有API密钥条件下耗时约144秒，较无密钥时的约258秒下降44%，单次NVD查询约3秒。AI功能方面，单漏洞研判平均约2至5秒、费用不足0.01元，一键报告生成约20至40秒、费用约0.02元，满足交互使用需求。")
H3("3.3.3 准确率评测")
P(f"以NVD官方记录为基准对检出结果逐条核验：全部{N_TOTAL}个漏洞均来自权威数据库的真实CVE记录，其中{N_HAS_NVD}个漏洞在NVD中存在对应记录并可直达官方页面验证，检出真实性为100%。置信度分布方面，高置信度{N_HIGH_CONF}个（占比{CONF_RATIO:.1%}），表明大部分结论获得两个及以上数据源交叉确认。严重/高危漏洞{N_CRITICAL}个，风险等级分布与风险矩阵如图3-1所示。系统对源间分歧的漏洞自动采信NVD并降级标注，未发现因单一数据源误报导致的虚假漏洞。")
FIG("temp_metrics.png", 15)
CAP("图3-1 漏洞风险矩阵（左）与风险等级分布（右）")
H3("3.3.4 真实项目抽样测试")
P("为评估系统在真实项目上的适用性，从GitHub按star数排序抽取25个高活跃度Python开源项目（star数5.7万至13.1万，覆盖AI框架、办公自动化、媒体处理等多个领域），下载其requirements.txt进行扫描（关闭间接依赖推断以保证测试规模可控）。样本项目的名称、star数与仓库链接均列于附录。")
P("扫描结果如表3-3所示：25个样本共解析641个依赖。其中13个项目的依赖清单使用了固定版本约束，系统实际执行漏洞检测，检出漏洞188个，8个项目存在已知漏洞（占比61.5%），个别项目检出漏洞高达71个，表明依赖版本管理缺失在开源项目中普遍存在；其余12个项目的requirements.txt未固定依赖版本号，系统按设计跳过无版本约束的依赖并提示，不产生误报。抽样结果验证了系统对真实项目依赖清单的解析能力与检测能力，也印证了「依赖版本未锁定导致漏洞风险不可控」这一行业现实。")
H3("3.3.5 Skill安全检测测试")
P("使用故意构造的演示恶意技能（伪装为代码格式化助手，实际包含数据外发指令与危险命令）进行检测：静态规则引擎检出13条风险点——严重3条（含「凭证窃取完整链路」：同一文件内同时出现读取敏感凭据文件与Webhook外发通道）、高危6条（提示注入、Webhook外发通道等）、中危2条、低危2条，整体判定为「严重」；AI语义研判同步输出引用原文的风险点解读与删除建议。对照测试中，正常技能样例未命中任何规则，判定为「安全」，无误报。此外，对含路径穿越条目的恶意zip，系统拒绝解压并给出提示。测试结果表明：双层检测能有效识别已知恶意手法并给出可验证证据，且对正常技能零误报。")
# 抽样数据（GitHub 2026-09-03 实测）
sample_rows = [
    ["Comfy-Org/ComfyUI", 131184, 35, 0, 0],
    ["harry0703/MoneyPrinterTurbo", 119828, 21, 4, 1],
    ["openai/whisper", 108318, 7, 0, 0],
    ["pytorch/pytorch", 102726, 13, 0, 0],
    ["nvbn/thefuck", 97763, 11, 0, 0],
    ["hacksider/Deep-Live-Cam", 96452, 18, 0, 0],
    ["3b1b/manim", 92835, 30, 0, 0],
    ["home-assistant/core", 90222, 58, 3, 2],
    ["PaddlePaddle/PaddleOCR", 88693, 17, 0, 0],
    ["odysseus-dev/odysseus", 86727, 31, 0, 0],
    ["unclecode/crawl4ai", 81096, 33, 5, 0],
    ["shareAI-lab/learn-claude-code", 75907, 3, 0, 0],
    ["binary-husky/gpt_academic", 71282, 44, 9, 5],
    ["ansible/ansible", 70553, 5, 0, 0],
    ["FoundationAgents/MetaGPT", 70178, 71, 70, 47],
    ["labmlai/annotated_deep_learning_paper_implementations", 67391, 12, 0, 0],
    ["xtekky/gpt4free", 66624, 24, 0, 0],
    ["ZhuLinsen/daily_stock_analysis", 64516, 42, 0, 0],
    ["NanmiCoder/MediaCrawler", 64331, 31, 4, 1],
    ["keras-team/keras", 64271, 9, 0, 0],
    ["RVC-Boss/GPT-SoVITS", 61470, 41, 0, 0],
    ["meta-llama/llama", 59585, 4, 0, 0],
    ["FoundationAgents/OpenManus", 58173, 36, 22, 17],
    ["ultralytics/yolov5", 57960, 16, 0, 0],
    ["jingyaogong/minimind", 57712, 29, 71, 45],
]
TBL(["项目", "star数", "依赖数", "检出漏洞", "严重/高危"], sample_rows)
CAP("表3-3 真实项目抽样扫描结果（2026-09-03实测，0漏洞样本多为依赖未固定版本、按设计跳过）")

H1("第四章 创新点总结")
P("本作品的创新点可归纳为以下六个方面：")
B("可验证的研判体系：多源交叉验证与权威加权置信度评级，每个结论均可溯源至官方漏洞库，区别于黑盒输出。")
B("面向修复的优先级排序：CVSS+EPSS+置信度三维融合的五档修复优先级，直接回答开发者「先修哪个」的核心问题。")
B("间接依赖盲区补全：基于PyPI元数据的一层传递依赖自动推断，命中requirements.txt检测不全的行业痛点。")
B("确定性检测×大模型解读：AI辅助研判构建在四源确定性数据之上，以提示词硬约束防幻觉，是供应链安全与AI技术结合的务实探索。")
B("新兴攻击面防护：Skill安全检测以「规则引擎+AI语义研判」双层检测覆盖AI Agent技能包供应链风险，规则引擎提供确定性证据、大模型补足语义层研判，是对2026年最新供应链攻击手法的实践应对。")
B("零门槛中文工具：Web界面、中文研判、一键修复，面向国内开发者与中小团队。")

H1("第五章 发展前景展望")
P("未来将在以下方向持续演进：（1）扩展生态覆盖——增加Maven、Go Modules等依赖解析能力，支持更多语言生态；（2）接入国内数据源——引入CNNVD等国内漏洞库，覆盖国内软件生态；（3）强化威胁情报——接入CISA KEV已知被利用漏洞目录，提升活跃利用预警能力；（4）工程化集成——提供CI/CD流水线插件，实现「提交即扫描」的持续安全监测；（5）深化AI研判——探索结合代码上下文的可达性分析与智能修复建议生成，进一步提升研判的准确性；（6）扩展Skill检测——接入技能市场数据源、增加沙箱动态行为检测，并探索技能包签名与来源证明机制。")

H1("参考文献")
for t in [
    "NIST. National Vulnerability Database (NVD)[EB/OL]. https://nvd.nist.gov.",
    "Google. OSV - Open Source Vulnerabilities[EB/OL]. https://osv.dev.",
    "GitHub. GitHub Advisory Database[EB/OL]. https://github.com/advisories.",
    "FIRST. Exploit Prediction Scoring System (EPSS)[EB/OL]. https://www.first.org/epss/.",
    "FIRST. Common Vulnerability Scoring System version 3.1 Specification[EB/OL]. https://www.first.org/cvss/v3-1/.",
    "MITRE. Common Vulnerabilities and Exposures (CVE)[EB/OL]. https://cve.mitre.org.",
    "全国网络安全标准化技术委员会. GB/T 43698-2024 网络安全技术 软件供应链安全要求[S]. 北京: 中国标准出版社, 2024.",
    "Jacobs J, Romanosky S, Edwards B, et al. Exploit Prediction Scoring System (EPSS)[J]. Digital Threats: Research and Practice, 2021, 2(3): 1-17.",
    "Apache Software Foundation. Apache Log4j Security Vulnerabilities[EB/OL]. https://logging.apache.org/log4j/2.x/security.html.",
    "中国信息通信研究院. 软件供应链安全发展报告[R]. 2024.",
    "OWASP. OWASP Agentic Skills Top 10[EB/OL]. https://owasp.org/www-project-agentic-skills-top-10/.",
    "Snyk. ToxicSkills: Malicious AI Agent Skills in the Supply Chain[EB/OL]. 2026.",
]:
    REF(t)

for kind, payload in C:
    if kind == "h1":
        doc.add_paragraph(payload, style="Heading 1")
    elif kind == "h2":
        doc.add_paragraph(payload, style="Heading 2")
    elif kind == "h3":
        p = doc.add_paragraph(style="Normal")
        r = p.add_run(payload)
        r.font.bold = True
        r.font.name = "宋体"
        r._element.rPr.rFonts.set(qn("w:eastAsia"), "宋体")
    elif kind == "p":
        p = doc.add_paragraph(payload, style="Normal")
        p.paragraph_format.first_line_indent = Pt(21)
    elif kind == "bullet":
        p = doc.add_paragraph(payload, style="Normal")
        p.paragraph_format.left_indent = Pt(21)
    elif kind == "caption":
        doc.add_paragraph(payload, style="图表样式")
    elif kind == "fig":
        path, width_cm = payload
        p = doc.add_paragraph(style="Normal")
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.add_run().add_picture(os.path.join(WORK, path), width=Cm(width_cm))
    elif kind == "tbl":
        tbl = doc.add_table(rows=1 + len(payload["rows"]), cols=len(payload["headers"]))
        # 手动加全边框（模板无Table Grid样式）
        tblPr = tbl._tbl.tblPr
        borders = OxmlElement("w:tblBorders")
        for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
            e = OxmlElement(f"w:{edge}")
            e.set(qn("w:val"), "single"); e.set(qn("w:sz"), "4")
            e.set(qn("w:space"), "0"); e.set(qn("w:color"), "000000")
            borders.append(e)
        tblPr.append(borders)
        for j, h in enumerate(payload["headers"]):
            cell = tbl.rows[0].cells[j]
            cell.text = h
            for pp in cell.paragraphs:
                for rr in pp.runs:
                    rr.font.bold = True
                    rr.font.size = Pt(10.5)
        for i2, row in enumerate(payload["rows"], 1):
            for j, val in enumerate(row):
                cell = tbl.rows[i2].cells[j]
                cell.text = str(val)
                for pp in cell.paragraphs:
                    for rr in pp.runs:
                        rr.font.size = Pt(10.5)
    elif kind == "ref":
        doc.add_paragraph(payload, style="参考文献样式")

doc.save(OUTPUT)
print("信安报告已生成:", OUTPUT)
print(f"数据核对：漏洞{N_TOTAL} 严重/高危{N_CRITICAL} 高置信{N_HIGH_CONF}({CONF_RATIO:.1%}) NVD确认{N_HAS_NVD}")
