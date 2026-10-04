# -*- coding: utf-8 -*-
"""生成AI大模型创新应用大赛作品报告（2026）。基于桌面"作品赛竞赛模板.docx"填写。正文10页内。"""
import os
import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

from docx import Document
from docx.shared import Pt, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

TEMPLATE = r"C:\Users\34612\Desktop\作品赛竞赛模板.docx"
OUTPUT = r"C:\Users\34612\Desktop\AI大模型大赛作品报告.docx"
WORK = r"D:\DeskApp\python_xiangmu\python-sbom-security-tool"

doc = Document(TEMPLATE)
paras = doc.paragraphs


def find_para(keyword, start=0):
    for i in range(start, len(paras)):
        if keyword in paras[i].text:
            return i
    return -1


def add_body(text, indent=True, bold=False):
    """正文段落（Normal样式继承模板宋体五号1.5倍行距）"""
    p = doc.add_paragraph(style="Normal")
    r = p.add_run(text)
    r.font.bold = bold
    if indent:
        p.paragraph_format.first_line_indent = Pt(21)
    return p


def add_h3(text):
    """小节标题（模板无三级标题样式，用加粗宋体）"""
    p = doc.add_paragraph(style="Normal")
    r = p.add_run(text)
    r.font.bold = True
    r.font.name = "宋体"
    r._element.rPr.rFonts.set(qn("w:eastAsia"), "宋体")
    return p


# ================= 1. 封面：作品名称 =================
i_name = find_para("作品名称：")
if i_name >= 0:
    paras[i_name].add_run("基于AI辅助研判的软件供应链依赖漏洞检测系统")

# ================= 2. 简介表格填写 =================
tbl = doc.tables[0]
# 定位行（按首单元格文字）
row_map = {}
for row in tbl.rows:
    key = row.cells[0].text.strip()
    row_map[key] = row

def fill_cell(row, col, text):
    cell = row.cells[col]
    # 清空原模板文字，写入新内容
    cell.text = ""
    p = cell.paragraphs[0]
    r = p.add_run(text)
    r.font.name = "宋体"
    r._element.rPr.rFonts.set(qn("w:eastAsia"), "宋体")

fill_cell(row_map["作品名称"], 1, "基于AI辅助研判的软件供应链依赖漏洞检测系统")
# 主题栏保留模板文字，9月6日主题公布后由用户自行修改
# 作品简介：模板为横向合并单元格——标签行保留"作品简介"，内容写入标签下方的说明行
intro_text = (
    "本作品是一个面向Python项目的软件供应链依赖漏洞检测系统，并创新性地引入大模型作为安全研判层。"
    "系统对项目依赖进行OSV、NVD、GitHub Advisory、FIRST EPSS多源交叉验证检测后，调用DeepSeek大模型对检测结果进行中文研判，"
    "提供单漏洞风险解读、一键安全评估报告生成与交互问答三大AI能力，将机器可读的漏洞数据转化为开发者可读的安全研判结论。"
    "系统解决了传统工具「只列CVE编号、缺乏解读、难以指导修复」的痛点，单次AI研判费用不足0.01元，成本透明可控。")
for row in tbl.rows:
    merged_text = "".join(c.text for c in row.cells)
    if "简明扼要" in merged_text:
        cell = row.cells[0]  # gridSpan 合并，cells[0] 即整个单元格
        cell.text = ""
        p = cell.paragraphs[0]
        r = p.add_run(intro_text)
        r.font.name = "宋体"
        r._element.rPr.rFonts.set(qn("w:eastAsia"), "宋体")
        break
fill_cell(row_map["作品来源"], 1, "原创")
fill_cell(row_map["应用行业"], 1, "网络安全、软件开发")
fill_cell(row_map["数据来源"], 1, "OSV、NVD、GitHub Advisory、FIRST EPSS公开漏洞数据库；PyPI软件包元数据")
fill_cell(row_map["作品展示"], 1, "Web应用（Streamlit本地运行，部署网址与演示视频随作品提交）")

# ================= 3. 正文 =================
i_body = find_para("正文")
i_tail = find_para("建议包括但不限定于以下内容：", i_body + 1)
if i_tail > i_body:
    # 删除"正文"标题之后的模板提示段落
    for i in range(len(paras) - 1, i_body, -1):
        p = paras[i]
        p._element.getparent().remove(p._element)
        paras.pop(i)

add_h3("（一）选题定位")
add_body("软件供应链安全已成为网络安全领域最突出的风险来源之一。SolarWinds事件、Log4j2高危漏洞、xz-utils后门事件反复证明：软件的风险往往不在开发者自己编写的代码中，而在所依赖的第三方开源组件中。然而，现有依赖扫描工具普遍存在「列而不判」的问题：pip-audit等开源工具仅输出CVE编号列表，缺乏真伪验证与修复优先级；Snyk等商业平台输出英文模板化报告，中小团队难以负担，且无法提供贴近开发者语言习惯的中文解读。")
add_body("大语言模型为这一痛点提供了全新的解决思路：大模型天然擅长将结构化数据转化为自然语言解读。但若直接让大模型「凭空」判断漏洞存在性，幻觉问题将带来严重误判。本作品的设计定位是：漏洞检测由多源交叉验证的确定性数据完成，大模型作为检测之上的研判层，将权威数据翻译为中文研判结论。这一「确定性检测×大模型解读」的分层架构，既发挥了AI的理解与生成能力，又从机制上规避了幻觉风险，是大模型技术在软件供应链安全领域的一次务实落地。")

add_h3("（二）社会价值")
add_body("目标用户为Python开发者、高校学生团队与中小软件企业，使用场景覆盖项目上线前安全体检、第三方组件选型评估与持续漏洞监测。本作品的社会价值体现在四个方面：其一，降低安全门槛——不具备安全专业背景的普通开发者通过「上传文件、一键扫描」即可完成供应链安全自查，AI研判将专业的安全结论转化为人人可读的中文解读；其二，提升修复效率——AI结合CVSS评分、EPSS利用概率与置信度给出修复优先级与具体建议，开发者得以聚焦真正高危的漏洞；其三，成本可控——大模型按量计费，单次研判费用不足0.01元，完整安全报告约0.02元，远低于商业平台订阅成本，且界面实时显示tokens消耗与费用，成本完全透明；其四，可推广性强——系统以Web应用形式提供，检测结论全部附官方漏洞库链接可验证，AI研判仅基于检测数据输出，具备向企业级持续安全监测演进的工程潜力。")

add_h3("（三）技术方案")
add_body("1、技术方向", bold=True, indent=False)
add_body("作品的技术方向为「软件供应链依赖漏洞检测+大模型安全研判」的融合应用。系统由检测引擎与AI研判层两部分构成：检测引擎采用「解析—检索—研判」流水线，解析requirements.txt等输入提取全部依赖，逐依赖查询OSV、NVD、GitHub Advisory三大漏洞库与FIRST EPSS接口，按权威性加权（NVD 3分、GitHub 2分、OSV 1分）生成高/中/低置信度评级，并融合CVSS与EPSS计算五档修复优先级；AI研判层基于检测引擎产出的确定性数据，提供单漏洞研判、一键安全报告与交互问答三大功能。")
add_body("2、所选AI大模型及方案创新性", bold=True, indent=False)
add_body("作品选用DeepSeek V4 Flash大模型，通过官方API调用。选型依据：其一，性能满足研判任务需求，Flash模型在文本理解与结构化生成任务上表现优秀；其二，成本优势显著，输入1元/百万tokens、输出2元/百万tokens，单次研判费用不足0.01元，适合作为长期驻留的研判服务；其三，官方API稳定可靠，支持流式输出与参数调节，模型型号通过配置文件可切换，答辩现场可随时切换至更高性能的V4 Pro型号。")
add_body("方案的创新性体现在三点：第一，分层防幻觉架构——与「直接询问通用大模型漏洞问题」的做法不同，本作品的大模型输入始终是经过四源交叉验证的结构化漏洞数据，提示词硬性约束「只引用提供的数据、禁止编造CVE编号」，数据中没有的信息须明确说明，从机制上切断幻觉来源；第二，面向研判的提示词工程——针对研判、报告、问答三个场景分别设计角色设定、数据注入方式与输出结构约束，将大模型塑造为「软件供应链安全分析师」而非通用聊天机器人；第三，成本透明机制——每次调用实时显示tokens消耗与估算费用，这一工程细节在同类作品中少见，体现了成本意识。与现有产品相比：Snyk等商业工具的报告为英文模板化输出且高级功能收费，pip-audit等开源工具无任何解读能力，本作品以极低成本提供可溯源的中文AI研判，形成差异化优势。")
# 插图：系统架构图与AI报告生成界面（居中）
def add_fig(path, width_cm):
    p = doc.add_paragraph(style="Normal")
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.add_run().add_picture(os.path.join(WORK, path), width=Cm(width_cm))

add_fig("temp_arch.png", 14.5)
add_fig("temp_shots/09_ai_report.png", 14.5)

add_body("3、提示词设计及处理方法", bold=True, indent=False)
add_body("系统设计了三个场景的提示词模板。研判场景：角色设定为「资深软件供应链安全分析专家」，注入单条漏洞的JSON结构化上下文（CVE编号、组件版本、风险等级、CVSS、EPSS、置信度、修复版本等字段），要求输出固定四段结构——漏洞概述、风险评估、修复建议、一句话结论。报告场景：角色设定为「软件供应链安全审计专家」，注入全部扫描结果的压缩摘要（总体统计与漏洞清单），要求生成含总体安全态势、TOP高危漏洞解读、修复优先级建议、改进建议四章节的中文评估报告。问答场景：注入相同扫描摘要并附加用户问题，要求仅引用数据中真实存在的漏洞回答，数据缺失时明确说明「扫描数据中没有相关记录」。")
add_body("在提示词处理方法上，作品采用了五项工程化措施：数据预处理——将扫描结果压缩为JSON摘要，漏洞描述截断至100字、清单上限80条，控制上下文规模；输出约束——三个提示词均包含「禁止编造、只引用数据」的硬性约束条款；参数调优——temperature设为0.3保证输出稳定，max_tokens按场景分级（研判1500、报告6000、问答2000）；关闭思考模式——经测试发现V4 Flash默认思考模式会将额度全部用于内部推理导致正文空白，通过thinking参数关闭；流式输出——采用SSE流式传输实现打字机式展示，提升交互体验。")
add_body("4、技术中所遇到的问题", bold=True, indent=False)
add_body("开发过程中主要遇到四个问题并逐一解决：一是NVD官方API密钥申请困难——申请页面采用Cloudflare Turnstile人机验证，在国内网络环境下多次失败，最终成功获得密钥后，通过请求头传递认证并将查询间隔从匿名模式的约6秒缩短至0.7秒，NVD检索环节耗时下降约44%；二是nvdlib库新版兼容性问题——新版要求带密钥调用时请求间隔必须大于0.6秒，且CWE字段返回结构由字典变为对象，经逐一调试适配后修复；三是大模型思考模式导致空输出——生成报告时发现输出正文为空、finish_reason为length，定位为思考模式耗尽额度，通过关闭思考模式并分级设置max_tokens解决；四是上下文规模控制——81个漏洞的完整数据注入大模型时上下文过长，通过摘要压缩、字段截断与数量上限控制，在信息完整性与token成本之间取得平衡。")

doc.save(OUTPUT)
print("AI比赛报告已生成:", OUTPUT)
