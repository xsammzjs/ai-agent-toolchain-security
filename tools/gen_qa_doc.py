"""生成组会答辩准备手册 DOCX"""
from docx import Document
from docx.shared import Pt, Cm, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
import os
from datetime import datetime

doc = Document()
style = doc.styles['Normal']
style.font.name = 'Microsoft YaHei'
style.font.size = Pt(10.5)
style.paragraph_format.line_spacing = 1.4
style._element.rPr.rFonts.set(qn('w:eastAsia'), 'Microsoft YaHei')

for sec in doc.sections:
    sec.top_margin = Cm(2.2)
    sec.bottom_margin = Cm(2.2)
    sec.left_margin = Cm(2.5)
    sec.right_margin = Cm(2.5)

def add_title(text):
    p = doc.add_heading(text, level=1)

def add_subtitle(text):
    p = doc.add_heading(text, level=2)

def add_body(text):
    doc.add_paragraph(text)

def add_qa(q, a):
    p = doc.add_paragraph()
    r = p.add_run(f'Q: {q}')
    r.font.bold = True
    r.font.color.rgb = RGBColor(0xc0, 0x39, 0x2b)
    p2 = doc.add_paragraph(f'A: {a}')
    p2.paragraph_format.left_indent = Cm(0.8)

# ====== 封面 ======
for _ in range(6):
    doc.add_paragraph('')

p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = p.add_run('组会答辩准备手册')
r.font.size = Pt(26)
r.font.bold = True

p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = p.add_run('Python依赖漏洞智能研判系统')
r.font.size = Pt(14)
r.font.color.rgb = RGBColor(0x7f, 0x8c, 0x8d)

doc.add_paragraph('')

p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = p.add_run(f'汇报日期：{datetime.now().strftime("%Y年%m月%d日")}')
r.font.size = Pt(11)

p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = p.add_run('包含：汇报话术 + 常见问题 + 应答策略')
r.font.size = Pt(10)
r.font.color.rgb = RGBColor(0x95, 0xa5, 0xa6)

doc.add_page_break()

# ====== 一、汇报话术 ======
add_title('一、5分钟汇报话术')

add_subtitle('开场（30秒）')
add_body('各位老师好，我这个月主要做了一件事：把自己的Python依赖漏洞检测工具做了一次聚焦升级。下面我直接演示。')

add_subtitle('演示作品（2分钟）')
add_body('（打开Streamlit界面，上传temp/text_requirements.txt，边操作边说）')
add_body('这是一个Python项目依赖的漏洞扫描工具。上传一个requirements.txt，点击扫描，它会自动去四个公开的漏洞数据库查询——OSV查有没有漏洞，NVD查CVSS分数有多严重，GitHub查怎么修，EPSS查被利用的概率。')
add_body('扫描完成后，上面是6个指标卡。下面自动生成5张可视化图表。这张风险矩阵散点图是最关键的——横轴是CVSS严重度，纵轴是EPSS利用概率，右上角的点就是又严重又容易被攻击的漏洞，必须最先修。')
add_body('切换到漏洞详情标签页，展开任意一条漏洞，能看到完整证据链——CVSS分数从哪来的、置信度为什么这么评、NVD和GitHub的官方链接。点开链接可以直接在NVD官网验证漏洞是不是真的。')

add_subtitle('讲核心思路（1分钟）')
add_body('和上个版本比，这个月我没急着加新功能。上次老师反馈说功能太散、堆了很多东西但不深入。这次我把方向聚焦到一个点上：漏洞检测的真实性和准确性。')
add_body('核心就是三件事：多源交叉验证、置信度评级、修复优先级排序。同一个漏洞去三个数据库查，三方都说有才标高置信度。然后综合CVSS严重度、EPSS利用概率、置信度三个维度加权，算出修复优先级。')
add_body('功能数量比上个版本少了，但核心功能的深度提高了。每个漏洞结论都有NVD官方链接可以验证。')

add_subtitle('下一步计划（30秒）')
add_body('接下来打算做一键修复功能——扫描完之后工具自动帮项目把漏洞依赖升级到安全版本。同时准备参加10月份的省赛。以上是我的汇报，请老师指正。')

doc.add_page_break()

# ====== 二、技术问题 ======
add_title('二、技术常见问题（15个）')

qas = [
    ("这个工具是怎么工作的？从上传到出结果讲一下",
     "第一步解析依赖文件，提取包名和版本号。第二步拿包名和版本号去四个公开数据库查漏洞——OSV查有没有，NVD查CVSS分数，GitHub查修复版本，EPSS查利用概率。第三步交叉验证，三个数据库信息拼在一起给置信度。第四步综合三个维度加权算出修复优先级。第五步生成报告和图表。每一步都清晰透明。"),

    ("什么是三源交叉验证？怎么做的？",
     "同一个漏洞去三个数据库查。比如CVE-2021-35042，OSV说有漏洞给9.8分，NVD也说有给9.8分，GitHub也说有给了修复版本。三方都确认且分数差在2分以内，就标记置信度'高'。如果只有一个数据库说了，或者分数差异很大，就标'低'置信度。相当于多找几个医生会诊。"),

    ("OSV、NVD、GitHub Advisory分别是什么？",
     "OSV是Google维护的开源漏洞库，告诉你有漏洞没有。NVD是美国政府的国家漏洞库，给出权威的CVSS分数。GitHub Advisory是GitHub的安全公告，告诉你怎么修。三者都是免费公开API。"),

    ("EPSS是什么？为什么用这个？",
     "EPSS是漏洞利用预测评分。CVSS告诉你漏洞多严重，但严重不等于有人在用。EPSS告诉你这个漏洞未来30天被利用的概率。比如CVSS 9.8但EPSS只有1%，说明没人用；CVSS 5.0但EPSS 50%，反而更要关注。"),

    ("修复优先级怎么算的？",
     "三个维度加权：CVSS严重度占60%（洞大不大）、EPSS利用概率占30%（有没有人在用）、置信度占10%（消息可不可信）。算出一个综合分，8分以上立即修复，6-8尽快修复，4-6计划修复，2-4关注即可，2以下低优先。"),

    ("风险等级怎么划分的？",
     "用的是CVSS国际标准：9分以上严重，7-9分高危，4-7分中危，0-4分低危。这不是我定的，是国际通用标准。"),

    ("图表是怎么画出来的？",
     "Streamlit框架自带的图表功能。把数据整理成DataFrame表格，传给st.bar_chart()或st.scatter_chart()，自动出图。不需要额外装任何库，就像Excel里选中数据点插入图表一样。"),

    ("依赖解析遇到版本区间怎么处理？",
     "比如>=2.0,<3.0，去掉操作符，取第一个合法数字2.0去查询。遇到==3.2.1直接用3.2.1。只是提取数字，不做复杂的版本范围匹配。"),

    ("NVD为什么有时候查不到？",
     "三个原因：漏洞太新NVD没录入（NVD更新比OSV慢）；有些漏洞NVD根本没收录；网络超时（NVD服务器在国外）。所以要多源交叉验证，一个查不到还有另外两个。"),

    ("置信度评级具体规则是什么？",
     "三个数据库都确认+分数精确+分数差2分以内=高置信度；两个数据库确认+精确分数=中置信度；只有一个来源但分数是精确的=中置信度；分数是估算的=低置信度。"),

    ("你怎么保证查出来的漏洞是真的？",
     "两条：第一，交叉验证——不多于一个来源确认的不标高置信度；第二，每个漏洞都有NVD官方链接，点进去就能在官网验证。不靠我说，靠官方数据。"),

    ("你的数据来源可靠吗？",
     "四个数据源都是国际公认的权威机构——OSV是Google的，NVD是美国政府的，GitHub Advisory是GitHub官方的，EPSS是FIRST组织的。没有自己编造的数据。"),

    ("报告里都包含什么内容？",
     "五部分：扫描摘要（依赖数、漏洞数等）；漏洞清单（含置信度、优先级）；每个漏洞的详细证据（含NVD/GitHub链接）；项目依赖清单；修复建议（按优先级排序）。"),

    ("SBOM是什么？",
     "SBOM是软件物料清单，Bill of Materials。就是一份清单列出你项目用了哪些第三方组件和版本。CycloneDX是国际标准格式。出了问题能快速知道哪些项目受影响。我的工具自动生成CycloneDX 1.5标准SBOM。"),

    ("你这个工具支持哪些文件格式？",
     "Python: requirements.txt, pyproject.toml, Pipfile, poetry.lock等6种格式。还初步支持npm的package.json。后续计划支持更多。"),
]

for q, a in qas:
    add_qa(q, a)

doc.add_page_break()

# ====== 三、灵魂问题 ======
add_title('三、可能遇到的"灵魂问题"（8个）')

soul_qas = [
    ("你这个代码是不是AI写的？",
     "用了AI辅助，但逻辑是我设计的。交叉验证的规则——三方确认才标高等、分数差2分以内算一致——这是我自己想的。AI帮我写了代码框架，但核心思路和数据流程我定的。每一行代码我都能讲清楚在做什么。"),

    ("你做的东西也太简单了吧？",
     "是的功能不多，但我是有意的。之前做过一个版本功能很多但每个都很浅，老师也反馈不够聚焦。这个月我把精力集中在漏洞检测的准确性上，先把一件事做对。现在核心链路跑通了，后面加功能会很快——架构是流水线式的，加一个模块不影响其他。"),

    ("你这个跟市面上已有的工具有什么区别？",
     "墨菲安全是企业级商业产品，收费高门槛高。我面向个人开发者和小团队，做轻量免费工具。核心差异：第一，每个结论都有NVD/GitHub公开链接可验证，不是黑盒；第二，后续要做一键修复——扫描完自动升级依赖到安全版本，商业产品反而因为怕担责任不敢做自动修复。"),

    ("你的检测准确率是多少？测过吗？",
     "诚实说目前没有系统性的准确率测试。但我用含已知漏洞的测试数据跑过，能正确检出，NVD链接都能验证。后面需要找标注测试集做评估。现在至少保证——我标出来的每个漏洞，都能在NVD官网查到。"),

    ("你这个能商用吗？",
     "目前是学生作品，离商用有距离。但方向有需求——开源社区大量中小项目没有专门的供应链安全工具。后续做成GitHub开源项目，小团队可以免费用。"),

    ("你7月份到底学了什么？",
     "7月份还考了驾照，时间有限。但在有限时间里做了几件事：第一，看了国赛几百个作品名单分析大家做啥方向，发现供应链安全是蓝海；第二，把之前版本聚焦升级，核心模块做深；第三，跟着焦宇阳学长参与国赛项目学习。"),

    ("你的技术能力能支撑后续升级吗？",
     "目前能力还不够，很多技术词边学边查。但暑假剩下的时间集中补。8月做一键修复，同时搞懂学长的项目。做一点学一点，到10月省赛能做出完整版本。"),

    ("一句话总结你的项目？",
     "一个告诉你项目用了哪些有漏洞的依赖、有没有人真的在攻击、应该先修哪个、每个结论都能在NVD官网验证的工具。"),
]

for q, a in soul_qas:
    add_qa(q, a)

doc.add_page_break()

# ====== 四、展示技巧 ======
add_title('四、现场演示注意事项')

tips = [
    "提前打开Streamlit做好扫描，不要现场等（扫描要1-3分钟）",
    "用temp/text_requirements.txt测试，能稳定检出36个漏洞",
    "重点展示风险矩阵散点图，这张图最直观最有说服力",
    "现场点开一个漏洞的NVD链接，证明可验证——这是最强证据",
    "如果网络出问题扫不出来，用提前截好的图代替",
    "语速慢一点不要赶，5分钟讲不完就讲到哪算哪",
    "答不上来的问题直接说'这块我还没研究到，后面会补上'",
]
for t in tips:
    doc.add_paragraph(t, style='List Bullet')

# ====== 五、救命话术 ======
add_title('五、万一被问懵了——5句救命话术')

saves = [
    '"这块我还在学习中，后面会补上。"',
    '"核心思路是多源交叉验证——多个数据库互相印证，不依赖单一来源。"',
    '"每个漏洞结论都能在NVD官网验证，不用信我，信官方。"',
    '"功能不多，但做的每件事都是真的、可验证的。"',
    '"后续方向是一键修复和许可证检测，架构已经预留好了。"',
]
for s in saves:
    p = doc.add_paragraph()
    r = p.add_run(s)
    r.font.bold = True
    r.font.size = Pt(12)

# ====== 保存 ======
output = r'C:\Users\34612\Desktop\组会答辩准备手册.docx'
doc.save(output)
print(f'已保存: {output}')
