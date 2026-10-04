"""
用 Pillow 生成项目流程框架图
"""
from PIL import Image, ImageDraw, ImageFont
import os

# 画布尺寸
W, H = 1800, 950
img = Image.new('RGB', (W, H), '#ffffff')
draw = ImageDraw.Draw(img)

# 字体 — Windows 微软雅黑是 TTC 格式，需指定 index=0
try:
    font_title = ImageFont.truetype("C:/Windows/Fonts/msyhbd.ttc", 40, index=0)
    font_box_title = ImageFont.truetype("C:/Windows/Fonts/msyhbd.ttc", 24, index=0)
    font_box = ImageFont.truetype("C:/Windows/Fonts/msyh.ttc", 17, index=0)
    font_sub = ImageFont.truetype("C:/Windows/Fonts/msyh.ttc", 14, index=0)
    font_small = ImageFont.truetype("C:/Windows/Fonts/msyh.ttc", 12, index=0)
except Exception:
    font_title = ImageFont.load_default()
    font_box_title = ImageFont.load_default()
    font_box = ImageFont.load_default()
    font_sub = ImageFont.load_default()
    font_small = ImageFont.load_default()

def draw_rounded_box(draw, xy, color, radius=18):
    """画圆角矩形"""
    x1, y1, x2, y2 = xy
    draw.rounded_rectangle(xy, radius=radius, fill=color, outline='white', width=3)

def draw_arrow_between(draw, x1, y1, x2, y2, color='#95a5a6'):
    """画箭头"""
    import math
    # 简化：画线和三角形箭头
    draw.line([(x1, y1), (x2, y2)], fill=color, width=3)
    # 箭头三角
    angle = math.atan2(y2 - y1, x2 - x1)
    arrow_len = 14
    ax1 = x2 - arrow_len * math.cos(angle - 0.5)
    ay1 = y2 - arrow_len * math.sin(angle - 0.5)
    ax2 = x2 - arrow_len * math.cos(angle + 0.5)
    ay2 = y2 - arrow_len * math.sin(angle + 0.5)
    draw.polygon([(x2, y2), (ax1, ay1), (ax2, ay2)], fill=color)

def text_center(draw, x, y, w, text, font, color='#ffffff'):
    """居中文字"""
    bbox = draw.textbbox((0, 0), text, font=font)
    tw = bbox[2] - bbox[0]
    th = bbox[3] - bbox[1]
    draw.text((x + (w - tw)//2, y - th//2), text, font=font, fill=color)

def text_multi_center(draw, x, y, w, title, sub, font_t, font_s, tc='#ffffff', sc='#ffffff'):
    """双行居中文字"""
    # 标题
    bbox = draw.textbbox((0, 0), title, font=font_t)
    tw = bbox[2] - bbox[0]
    th = bbox[3] - bbox[1]
    draw.text((x + (w - tw)//2, y - th - 4), title, font=font_t, fill=tc)
    # 副标题
    bbox2 = draw.textbbox((0, 0), sub, font=font_s)
    tw2 = bbox2[2] - bbox2[0]
    th2 = bbox2[3] - bbox2[1]
    draw.text((x + (w - tw2)//2, y + 6), sub, font=font_s, fill=sc)

# ===== 颜色 =====
C1 = '#2c3e50'   # 深蓝灰 - 标题
C_IN = '#3498db'  # 蓝
C_PR = '#27ae60'  # 绿
C_AN = '#e67e22'  # 橙
C_DB = '#8e44ad'  # 紫
C_RD = '#c0392b'  # 红
C_OUT = '#16a085' # 青绿
C_BG = '#ecf0f1'  # 浅灰背景
C_LINE = '#95a5a6'

# ===== 背景装饰 =====
# 四个阶段背景条
for i, (x, color) in enumerate([
    (60, '#ebf5fb'), (480, '#eafaf1'), (900, '#fdf2e9'), (1320, '#f4ecf7')
]):
    draw.rounded_rectangle([x, 100, x+390, 820], radius=14, fill=color, outline='#e0e0e0', width=1)

# 阶段标签
stages = [
    (255, 112, '📥 输入层'),
    (675, 112, '🔍 分析层'),
    (1095, 112, '📊 研判层'),
    (1515, 112, '📄 输出层'),
]
for x, y, label in stages:
    bbox = draw.textbbox((0, 0), label, font=font_box_title)
    tw = bbox[2] - bbox[0]
    draw.text((x - tw//2, y), label, font=font_box_title, fill='#2c3e50')

# ===== 标题 =====
title_text = '依赖漏洞智能研判系统 — 技术架构流程图'
bbox = draw.textbbox((0, 0), title_text, font=font_title)
tw = bbox[2] - bbox[0]
draw.text((W//2 - tw//2, 30), title_text, font=font_title, fill='#2c3e50')

# 副标题
subtitle = '三源交叉验证  ·  置信度评级  ·  EPSS 利用预测  ·  修复优先级排序  ·  证据溯源'
bbox = draw.textbbox((0, 0), subtitle, font=font_box)
tw = bbox[2] - bbox[0]
draw.text((W//2 - tw//2, 78), subtitle, font=font_box, fill='#7f8c8d')

# ==========================================
# 第1层：输入
# ==========================================
y1 = 160
draw_rounded_box(draw, [80, y1, 440, y1+100], C_IN)
text_multi_center(draw, 260, y1+50, 360, '📦 项目文件上传', 'requirements.txt / ZIP / RAR',
                  font_box_title, font_sub)

# 向右箭头
draw_arrow_between(draw, 442, y1+50, 498, y1+50, C_LINE)

draw_rounded_box(draw, [500, y1, 870, y1+100], C_PR)
text_multi_center(draw, 685, y1+50, 370, '🔧 依赖解析引擎', '6种格式 · 递归引用 · 版本号提取',
                  font_box_title, font_sub)

draw_arrow_between(draw, 872, y1+50, 928, y1+50, C_LINE)

draw_rounded_box(draw, [930, y1, 1340, y1+100], C_IN)
text_multi_center(draw, 1135, y1+50, 410, '📋 依赖清单输出', '去重 · 生态标注 · 版本清洗',
                  font_box_title, font_sub)

# ==========================================
# 第2层：三源检索
# ==========================================
y2 = 320

# 四个数据源
sources = [
    (90, 'OSV.dev', 'Google 开源漏洞库', C_IN),
    (430, 'NIST NVD', '美国国家漏洞数据库', '#2471a3'),
    (770, 'GitHub Advisory', '开源安全公告', '#1a5276'),
    (1110, 'FIRST EPSS', '漏洞利用预测系统', '#154360'),
]
for x, title, sub, color in sources:
    draw_rounded_box(draw, [x, y2, x+300, y2+70], color)
    text_multi_center(draw, x+150, y2+35, 300, title, sub, font_box_title, font_sub)

# 向下汇聚箭头
for x in [240, 580, 920, 1260]:
    draw_arrow_between(draw, x, y2+72, x, y2+120, '#bdc3c7')

# ==========================================
# 第3层：交叉验证（核心）
# ==========================================
y3 = 450
draw_rounded_box(draw, [350, y3, 1100, y3+60], C_AN)
text_multi_center(draw, 725, y3+30, 750, '🔄 三源交叉验证 + 置信度评级（核心引擎）',
                  '三方一致 → 高置信度  |  两方确认 → 中置信度  |  单源 → 低置信度',
                  font_box_title, font_sub, '#ffffff', '#ffeaa7')

# ==========================================
# 第4层：研判输出
# ==========================================
y4 = 570
results = [
    (80, '📊 风险等级 + CVSS', '严重 / 高危 / 中危 / 低危', C_RD),
    (500, '🎯 修复优先级排序', '综合CVSS+EPSS+置信度加权', '#d35400'),
    (920, '🔗 证据溯源链接', 'NVD · GitHub 官方直达', '#7d3c98'),
]
for x, title, sub, color in results:
    draw_rounded_box(draw, [x, y4, x+420, y4+65], color)
    text_multi_center(draw, x+210, y4+32, 420, title, sub, font_box_title, font_sub)

# 从交叉验证向下箭头
for x_target in [290, 710, 1130]:
    draw_arrow_between(draw, x_target, y3+60, x_target, y4, C_LINE)

# ==========================================
# 第5层：报告输出
# ==========================================
y5 = 700
draw_rounded_box(draw, [300, y5, 800, y5+70], C_OUT)
text_multi_center(draw, 700, y5+35, 500, '📄 DOCX 审计报告',
                  '扫描摘要 · 漏洞清单 · 置信度评级 · 证据溯源 · 修复建议',
                  font_box_title, font_sub)

draw_rounded_box(draw, [1140, y5, 1550, y5+70], C_OUT)
text_multi_center(draw, 1345, y5+35, 410, '📋 CycloneDX SBOM', '国际标准软件物料清单',
                  font_box_title, font_sub)

# 箭头
draw_arrow_between(draw, 700, y4+67, 700, y5, C_LINE)
draw_arrow_between(draw, 1345, y4+67, 1345, y5, C_LINE)

# ===== 底部 =====
y_btm = 820
footer = '数据源：Google OSV  ·  NIST NVD  ·  GitHub Advisory  ·  FIRST EPSS        |        输出：DOCX 报告  ·  CycloneDX SBOM  ·  JSON 结果'
bbox = draw.textbbox((0, 0), footer, font=font_sub)
tw = bbox[2] - bbox[0]
draw.text((W//2 - tw//2, y_btm), footer, font=font_sub, fill='#95a5a6')

# ===== 阶段连接线 =====
# 第一层到第二层
for x in [240, 580, 920, 1260]:
    pass  # already handled with arrows above

# 保存
output_path = r'C:\Users\34612\Desktop\项目流程图.png'
img.save(output_path, 'PNG', quality=95)
print(f'流程图已保存: {output_path}')
