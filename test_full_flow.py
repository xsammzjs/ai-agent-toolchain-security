"""全流程自测（2026-09-09 封版验证）：导航锚点/依赖扫描进度/Skill检测/报告导出"""
import io
import sys
import time

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
from playwright.sync_api import sync_playwright

URL = "http://localhost:8501"
SAMPLE = r"D:\DeskApp\python_xiangmu\python-sbom-security-tool\samples\vuln_reqs\sample_clean.txt"

ok = []


def check(name, cond):
    ok.append((name, bool(cond)))
    print(("✅ " if cond else "❌ ") + name)


with sync_playwright() as p:
    browser = p.chromium.launch(channel="msedge", headless=True)
    page = browser.new_page(viewport={"width": 1400, "height": 1000})
    page.goto(URL, wait_until="networkidle", timeout=60000)
    time.sleep(3)

    # ① 导航条与锚点
    body = page.inner_text("body")
    check("导航条存在（跳转到Skill安全检测）", "跳转到 Skill 安全检测" in body)
    check("导航条存在（返回顶部）", "返回顶部" in body)
    page.click("a[href='#skill-section']")
    time.sleep(1.5)
    check("锚点跳转后Skill区可见", "Skill 安全检测" in page.inner_text("body"))
    page.click("a[href='#top']")
    time.sleep(1)

    # ② 依赖扫描（上传→进度提示→结果）
    # 注意：缓存热时扫描可能3秒完成，进度提示只存在约1.5秒（一个rerun周期），
    # 必须点击后立即高频轮询才能抓到。
    page.set_input_files("input[type='file']", SAMPLE)
    time.sleep(2)
    page.get_by_role("button", name="开始安全扫描").click()
    saw_progress = False
    t0 = time.time()
    while time.time() - t0 < 30:
        body = page.inner_text("body")
        if "正在执行多源漏洞研判" in body:
            saw_progress = True
        if "漏洞总数" in body and "正在执行多源漏洞研判" not in body:
            break
        time.sleep(0.5)
    check("扫描进度提示出现", saw_progress)
    page.screenshot(path="temp_shots/12_scan_progress.png")
    # 等待扫描完成（缓存冷时clean样本约60-150秒，缓存热时约3秒）
    deadline = time.time() + 300
    done = False
    while time.time() < deadline:
        body = page.inner_text("body")
        if "扫描进度" not in body and "正在执行多源漏洞研判" not in body and "漏洞总数" in body:
            done = True
            break
        time.sleep(3)
    check("依赖扫描完成并显示结果", done)
    page.screenshot(path="temp_shots/13_scan_result.png")

    # ③ Skill 检测（演示样例；AI 语义研判为流式生成，需轮询等待 rerun 后结果区出现）
    page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
    time.sleep(1)
    page.get_by_role("button", name="🎬 演示样例").click()
    deadline = time.time() + 90
    body = ""
    while time.time() < deadline:
        body = page.inner_text("body")
        if "命中风险点" in body and "整体判定" in body:
            break
        time.sleep(3)
    check("Skill演示样例检出13个风险点", "13" in body and "命中风险点" in body)
    check("Skill整体判定显示", "整体判定" in body)

    # ④ 检测率测试按钮
    page.get_by_role("button", name="运行样本检测率测试").click()
    time.sleep(4)
    body = page.inner_text("body")
    # 样本库已扩充为 30 恶意 + 20 正常，旧断言 5/5、2/2 已失效
    check("检测率30/30与无误报20/20", "30/30" in body and "20/20" in body)
    page.screenshot(path="temp_shots/14_skill_full.png")

    # ⑤ 报告导出按钮（存在且可点）
    page.evaluate("window.scrollTo(0, 0)")
    time.sleep(1)
    body = page.inner_text("body")
    check("DOCX报告导出按钮存在", "DOCX" in body or "导出" in body)

    browser.close()

fails = [n for n, c in ok if not c]
print(f"\n===== 自测结果: {len(ok) - len(fails)}/{len(ok)} 通过 =====")
if fails:
    print("失败项:", fails)
