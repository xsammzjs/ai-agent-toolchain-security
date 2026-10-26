# -*- coding: utf-8 -*-
"""缺陷复现（真实用户场景 + 真实默认端口 8501 + 真实 bat 入口参数）：

场景：用户按《运行说明.md》方式二手动起过一次服务
      （`.venv\\Scripts\\python.exe -m streamlit run main.py`，绑 0.0.0.0），
      那个黑窗口还开着；然后又双击了「快速运行.bat」。

预期（合理行为）：bat 应识别出「8501 上已有本服务在运行」并直接给出访问地址，
                  而不是再起一个实例、也不是报错。

实测：会起**第二个实例**，且旧的 0.0.0.0 实例和新的 127.0.0.1 实例并存。
      浏览器访问 localhost:8501 会被新的（127.0.0.1）实例接管，
      旧实例变成僵尸进程仍在占资源。

根因（已定位到 launcher.py）：
  resolve_port() 先调 port_is_free(port, host)，只有它为 False 才去看 health_ok。
  而 Windows 上 port_is_free 只 bind `host`（127.0.0.1）：
      占用者绑 127.0.0.1 -> bind 失败 -> BUSY  （能发现）
      占用者绑 0.0.0.0   -> bind 成功 -> FREE  （发现不了，直接放行）
  所以「按文档手动起过服务」这个最常见的场景，走不进「已有本服务」分支。
"""
import os
import re
import subprocess
import sys
import time
import urllib.request

PROJ = r"D:\DeskApp\python_xiangmu\python-sbom-security-tool"
PY_EXE = os.path.join(PROJ, ".venv", "Scripts", "python.exe")
LOCAL = urllib.request.build_opener(urllib.request.ProxyHandler({}))
PORT = 8501


def health(port):
    try:
        with LOCAL.open(f"http://127.0.0.1:{port}/_stcore/health", timeout=3) as r:
            return r.status == 200 and r.read(64).decode().strip().lower() == "ok"
    except Exception:
        return False


def listeners(port):
    r = subprocess.run(["netstat", "-ano", "-p", "TCP"], capture_output=True)
    out = r.stdout.decode("gbk", errors="replace")
    return [l.strip() for l in out.splitlines()
            if f":{port}" in l and "LISTENING" in l]


def count_streamlit_on(port):
    """该端口上有几个 streamlit 进程在监听（按 netstat 行数近似）。"""
    return len(listeners(port))


def main():
    print("=" * 72)
    print("缺陷复现：旧实例绑 0.0.0.0 时，start.py 认不出「已有本服务」")
    print("=" * 72)

    # 第 1 个实例：完全按《运行说明.md》方式二的方式起
    old = subprocess.Popen([PY_EXE, "-m", "streamlit", "run", "main.py",
                            "--server.port", str(PORT), "--server.headless", "true"],
                           cwd=PROJ, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
    second = None
    try:
        t0 = time.time()
        while time.time() - t0 < 120 and not health(PORT):
            time.sleep(1.5)
        print(f"[1] 旧实例就绪（方式二启动，绑 0.0.0.0）: health={health(PORT)}")
        print(f"    监听行: {listeners(PORT)}")

        # 第 2 次：走 bat 的真实入口参数（--ask-port）
        env = dict(os.environ)
        env["BROWSER"] = "echo"
        env["NO_PROXY"] = "127.0.0.1,localhost"
        env["no_proxy"] = env["NO_PROXY"]
        second = subprocess.Popen(
            [PY_EXE, "start.py", "--ask-port", "--port", str(PORT),
             "--no-browser", "--timeout", "60"],
            cwd=PROJ, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", env=env)
        buf = ""
        t0 = time.time()
        while time.time() - t0 < 60:
            line = second.stdout.readline()
            if not line:
                break
            buf += line
            if "访问地址" in buf or "直接访问" in buf:
                break
        print(f"[2] 第二次 start.py --ask-port 的关键输出:")
        for l in buf.splitlines():
            if any(k in l for k in ("端口", "访问地址", "直接访问", "占用", "选择")):
                print(f"    {l.strip()}")
        detected = ("已有本服务" in buf) or ("不用重复" in buf)
        print(f"[3] 是否识别出「已有本服务在运行」? {detected}")
        print(f"    （若为 False，说明用户会看到「端口可用」并被静默拉起第二个实例）")

        # 等第二个实例真正起来，再数监听进程
        t0 = time.time()
        while time.time() - t0 < 60:
            if len(listeners(PORT)) >= 2:
                break
            time.sleep(1.5)
        rows = listeners(PORT)
        print(f"[4] 最终监听行（{len(rows)} 条）:")
        for r in rows:
            print(f"    {r}")
        print(f"[5] 判定：")
        print(f"    - 识别出已有本服务 ? {detected}")
        print(f"    - 是否出现两个实例并存 ? {len(rows) >= 2}")
        print(f"    - 旧实例(0.0.0.0)是否变成僵尸 ? "
              f"{any('0.0.0.0' in r for r in rows) and len(rows) >= 2}")
    finally:
        if second:
            second.kill(); second.wait()
        old.kill(); old.wait()
        time.sleep(1.0)


if __name__ == "__main__":
    main()
