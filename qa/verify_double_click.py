# -*- coding: utf-8 -*-
"""复现 / 复验「旧实例还在跑又双击一次」这个场景。

场景：用户按《运行说明.md》方式二手动起过一次服务
      （`.venv\\Scripts\\python.exe -m streamlit run main.py`，绑 0.0.0.0），
      那个黑窗口还开着；然后又双击了「快速运行.bat」。

期望（合理行为）：bat 应识别出「8501 上已有本服务在运行」并直接给出访问地址，
                  而不是再起一个实例、也不是报错。

【历史缺陷（2026-10-26 已修复）】
修复前：会起**第二个实例**，旧的 0.0.0.0 实例和新的 127.0.0.1 实例并存。
      浏览器访问 localhost:8501 会被新的（127.0.0.1）实例接管，
      旧实例变成僵尸进程仍在占资源。

根因（当时的 launcher.py）：
  resolve_port() 先调 port_is_free(port, host)，只有它为 False 才去看 health_ok。
  而 Windows 上 port_is_free 只 bind `host`（127.0.0.1）：
      占用者绑 127.0.0.1 -> bind 失败 -> BUSY  （能发现）
      占用者绑 0.0.0.0   -> bind 成功 -> FREE  （发现不了，直接放行）
  所以「按文档手动起过服务」这个最常见的场景，走不进「已有本服务」分支。

修复：port_is_free 改为「bind 试探 + netstat 核对有没有进程在 LISTEN 该端口」
      的双重判定；find_free_port 同样加了 netstat 过滤。

⚠️ 实现注意：等子进程输出**不能**用阻塞的 `stdout.readline()` ——
   没有新输出时它会一直卡住，导致「超时检查」根本执行不到，整个脚本挂死。
   必须用后台线程读、主线程轮询。（这个坑我踩过两次。）
"""
import os
import re
import subprocess
import sys
import threading
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


class Reader:
    """后台线程读 stdout，主线程轮询缓冲 —— 绝不阻塞。"""

    def __init__(self, proc):
        self.proc = proc
        self.buf = []
        self.lock = threading.Lock()
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        try:
            for line in self.proc.stdout:
                with self.lock:
                    self.buf.append(line)
        except (ValueError, OSError):
            pass

    @property
    def text(self):
        with self.lock:
            return "".join(self.buf)

    def wait_for(self, keywords, timeout=60):
        t0 = time.time()
        while time.time() - t0 < timeout:
            if any(k in self.text for k in keywords):
                return self.text
            if self.proc.poll() is not None:
                time.sleep(0.5)
                return self.text
            time.sleep(0.3)
        return self.text


def wait_health(port, timeout=120):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if health(port):
            return True
        time.sleep(1.5)
    return False


def main():
    print("=" * 72)
    print("复验：旧实例绑 0.0.0.0 时，start.py 应识别出「已有本服务」")
    print("=" * 72)

    # 第 1 个实例：完全按《运行说明.md》方式二的方式起（绑 0.0.0.0）
    old = subprocess.Popen([PY_EXE, "-m", "streamlit", "run", "main.py",
                            "--server.port", str(PORT), "--server.headless", "true"],
                           cwd=PROJ, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
    second = None
    try:
        ok = wait_health(PORT)
        print(f"[1] 旧实例就绪（方式二启动，绑 0.0.0.0）: health={ok}")
        for r in listeners(PORT):
            print(f"    {r}")

        env = dict(os.environ)
        env["BROWSER"] = "echo"
        env["NO_PROXY"] = "127.0.0.1,localhost"
        env["no_proxy"] = env["NO_PROXY"]
        second = subprocess.Popen(
            [PY_EXE, "start.py", "--ask-port", "--port", str(PORT),
             "--no-browser", "--timeout", "60"],
            cwd=PROJ, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", env=env)
        reader = Reader(second)
        text = reader.wait_for(["访问地址", "直接访问", "选择", "取消"], timeout=60)

        print(f"[2] 第 2 次启动 start.py --ask-port 的关键输出:")
        for l in text.splitlines():
            if any(k in l for k in ("端口", "访问地址", "直接访问", "占用", "选择")):
                print(f"    {l.strip()}")

        detected = (("已有本服务" in text) or ("不用重复" in text)
                    or ("本服务已在这个端口跑着" in text))
        misjudged = re.search(r"端口\s*\d+\s*可用", text) is not None
        print(f"[3] 判定：")
        print(f"    - 识别出「已有本服务在运行」? {detected}  "
              f"{'✅' if detected else '❌'}")
        print(f"    - 误判「端口 … 可用」? {misjudged}  "
              f"{'❌ 是' if misjudged else '✅ 否'}")

        # 给它时间把第二个实例拉起来（若真会拉起）
        t0 = time.time()
        while time.time() - t0 < 30 and len(listeners(PORT)) < 2:
            time.sleep(1.0)
        rows = listeners(PORT)
        print(f"    - 最终监听行（{len(rows)} 条）:")
        for r in rows:
            print(f"        {r}")
        print(f"    - 出现重复实例? {'❌ 是' if len(rows) >= 2 else '✅ 否'}")
    finally:
        if second:
            second.kill()
            try:
                second.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
        old.kill()
        try:
            old.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        for r in listeners(PORT):
            parts = r.split()
            if parts:
                subprocess.run(["taskkill", "/F", "/PID", parts[-1]],
                               capture_output=True)
        time.sleep(1.0)


if __name__ == "__main__":
    main()
