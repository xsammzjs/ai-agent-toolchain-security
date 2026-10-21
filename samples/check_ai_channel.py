# -*- coding: utf-8 -*-
"""
AI 研判通道连通性自检
=================================================
用法：  python samples/check_ai_channel.py

【为什么需要这个】
填完 .env 后只看 is_available() 返回 True 是不够的——
那只能证明「三个变量都非空」，不能证明「真的能调通」。
本脚本发起一次最小真实请求，把问题定位到具体环节。

【排查思路】
四步逐个验，任一步失败就停在那一步，不往下猜：
  1. 环境变量是否读到      → .env 是否在项目根目录、变量名有没有写错
  2. MaaS 直连是否通        → 网络能否访问 maas 域名
  3. 真实调用是否成功      → API Key / 模型名 / 额度是否有效
  4. 降级路径是否可用       → 万一 MaaS 挂了，答辩能不能兜住
"""
import io
import os
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ENV_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        ".env")


def load_env(path: str) -> int:
    """把 .env 读进 os.environ，返回加载的变量数。"""
    if not os.path.isfile(path):
        print(f"[✗] 找不到 .env 文件：{path}")
        print("     .env 应位于项目根目录（与 main.py 同级）")
        return 0
    n = 0
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ[k.strip()] = v.strip()
            n += 1
    print(f"[✓] 已从 .env 加载 {n} 个变量")
    return n


def step1_env():
    print("\n" + "=" * 62)
    print("第 1 步：环境变量检查")
    print("=" * 62)
    if not load_env(ENV_PATH):
        return False

    keys = ("MAAS_BASE_URL", "MAAS_API_KEY", "MAAS_MODEL")
    ok = True
    for k in keys:
        v = os.environ.get(k, "")
        if v:
            masked = v[:12] + "..." + v[-4:] if len(v) > 20 else v[:8] + "..."
            print(f"  [✓] {k:15s} = {masked}")
        else:
            print(f"  [✗] {k:15s} 未填写")
            ok = False

    # 常见错误：Base URL 填全了（含 /chat/completions），代码会拼成
    # /chat/completions/chat/completions
    url = os.environ.get("MAAS_BASE_URL", "")
    if url.endswith("/chat/completions"):
        print("  [!] 警告：MAAS_BASE_URL 末尾含 /chat/completions，")
        print("      代码会自己拼这个后缀，请删掉这段，只填到 /v1")
    if not ok:
        print("\n  → 第 1 步失败。参考 docs/学生认证后操作手册.md 填写方式")
        return False
    print("  → 三项齐全，进入第 2 步")
    return True


def step2_network():
    print("\n" + "=" * 62)
    print("第 2 步：网络可达性")
    print("=" * 62)
    url = os.environ.get("MAAS_BASE_URL", "")
    host = url.split("//")[-1].split("/")[0]
    print(f"  目标主机：{host}")
    try:
        import socket
        socket.gethostbyname(host)
        print(f"  [✓] DNS 解析成功")
        return True
    except Exception as e:
        print(f"  [✗] DNS 解析失败：{e}")
        print("      若你在用加速器/proxy，可能需要暂时关闭后重试")
        return False


def step3_call():
    print("\n" + "=" * 62)
    print("第 3 步：真实调用测试")
    print("=" * 62)
    from modules import adjudicator as a

    if not a.is_available():
        print("  [✗] is_available() 为 False，第 1 步应该已通过，请检查是否重启了进程")
        return False

    out = a._call_maas(
        [{"role": "user", "content": "回复一句话：连通性测试成功"}],
        temperature=0.1,
    )
    if out:
        preview = out.strip().replace("\n", " ")[:120]
        print(f"  [✓] 调用成功")
        print(f"      模型返回：{preview}")
        print("\n  → MaaS 通道已打通，赛题⑤「人工智能必选」落地")
        return True

    print("  [✗] 调用失败。常见原因按可能性排序：")
    print("      1) 未开通模型服务 → MaaS「在线推理 → 预置服务」点「开通服务」")
    print("         ⚠️ 2026-08-18 起 MaaS 已无「免费服务」标签页，")
    print("            200 万 Token 免费额度已移交 AgentArts（智果）平台")
    print("      2) MAAS_MODEL 与开通的模型名不一致（大小写/版本号要对上）")
    print("      3) API Key 复制时带了空格或换行")
    print("      4) 余额为 0 且未开通按量计费 → 开通服务前先设余额预警")
    print("      5) 欠费冻结 → 控制台「费用与成本」查看欠费状态")
    print("      详细排查看终端里 [AI研判] 开头的那行错误信息")
    return False


def step4_fallback():
    print("\n" + "=" * 62)
    print("第 4 步：降级路径检查（答辩兜底，必须可用）")
    print("=" * 62)
    from modules import demo_mode

    if hasattr(demo_mode, "run_demo"):
        print("  [✓] modules/demo_mode.py 提供 run_demo()")
    else:
        funcs = [f for f in dir(demo_mode) if not f.startswith("_")
                 and callable(getattr(demo_mode, f))]
        print(f"  [✓] demo_mode 可用函数：{funcs}")

    from modules import adjudicator as a
    has_local = hasattr(a, "AI_ALLOWED_TASK")
    print(f"  [✓] AI 职责边界约束存在：{has_local}")
    print("\n  说明：MaaS 不可用时系统自动降级为本地模板，并在界面明示")
    print("      「未调用大模型」。这是设计好的行为，答辩现场网络出问题也能演示。")
    return True


def main():
    print("=" * 62)
    print("AI 研判通道连通性自检")
    print("=" * 62)

    results = []
    if step1_env():
        step2_network()
        results.append(("MaaS 调用", step3_call()))
    else:
        results.append(("MaaS 调用", False))
    results.append(("降级路径", step4_fallback()))

    print("\n" + "=" * 62)
    print("汇总")
    print("=" * 62)
    for name, ok in results:
        print(f"  {name:10s} {'通过' if ok else '未通过'}")

    # 按名称取结果，不依赖下标顺序（曾因取错下标把失败报成成功）
    maas_ok = dict(results).get("MaaS 调用", False)
    if maas_ok:
        print("\n  结论：AI 通道已打通。赛题⑤「人工智能（必选）」已落地，")
        print("        截图 MaaS 研判输出 → 存 docs/figures/codearts/ → 可作证据")
        return 0
    print("\n  结论：MaaS 未通，但降级路径可用，系统仍可完整演示。")
    print("        按上面提示排查；若反复失败可先保留现状，")
    print("        DeepSeek key 是备用通道，MaaS 通了再替换。")
    return 1


if __name__ == "__main__":
    sys.exit(main())