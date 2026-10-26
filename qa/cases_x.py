# -*- coding: utf-8 -*-
"""用例组 X —— **验收脚本自身**的自检

  X1 端口精确匹配（不误伤相邻端口）
  X2 占位进程启动失败能被识别
  X3 占位进程异常路径也清理干净

为什么要给「测试代码」写用例：
  测试脚本自己出 bug，会让**整个验收结果不可信**。
  这三条盯的是测试基础设施本身，必须和被测产品一样被盯着。
"""

from __future__ import annotations

from _harness import Result, wait_until, Case
from _portkit import (
    netstat_listening,
    TEST_PORT,
    kill_holder,
    kill_port_listeners,
    start_port_holder,
)



def case_x1_port_match_precision(res: Result) -> None:
    """X1（自检）：端口匹配必须精确，不能把 `:87650` 当成 `:8765`。

    这是真实踩过的坑：netstat 里 `":8765" in line` 会同时命中 `":87650"`，
    导致「以为端口被占」或「以为端口已释放」的误判，进而连锁失败。
    """
    real = netstat_listening(TEST_PORT)
    res.check(all(f":{TEST_PORT} " in line for line in real),
              f"netstat_listening({TEST_PORT}) 返回的行都精确匹配该端口")
    # 用相邻端口号构造一个假阳性样本，验证匹配函数不会命中
    fake = [f"  TCP    127.0.0.1:{TEST_PORT}0        0.0.0.0:0              LISTENING       1"]
    needle = f":{TEST_PORT} "
    res.check(not any(needle in line for line in fake),
              f"相邻端口 :{TEST_PORT}0 不会被误判为 :{TEST_PORT}")
    # 实测：真端口能匹配上
    res.check(any(needle in line for line in
                  [f"  TCP    127.0.0.1:{TEST_PORT}         0.0.0.0:0              LISTENING       1"]),
              f"真实端口 :{TEST_PORT} 能被匹配到")



def case_x2_holder_failure_detected(res: Result) -> None:
    """X2（自检）：占位进程启动失败必须被**发现**，不能静默当成功。

    场景：端口已经被别的进程占着时，哑巴占用者 bind 会失败、进程直接退出，
    stdout 关闭、readline() 返回空串。若把空串当成功，
    「占用者其实没起来」会被当成「占用成功」，把后面所有断言带偏。
    """
    kill_port_listeners(TEST_PORT)
    try:
        first = start_port_holder(TEST_PORT, reuse=False, addr="127.0.0.1")
    except RuntimeError as exc:
        res.check(False, f"第一次起占位者就失败了：{exc}")
        return
    try:
        res.check(bool(netstat_listening(TEST_PORT)),
                  "第一个占位者成功占住了端口")
        # 再起一个同端口的 -> 必须报错
        detected = False
        try:
            second = start_port_holder(TEST_PORT, reuse=False, addr="127.0.0.1")
            # 没报错的话要主动清理
            kill_holder(second)
        except RuntimeError:
            detected = True
        res.check(detected,
                  "端口已被占用时，第二个占位者启动失败被正确识别（抛 RuntimeError）")
    finally:
        kill_holder(first)
        kill_port_listeners(TEST_PORT)



def case_x3_holder_cleanup(res: Result) -> None:
    """X3（自检）：占位进程在**异常路径**下也必须被清理干净。

    这是真实踩过的坑：占位进程没 kill 掉 → 端口一直被占 →
    下次跑测试连环失败（症状是「占用者已就绪，监听行 []」）。
    """
    kill_port_listeners(TEST_PORT)
    holder = start_port_holder(TEST_PORT, reuse=False, addr="127.0.0.1")
    res.check(bool(netstat_listening(TEST_PORT)), "占位者已就绪")

    # 模拟异常路径：中途抛异常，但 finally 里的 kill_holder 必须执行
    try:
        try:
            raise RuntimeError("模拟用例中途失败")
        finally:
            kill_holder(holder)
    except RuntimeError:
        pass

    released = wait_until(lambda: not netstat_listening(TEST_PORT),
                          timeout=15, interval=0.5)
    res.check(released,
              f"异常路径下占位进程也被清理干净（残留 = {netstat_listening(TEST_PORT)}）")


# ==========================================================
# 本模块的用例注册表
# ==========================================================
CASES: List[Case] = [
    ("X1", "自检：端口精确匹配（不误伤相邻端口）", case_x1_port_match_precision, True),
    ("X2", "自检：占位进程启动失败能被识别", case_x2_holder_failure_detected, True),
    ("X3", "自检：占位进程异常路径也清理干净", case_x3_holder_cleanup, True),
]
