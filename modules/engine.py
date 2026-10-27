"""
调度引擎（v3.0 精简版）
======================
负责：解析 → 研判 → SBOM → 报告 的完整流程编排。
"""
import os
import shutil
import zipfile
from datetime import datetime
from typing import Optional

from modules import parser
from modules import vulnerability


class ScanEngine:
    """供应链安全扫描引擎"""

    def __init__(self):
        self.temp_dir = "temp_upload"
        self.dep_list: list[dict] = []
        self.vulns: list[dict] = []
        self.sbom_data: dict = {}

    def run_full_scan(
        self,
        uploaded_file_path: str,
        upload_mode: str = "auto",
        project_name: str = "Python Project",
        include_transitive: bool = False,
        use_nvd: bool = True,
        do_epss: bool = True,
        progress_cb=None
    ) -> dict:
        """
        执行完整扫描流程。
        include_transitive: 是否推断一层间接依赖（v3.1 新增，默认关闭）。
        use_nvd / do_epss: NVD 交叉验证 / EPSS 查询开关（v3.1 起真正生效）。
        progress_cb: 阶段进度回调（2026-09-09 新增，接收 (中文进度文本, 百分比)）。
        返回: {dep_list, vulns, sbom, summary, transitive_info}
        """
        def _notify(msg, percent=None):
            if progress_cb:
                try:
                    progress_cb(msg, percent)
                except Exception:
                    pass

        os.makedirs(self.temp_dir, exist_ok=True)

        # ===== 阶段 1：解压 & 解析依赖 =====
        _notify("正在解析依赖文件…", percent=5)
        extract_dir = self._prepare_files(uploaded_file_path, upload_mode)
        all_deps = self._parse_dependencies(uploaded_file_path, extract_dir)

        # 去重
        self.dep_list = self._deduplicate(all_deps)
        for d in self.dep_list:
            d.setdefault("is_transitive", False)

        # ===== 阶段 1.5：间接依赖推断（可选，v3.1 新增）=====
        self.transitive_info = {"deps": [], "truncated": False, "limit": 0}
        if include_transitive:
            _notify("正在推断间接依赖（一层）…", percent=10)
            self.transitive_info = vulnerability.detect_transitive_deps(self.dep_list)
            if self.transitive_info["deps"]:
                self.dep_list = self._deduplicate(
                    self.dep_list + self.transitive_info["deps"]
                )

        # ===== 阶段 2：漏洞研判 =====
        # 并发改造（2026-10-15）：依赖粒度开线程池，实测 5.75 倍加速，
        # 且结果与串行完全一致（并发只改速度不改结论）。
        use_concurrent = True
        max_workers = min(8, max(2, len(self.dep_list)))
        if use_concurrent and len(self.dep_list) > 1:
            _notify(f"开始并发四源漏洞研判（{max_workers} 线程，"
                    f"共 {len(self.dep_list)} 个依赖）…", percent=15)
            self.scan_stats: dict = {}
            self.vulns = vulnerability.detect_vulnerabilities_concurrent(
                self.dep_list, parser, use_nvd=use_nvd, do_epss=do_epss,
                progress_cb=progress_cb, stats=self.scan_stats,
                max_workers=max_workers,
            )
        else:
            _notify(f"开始四源漏洞研判（共 {len(self.dep_list)} 个依赖）…",
                    percent=15)
            self.scan_stats: dict = {}
            self.vulns = vulnerability.detect_vulnerabilities(
                self.dep_list, parser, use_nvd=use_nvd, do_epss=do_epss,
                progress_cb=progress_cb, stats=self.scan_stats,
            )

        # ===== 阶段 3：生成 SBOM =====
        _notify("正在生成SBOM物料清单…", percent=95)
        self.sbom_data = generate_sbom(self.dep_list)

        # ===== 整理返回 =====
        return {
            "dep_list": self.dep_list,
            "vulns": self.vulns,
            "sbom": self.sbom_data,
            "summary": self._build_summary(),
            "transitive_info": self.transitive_info,
        }

    # ==========================================
    # 内部方法
    # ==========================================
    def _prepare_files(self, file_path: str, upload_mode: str) -> Optional[str]:
        """解压项目包"""
        if file_path.endswith(".zip"):
            extract_dir = os.path.join(self.temp_dir, "extracted")
            if os.path.exists(extract_dir):
                shutil.rmtree(extract_dir)
            os.makedirs(extract_dir)
            with zipfile.ZipFile(file_path, "r") as zf:
                zf.extractall(extract_dir)
            return extract_dir
        if file_path.endswith(".rar"):
            # RAR 支持（需要系统安装 WinRAR 或 7-Zip 提供解压能力）
            try:
                import rarfile
                extract_dir = os.path.join(self.temp_dir, "extracted")
                if os.path.exists(extract_dir):
                    shutil.rmtree(extract_dir)
                os.makedirs(extract_dir)
                with rarfile.RarFile(file_path, "r") as rf:
                    rf.extractall(extract_dir)
                return extract_dir
            except ImportError:
                raise ValueError(
                    "RAR 解压需要 rarfile 库，请先安装：pip install rarfile"
                )
            except Exception:
                raise ValueError(
                    "RAR 压缩包需要系统安装 WinRAR 或 7-Zip 才能解压。"
                    "请安装解压工具后重试，或改用 ZIP 格式上传。"
                )
        if os.path.isdir(file_path):
            return file_path
        return None

    def _parse_dependencies(self, file_path: str, extract_dir: Optional[str]) -> list[dict]:
        """解析所有依赖文件"""
        all_deps = []

        if file_path.endswith(".txt"):
            all_deps.extend(parser.parse_requirements(file_path))
        elif file_path.endswith(".json"):
            all_deps.extend(parser.parse_package_json(file_path))
        elif extract_dir and os.path.isdir(extract_dir):
            dep_files = parser.find_dependency_files(extract_dir)
            for df in dep_files:
                all_deps.extend(parser.parse_dependency_file(df))
        elif file_path.lower().endswith("pyproject.toml"):
            all_deps.extend(parser.parse_pyproject_toml(file_path))

        return all_deps

    def _deduplicate(self, deps: list[dict]) -> list[dict]:
        """去重"""
        unique = []
        seen = set()
        for d in deps:
            key = (d["package"], d["version"], d.get("ecosystem", "PyPI"))
            if key not in seen:
                seen.add(key)
                unique.append(d)
        return unique

    def _build_summary(self) -> dict:
        """扫描摘要"""
        total_vulns = len(self.vulns)
        critical = sum(1 for v in self.vulns if v.get("severity") in ("严重", "高危"))
        high_confidence = sum(1 for v in self.vulns if v.get("confidence", {}).get("level") == "高")
        fixable = sum(1 for v in self.vulns if v.get("fixed_version", "未知") != "未知")
        priority_1 = sum(1 for v in self.vulns if v.get("fix_priority", {}).get("priority") == 1)
        actively_exploited = sum(1 for v in self.vulns if v.get("is_actively_exploited"))

        indirect = sum(1 for d in self.dep_list if d.get("is_transitive"))
        stats = getattr(self, "scan_stats", {}) or {}
        skipped = stats.get("skipped", []) or []

        return {
            "total_dependencies": len(self.dep_list),
            # ai.py 的 _scan_brief 一直读这个字段，但原实现从未生成 → 恒为 None
            "direct_count": len(self.dep_list) - indirect,
            "indirect_count": indirect,
            # 检测覆盖度（原先被跳过的依赖是静默丢弃的，用户无从得知）
            "scanned_count": stats.get("scanned_count", len(self.dep_list)),
            "skipped_count": len(skipped),
            "skipped_deps": skipped,
            "lower_bound_count": stats.get("lower_bound_count", 0),
            # 查询失败次数：只有它为 0，"零漏洞"这个结论才可信
            "query_errors": stats.get("query_errors", {}),
            "query_error_total": sum(stats.get("query_errors", {}).values()),
            # 超出每包外部查询上限、未做 NVD/EPSS 交叉验证的条目数
            # （漏洞本身仍在结果里，只是分数取自 OSV 单源）
            "external_truncated": stats.get("external_truncated", 0),
            "lookup_budget": stats.get("lookup_budget_per_package", 0),
            "total_vulnerabilities": total_vulns,
            "critical_count": critical,
            "high_confidence_count": high_confidence,
            "fixable_count": fixable,
            "priority_1_count": priority_1,
            "actively_exploited_count": actively_exploited,
            "scan_time": datetime.now().isoformat(),
        }


# ==========================================
# SBOM 生成（简洁版 CycloneDX 1.5）
# ==========================================
def _sbom_version(raw_version: str) -> tuple:
    """
    清洗版本号，产出 CycloneDX 合规的 (version, 是否精确定位)。

    依赖声明里的版本常带操作符（"== 2.2.0"、">= 1.26.5"），原实现直接写入 SBOM，
    会产生 "version": "== 2.2.0"、purl "pkg:pypi/django@== 2.2.0" 这类非法值，
    下游 SBOM 工具（Dependency-Track、cyclonedx-cli 等）会直接拒绝解析。

    规则：
      - 有明确下界（== / >= / ~=）→ 写入清洗后的版本号，标记精确
      - 无版本号或仅有上界（如 <1.20、未限定）→ 写 "unknown"，不可拿推断值冒充
        实际版本（把 "<1.20" 写成 "1.20" 会让下游误判为「装的正是 1.20」）
    """
    if not raw_version:
        return "unknown", False
    if vulnerability.version_basis(raw_version) == "unknown":
        return "unknown", False
    cleaned = parser.extract_clean_version(str(raw_version))
    return (cleaned, True) if cleaned else ("unknown", False)


def generate_sbom(dep_list: list[dict]) -> dict:
    """生成最小但合规的 CycloneDX 1.5 SBOM（含直接/间接依赖标记）"""
    import uuid

    components = []
    for dep in dep_list:
        ver, located = _sbom_version(dep.get("version", ""))
        comp = {
            "type": "library",
            "name": dep["package"],
            "version": ver,
            "purl": f"pkg:{dep.get('ecosystem', 'PyPI').lower()}/{dep['package']}@{ver}",
        }
        if not located:
            # 版本无法定位：如实标记，避免下游把推断值当成实际安装版本
            comp["properties"] = [{
                "name": "dependency:versionUnresolved",
                "value": f"true (declared as {dep.get('version', '')})",
            }]
        if dep.get("is_transitive"):
            comp["description"] = "间接依赖（一层推断）"
            comp["properties"] = [{
                "name": "dependency:transitive",
                "value": f"true (inferred from {dep.get('transitive_from', 'unknown')})",
            }]
        components.append(comp)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "tools": [{
                "name": "AI 技能与依赖漏洞检测平台",
                "version": "3.1.0",
            }],
        },
        "components": components,
    }


# ==========================================
# 兼容旧接口
# ==========================================
parse_requirements = parser.parse_requirements
parse_pyproject_toml = parser.parse_pyproject_toml
parse_pipfile = parser.parse_pipfile
parse_poetry_lock = parser.parse_poetry_lock
find_requirements_in_folder = parser.find_dependency_files
detect_vulnerabilities = vulnerability.detect_vulnerabilities
