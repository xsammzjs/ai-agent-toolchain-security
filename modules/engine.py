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
from modules import report as report_gen


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
        _notify(f"开始四源漏洞研判（共 {len(self.dep_list)} 个依赖）…", percent=15)
        self.vulns = vulnerability.detect_vulnerabilities(
            self.dep_list, parser, use_nvd=use_nvd, do_epss=do_epss,
            progress_cb=progress_cb
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

        return {
            "total_dependencies": len(self.dep_list),
            "indirect_count": sum(1 for d in self.dep_list if d.get("is_transitive")),
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
def generate_sbom(dep_list: list[dict]) -> dict:
    """生成最小但合规的 CycloneDX 1.5 SBOM（含直接/间接依赖标记）"""
    import uuid

    components = []
    for dep in dep_list:
        comp = {
            "type": "library",
            "name": dep["package"],
            "version": dep["version"],
            "purl": f"pkg:{dep.get('ecosystem', 'PyPI').lower()}/{dep['package']}@{dep['version']}",
        }
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
                "name": "双链软件供应链安全检测系统",
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
