"""
依赖解析模块（v3.0）
====================
支持格式：requirements.txt / pyproject.toml / Pipfile / poetry.lock / setup.py / Pipfile.lock / uv.lock
新增：-r 递归引用支持、版本范围智能处理
"""
import os
import re
from packaging.version import Version, InvalidVersion
from packaging.requirements import Requirement, InvalidRequirement

# TOML 解析库兼容
try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None


# ==========================================
# 包名归一化
# ==========================================
def normalize_package_name(name: str) -> str:
    """PEP 503 归一化：小写、下划线和点替换为连字符"""
    name = name.strip().lower()
    name = re.sub(r'[_\.]+', '-', name)
    return name


# ==========================================
# 版本提取
# ==========================================
VERSION_UNKNOWN = "未限定版本"


def extract_clean_version(version_str: str) -> str | None:
    """
    从版本约束字符串提取纯版本号。
    例如 ">=2.0" → "2.0", "==3.2.1" → "3.2.1", "*" → None
    """
    version_str = version_str.strip()
    if not version_str or version_str == VERSION_UNKNOWN or version_str == "*":
        return None

    # 尝试直接解析
    try:
        Version(version_str)
        return version_str
    except InvalidVersion:
        pass

    # 带操作符：>=2.0 → 提取数字部分
    ops = ["==", "~=", ">=", "<=", ">", "<", "!="]
    for op in ops:
        if version_str.startswith(op):
            rest = version_str[len(op):].strip().split()[0]
            # 处理逗号分隔的范围：">=2.0,<3.0"
            for sep in [",", ";"]:
                rest = rest.split(sep)[0]
            try:
                Version(rest)
                return rest
            except InvalidVersion:
                return None

    return None


def extract_representative_version(version_str: str) -> str | None:
    """
    从版本范围中提取代表性版本（更宽松的提取）。
    用于 OSV 查询时需要一个具体版本号。
    """
    # 复用 extract_clean_version 的逻辑
    return extract_clean_version(version_str)


# ==========================================
# 依赖行解析
# ==========================================
def parse_package_line(line: str) -> tuple:
    """
    解析单行依赖声明。
    返回 (包名, 版本字符串) 或 (None, None)
    """
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("-") or line.startswith("--"):
        return None, None

    # 处理可编辑安装：-e git+https://...@egg=package
    if line.startswith("-e "):
        line = line[3:].strip()
        # 尝试提取 egg=package 或 #egg=package
        egg_match = re.search(r'[#&?]egg=([^#&?]+)', line)
        if egg_match:
            return normalize_package_name(egg_match.group(1)), VERSION_UNKNOWN
        return None, None

    # 去掉 extras（[security] 等）但保留包名
    extras_stripped = re.sub(r'\[.*?\]', '', line)

    # 优先用 packaging 库解析
    try:
        req = Requirement(extras_stripped)
        name = normalize_package_name(req.name)
        version = VERSION_UNKNOWN
        for spec in req.specifier:
            if spec.operator == "==":
                version = f"== {spec.version}"
                break
        if version == VERSION_UNKNOWN and req.specifier:
            # 取第一个版本约束
            spec = next(iter(req.specifier))
            version = f"{spec.operator} {spec.version}"
        elif version == VERSION_UNKNOWN:
            # 检查是否在 extras_stripped 中有直接的版本号
            # 例如 "flask>=2.0" 用 packaging 解析会正确处理
            version = VERSION_UNKNOWN
        return name, version
    except InvalidRequirement:
        pass

    # 兜底：字符串分割法
    operators = ["~=", ">=", "<=", "==", "!=", ">", "<"]
    for op in operators:
        if op in line:
            parts = line.split(op, 1)
            name = normalize_package_name(parts[0].strip())
            ver = f"{op} {parts[1].strip()}"
            return name, ver

    # 纯包名，无版本号
    return normalize_package_name(line.strip()), VERSION_UNKNOWN


# ==========================================
# 解析 requirements.txt（支持 -r 递归）
# ==========================================
def parse_requirements(file_path: str, visited: set = None) -> list[dict]:
    """
    解析 requirements.txt，支持 -r 递归引用。
    """
    deps = []
    if visited is None:
        visited = set()

    abs_path = os.path.abspath(file_path)
    if abs_path in visited:
        return deps
    visited.add(abs_path)

    if not os.path.exists(file_path):
        return deps

    base_dir = os.path.dirname(abs_path)

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # 处理 -r 引用
        if line.startswith("-r "):
            ref_file = line[3:].strip()
            ref_path = os.path.join(base_dir, ref_file)
            if os.path.exists(ref_path):
                deps.extend(parse_requirements(ref_path, visited))
            continue

        # 处理 -c 约束文件（只读取其中的 == 约束）
        if line.startswith("-c "):
            continue  # 约束文件不影响依赖列表

        name, ver = parse_package_line(line)
        if name:
            deps.append({"package": name, "version": ver, "ecosystem": "PyPI"})

    return deps


# ==========================================
# 解析 pyproject.toml
# ==========================================
def parse_pyproject_toml(file_path: str) -> list[dict]:
    """解析 pyproject.toml [project].dependencies"""
    deps = []
    if tomllib is None:
        return deps
    try:
        with open(file_path, "rb") as f:
            data = tomllib.load(f)

        # 标准 [project].dependencies
        dependencies = data.get("project", {}).get("dependencies", [])
        for line in dependencies:
            name, ver = parse_package_line(line)
            if name:
                deps.append({"package": name, "version": ver, "ecosystem": "PyPI"})

        # [project.optional-dependencies]
        opt_deps = data.get("project", {}).get("optional-dependencies", {})
        for group_name, deps_list in opt_deps.items():
            for line in deps_list:
                name, ver = parse_package_line(line)
                if name:
                    deps.append({"package": name, "version": ver,
                                 "ecosystem": "PyPI", "dev": True})

        # [tool.poetry.dependencies]
        poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
        for pkg, ver in poetry_deps.items():
            if pkg.lower() == "python":
                continue
            ver_str = VERSION_UNKNOWN
            if isinstance(ver, str):
                ver_str = ver
            elif isinstance(ver, dict) and "version" in ver:
                ver_str = ver["version"]
            deps.append({"package": normalize_package_name(pkg),
                         "version": ver_str, "ecosystem": "PyPI"})
    except Exception:
        pass
    return deps


# ==========================================
# 解析 Pipfile
# ==========================================
def parse_pipfile(file_path: str) -> list[dict]:
    """解析 Pipfile [packages] + [dev-packages]"""
    deps = []
    if tomllib is None:
        return deps
    try:
        with open(file_path, "rb") as f:
            data = tomllib.load(f)

        for section in ["packages", "dev-packages"]:
            packages = data.get(section, {})
            for pkg, ver in packages.items():
                name = normalize_package_name(pkg)
                ver_str = VERSION_UNKNOWN
                if isinstance(ver, str):
                    ver_str = ver if ver != "*" else VERSION_UNKNOWN
                elif isinstance(ver, dict):
                    ver_str = ver.get("version", VERSION_UNKNOWN)
                dev_flag = (section == "dev-packages")
                deps.append({"package": name, "version": ver_str,
                             "ecosystem": "PyPI", "dev": dev_flag})
    except Exception:
        pass
    return deps


# ==========================================
# 解析 poetry.lock
# ==========================================
def parse_poetry_lock(file_path: str) -> list[dict]:
    """解析 poetry.lock [[package]] 数组"""
    deps = []
    if tomllib is None:
        return deps
    try:
        with open(file_path, "rb") as f:
            data = tomllib.load(f)
        for pkg in data.get("package", []):
            name = normalize_package_name(pkg.get("name", ""))
            version = pkg.get("version", VERSION_UNKNOWN)
            if name:
                deps.append({"package": name, "version": f"== {version}",
                             "ecosystem": "PyPI"})
    except Exception:
        pass
    return deps


# ==========================================
# 解析 uv.lock / Pipfile.lock
# ==========================================
def parse_lockfile(file_path: str) -> list[dict]:
    """
    通用 lock file 解析器。
    尝试识别 uv.lock 和 Pipfile.lock。
    """
    deps = []
    if tomllib is None:
        return deps
    try:
        with open(file_path, "rb") as f:
            data = tomllib.load(f)

        # uv.lock 格式
        if "lock-version" in data or "distribution" in str(data.keys()):
            for item in data.get("package", []):
                name = normalize_package_name(item.get("name", ""))
                version = item.get("version", "")
                if name and version:
                    deps.append({"package": name, "version": f"== {version}",
                                 "ecosystem": "PyPI"})
            return deps

        # Pipfile.lock 格式
        for section in ["default", "develop"]:
            section_data = data.get(section, {})
            for pkg, info in section_data.items():
                name = normalize_package_name(pkg)
                version = info.get("version", "") if isinstance(info, dict) else str(info)
                if name and version:
                    deps.append({"package": name, "version": f"== {version}",
                                 "ecosystem": "PyPI"})
    except Exception:
        pass
    return deps


# ==========================================
# 解析 package.json（npm 生态——预留扩展）
# ==========================================
def parse_package_json(file_path: str) -> list[dict]:
    """解析 npm package.json 依赖"""
    import json
    deps = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for section in ["dependencies", "devDependencies"]:
            pkgs = data.get(section, {})
            for pkg, ver in pkgs.items():
                clean_ver = str(ver).lstrip("^").lstrip("~").lstrip("=")
                # 存干净版本号而非 ">= x" 范围串，避免被 _is_pure_range 误判跳过
                deps.append({"package": pkg, "version": clean_ver,
                             "ecosystem": "npm", "dev": section == "devDependencies"})
    except Exception:
        pass
    return deps


# ==========================================
# 文件调度器
# ==========================================
PARSER_MAP = {
    "requirements.txt": parse_requirements,
    "pyproject.toml": parse_pyproject_toml,
    "pipfile": parse_pipfile,
    "poetry.lock": parse_poetry_lock,
    "pipfile.lock": parse_lockfile,
    "uv.lock": parse_lockfile,
    "setup.py": None,   # 暂不支持，跳过
    "setup.cfg": None,   # 暂不支持，跳过
    "package.json": parse_package_json,
}


def parse_dependency_file(file_path: str) -> list[dict]:
    """根据文件名自动选择解析器"""
    fname = os.path.basename(file_path).lower()
    parser_func = PARSER_MAP.get(fname)
    if parser_func:
        return parser_func(file_path)
    return []


def find_dependency_files(folder_path: str) -> list[str]:
    """递归查找目录中的依赖文件"""
    req_files = []
    target_names = set(PARSER_MAP.keys())
    for root, dirs, files in os.walk(folder_path):
        # 跳过虚拟环境和非代码目录
        dirs[:] = [d for d in dirs if d not in (
            ".venv", "venv", "__pycache__", ".git", "node_modules",
            "dist", "build", ".tox", ".eggs", "site-packages"
        )]
        for f in files:
            if f.lower() in target_names:
                req_files.append(os.path.join(root, f))
    return req_files
