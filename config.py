"""
配置管理模块
============
统一管理 API 密钥、超时、阈值等所有配置。
支持 .env 文件和环境变量。
"""
import os
from dotenv import load_dotenv

# 加载 .env 文件（如果存在）
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))


class Config:
    """应用配置"""

    # ========== 项目信息 ==========
    APP_NAME = "AI Agent 工具链安全检测平台"
    APP_VERSION = "4.0.0"

    # ========== API 密钥 ==========
    NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
    GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
    # DeepSeek 大模型配置已于2026-10-05 移除（commit b84ff1b），之后未重新引入。
    # AI 能力如需恢复，应使用华为云 MaaS 而非外部大模型 API（华为ICT大赛赛题1 要求）。

    # ========== GitHub 访问方式 ==========
    # 开着 Steam++/Watt Toolkit 等 GitHub 加速工具时，它们会在本机 127.0.0.1
    # 用自签证书转发 api.github.com 的流量，Python 默认不信任该证书。
    # 此时需要在 .env 里设 GITHUB_VERIFY_SSL=False（连接目标仍是本机加速器，风险可控）。
    # 未使用加速工具、可直连 GitHub 的网络环境，请保持 True（默认）。
    GITHUB_VERIFY_SSL = os.environ.get("GITHUB_VERIFY_SSL", "True").lower() in ("1", "true", "yes")

    # ========== API 端点 ==========
    OSV_API = "https://api.osv.dev/v1/query"
    EPSS_API = "https://api.first.org/data/v1/epss"
    GITHUB_ADVISORY_API = "https://api.github.com/advisories"
    PYPI_JSON_API = "https://pypi.org/pypi"

    # ========== 超时配置（秒）==========
    OSV_TIMEOUT = 15
    NVD_TIMEOUT = 10
    GITHUB_TIMEOUT = 10
    EPSS_TIMEOUT = 8
    PYPI_TIMEOUT = 8

    # ========== 间接依赖推断（v3.1 新增）==========
    MAX_TRANSITIVE_DEPS = 150     # 一层间接依赖收集上限，超出截断
    PYPI_REQUEST_INTERVAL = 0.3   # PyPI 请求间隔（秒），防限流

    # ========== 风险阈值 ==========
    CVSS_HIGH = 7.0        # 高危分界线
    CVSS_CRITICAL = 9.0    # 严重分界线
    EPSS_ALERT = 0.10      # EPSS > 10% 告警

    # ========== 置信度评级阈值 ==========
    CONFIDENCE_HIGH = 3     # 需三方验证
    CONFIDENCE_MEDIUM = 2   # 需两方验证

    # ========== 临时目录 ==========
    TEMP_DIR = "temp_upload"
    REPORT_DIR = "reports"

    # ========== 扫描配置 ==========
    MAX_DEPENDENCIES = 500  # 单次扫描最多处理 500 个依赖


# 全局单例
config = Config()
