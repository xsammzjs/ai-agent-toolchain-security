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
    APP_NAME = "双链软件供应链安全检测系统"
    APP_VERSION = "3.0.0"

    # ========== API 密钥 ==========
    NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
    GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
    DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")

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
    DEEPSEEK_API_URL = "https://api.deepseek.com/chat/completions"

    # ========== 超时配置（秒）==========
    OSV_TIMEOUT = 15
    NVD_TIMEOUT = 10
    GITHUB_TIMEOUT = 10
    EPSS_TIMEOUT = 8
    PYPI_TIMEOUT = 8
    DEEPSEEK_TIMEOUT = 120  # AI 生成长报告可能较慢，放宽超时

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

    # ========== AI 辅助研判（DeepSeek 大模型，2026-09-03 新增）==========
    # 官方可用模型：deepseek-v4-flash（便宜快速，默认）/ deepseek-v4-pro（更强更贵）
    # 答辩想换更强模型：改 .env 里的 DEEPSEEK_MODEL 后重启即可
    DEEPSEEK_MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-v4-flash")
    # V4 Flash 官方价格（元/百万 tokens）：缓存命中输入 / 缓存未命中输入 / 输出
    # 用于界面显示每次调用的估算费用
    DEEPSEEK_PRICE_INPUT_HIT = 0.02
    DEEPSEEK_PRICE_INPUT_MISS = 1.0
    DEEPSEEK_PRICE_OUTPUT = 2.0

    # ========== 临时目录 ==========
    TEMP_DIR = "temp_upload"
    REPORT_DIR = "reports"

    # ========== 扫描配置 ==========
    MAX_DEPENDENCIES = 500  # 单次扫描最多处理 500 个依赖


# 全局单例
config = Config()
