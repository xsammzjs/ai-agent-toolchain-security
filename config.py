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
    APP_NAME = "AI 技能组合风险体检站"
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

    # ========== 外部查询数量上限（防卡死）==========
    # 一个依赖包可能命中上百条漏洞，逐条去 NVD/EPSS/GitHub 查会非常慢：
    # 每条 NVD 约 1-2 秒（无 key 更慢），100 条就是几分钟，界面看起来像「卡死」。
    # 因此每个包只对【最严重的 N 条】做外部交叉验证，其余条目：
    #   - 仍会出现在结果里（不丢数据）
    #   - 直接使用 OSV 自带的 CVSS 分数
    #   - 标记 external_verified=False，界面可明示「未做 NVD 交叉验证」
    # 想返回更完整的结果就把它调大（代价是扫描变慢）。
    MAX_LOOKUPS_PER_PACKAGE = 8

    # 外部源连续失败几次就熔断（该源暂时跳过，不每条都等满超时）
    LOOKUP_BREAKER_THRESHOLD = 3
    # 熔断冷却时间（秒）：到点后自动重试该源
    LOOKUP_BREAKER_COOLDOWN = 120

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
