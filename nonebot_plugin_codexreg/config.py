from pydantic import Field, BaseModel
from nonebot.plugin import get_plugin_config


class ScopedConfig(BaseModel):
    oai_proxy_url: str = ""
    """注册过程中访问 OAI 相关接口的代理地址，建议使用家宽代理"""
    mail_api_base: str = "https://maliapi.215.im"
    """邮箱服务 API 地址，默认为 YYDSMail 的公开 API"""
    mail_api_key: str = ""
    """邮箱服务 API key"""
    oai_url_base: str = "https://chatgpt.com"
    oauth_url_base: str = "https://auth.openai.com"
    oauth_client_id: str = "app_EMoamEEZ73f0CkXaXp7hrann"
    oauth_redirect_uri: str = "http://localhost:1455/auth/callback"
    domain_whitelist: list[str] = []
    """注册时使用的邮箱域名白名单，优先从中选择，默认为空"""
    max_thread_workers: int = 5
    """注册最大并发数"""
    retry_max_attempts: int = 50
    """单账户注册失败最大重试次数"""
    reg_max_user_per_day: int = 1
    """用户每日注册上限"""


class Config(BaseModel):
    codex: ScopedConfig = Field(default_factory=ScopedConfig)


config = get_plugin_config(Config).codex
