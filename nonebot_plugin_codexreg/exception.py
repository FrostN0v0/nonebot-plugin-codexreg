from nonebot.exception import NoneBotException


class Exception(NoneBotException):
    """异常基类"""


class RequestException(Exception):
    """请求错误"""


class OAuthException(Exception):
    """OAuth 登录错误"""
