"""
YYDS Mail 邮箱客户端
"""

import httpx

from ..config import config
from ..log import cx_logger as logger
from ..exception import RequestException
from ..schemas import Inbox, DomainInfo, MailAccount, MailMessages, MessageDetail

_headers = {
    "User-Agent": "YYDSMailClient/0.1",
    "Accept": "application/json",
    "Content-Type": "application/json",
    "Accept-Encoding": "gzip",
    "Connection": "close",
}


class YYDSMailAPI:
    """YYDS Mail 异步 API 客户端"""

    @staticmethod
    def _url(path: str) -> str:
        return config.mail_api_base.rstrip("/") + path

    @staticmethod
    def _make_client(token: str | None = None) -> httpx.AsyncClient:
        headers = _headers.copy()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return httpx.AsyncClient(headers=headers, timeout=10)

    @classmethod
    async def fetch_all_inboxes(cls) -> list[Inbox]:
        """GET /v1/me/inboxes — 获取账号下所有邮箱"""
        async with cls._make_client(token=config.mail_api_key) as client:
            try:
                res = await client.get(
                    cls._url("/v1/me/inboxes"),
                )
            except httpx.RequestError as e:
                logger("ERROR", f"fetch_all_inboxes 网络错误: {e}")
                raise RequestException(f"fetch_all_inboxes 网络错误: {e}") from e

        if res.status_code != 200:
            raise RequestException(f"fetch_all_inboxes 失败 {res.status_code}")

        data = res.json().get("data", [])
        return [Inbox(**d) for d in data if d.get("address")]

    @classmethod
    async def fetch_messages_by_address(cls, email_address: str) -> MailMessages:
        """GET /v1/messages?address=... — 获取指定邮箱消息列表"""
        try:
            async with cls._make_client(token=config.mail_api_key) as client:
                res = await client.get(
                    cls._url("/v1/messages"),
                    params={"address": email_address},
                )
        except httpx.RequestError as e:
            raise RequestException(f"fetch_messages_by_address 网络错误: {e}") from e

        if res.status_code != 200:
            raise RequestException(f"fetch_messages_by_address 失败 {res.status_code}")
        data = res.json().get("data", {})
        return MailMessages(**data)

    @classmethod
    async def fetch_message_detail(cls, msg_id: str, email_address: str) -> MessageDetail:
        """GET /v1/messages/{id} — 获取邮件详情"""
        try:
            async with cls._make_client(token=config.mail_api_key) as client:
                res = await client.get(
                    cls._url(f"/v1/messages/{msg_id}"),
                    params={"address": email_address},
                )
        except httpx.RequestError as e:
            raise RequestException(f"fetch_message_detail 网络错误: {e}") from e

        if res.status_code != 200:
            raise RequestException(f"fetch_message_detail 失败 {res.status_code}")
        return MessageDetail(**res.json().get("data", {}))

    @classmethod
    async def fetch_domains(cls) -> list[DomainInfo]:
        """GET /v1/domains — 获取可用公共域名"""
        try:
            async with cls._make_client(token=config.mail_api_key) as client:
                res = await client.get(cls._url("/v1/domains"))

        except httpx.RequestError as e:
            raise RequestException(f"fetch_domains 网络错误: {e}") from e

        if res.status_code != 200:
            raise RequestException(f"fetch_domains 失败 {res.status_code}")
        return [DomainInfo(**d) for d in res.json().get("data", []) if d.get("isVerified") and d.get("isPublic")]

    @classmethod
    async def create_temp_inbox(cls, prefix: str, domain: str) -> MailAccount:
        """POST /v1/accounts — 创建临时邮箱"""
        try:
            async with cls._make_client(token=config.mail_api_key) as client:
                res = await client.post(
                    cls._url("/v1/accounts"),
                    json={"prefix": prefix, "domain": domain},
                )
        except httpx.RequestError as e:
            raise RequestException(f"create_temp_inbox 网络错误: {e}") from e

        if res.status_code not in (200, 201):
            raise RequestException(f"create_temp_inbox 失败 {res.status_code}: {res.text[:100]}")
        return MailAccount(**res.json().get("data", {}))
