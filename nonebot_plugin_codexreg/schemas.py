"""
YYDS Mail API 响应数据结构定义
"""

from pydantic import Field, BaseModel
from nonebot.compat import model_validator


class Inbox(BaseModel):
    id: str
    userId: str
    address: str
    inboxType: str
    source: str
    expiresAt: str
    isActive: bool
    messageCount: int
    createdAt: str
    updatedAt: str


class EmailContact(BaseModel):
    name: str
    address: str


class Attachment(BaseModel):
    id: str
    filename: str
    contentType: str
    size: int
    downloadUrl: str


class MessageBase(BaseModel):
    id: str
    subject: str
    seen: bool
    hasAttachments: bool
    size: int
    createdAt: str
    _from: EmailContact
    to: list[EmailContact]

    @model_validator(mode="before")
    @classmethod
    def inject_from(cls, data: dict) -> dict:
        """将 API 返回的 from 字段重命名为 _from"""
        if "from" in data:
            data["_from"] = data.pop("from")
        return data


class MailMessage(MessageBase):
    inboxId: str
    inbox_id: str
    _from: EmailContact
    to: list[EmailContact]


class MailMessages(BaseModel):
    messages: list[MailMessage]
    total: int


class MessageDetail(MessageBase):
    text: str
    html: list[str] | str
    attachments: list[Attachment] | None = None


class DomainInfo(BaseModel):
    id: str
    domain: str
    isVerified: bool
    isPublic: bool


class MailAccount(BaseModel):
    id: str
    address: str
    token: str
    inboxType: str
    source: str
    expiresAt: str
    isActive: bool
    createdAt: str


class CXLoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    expires_in: int
    token_type: str
    id_token: str
    scope: str


class CXAccountInfo(BaseModel):
    email: str
    access_token: str
    refresh_token: str
    disabled: bool = Field(default=False)
    expired: str
    account_id: str
    last_refresh: str
    id_token: str
    type: str = Field(default="codex")
