"""
OAI 注册异步 API 客户端
"""

import re
import uuid
import random
import asyncio
from json import JSONDecodeError
from datetime import datetime, timedelta

from curl_cffi.requests import AsyncSession
from curl_cffi.requests.errors import CurlError, RequestsError

from ..config import config
from .yyds_mail import YYDSMailAPI
from ..log import cx_logger as logger
from ..exception import RequestException
from ..utils import generate_datadog_trace, extract_verification_code

_CHROME_PROFILES = [
    {
        "major": 131,
        "impersonate": "chrome131",
        "build": 6778,
        "patch_range": (69, 205),
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    },
    {
        "major": 133,
        "impersonate": "chrome133a",
        "build": 6943,
        "patch_range": (33, 153),
        "sec_ch_ua": '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"',
    },
    {
        "major": 136,
        "impersonate": "chrome136",
        "build": 7103,
        "patch_range": (48, 175),
        "sec_ch_ua": '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
    },
]


class OAIRegisterAPI:
    """OAI 注册异步 API 客户端"""

    def __init__(self):
        self.device_id = str(uuid.uuid4())
        self.auth_session_logging_id = str(uuid.uuid4())
        self.impersonate, self.chrome_major, self.chrome_full, self.ua, self.sec_ch_ua = self._random_chrome_version()
        self.session = AsyncSession(impersonate=self.impersonate)
        self.session.headers.update(
            {
                "User-Agent": self.ua,
                "Accept-Language": random.choice(
                    [
                        "en-US,en;q=0.9",
                        "en-US,en;q=0.9,zh-CN;q=0.8",
                        "en,en-US;q=0.9",
                        "en-US,en;q=0.8",
                    ]
                ),
                "sec-ch-ua": self.sec_ch_ua,
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Windows"',
                "sec-ch-ua-arch": '"x86"',
                "sec-ch-ua-bitness": '"64"',
                "sec-ch-ua-full-version": f'"{self.chrome_full}"',
                "sec-ch-ua-platform-version": f'"{random.randint(10, 15)}.0.0"',
            }
        )
        self.session.cookies.set("oai-did", self.device_id, domain="chatgpt.com")
        if config.oai_proxy_url:
            self.session.proxies = {"http": config.oai_proxy_url, "https": config.oai_proxy_url}
        self.BASE = config.oai_url_base.rstrip("/")
        self.AUTH = config.oauth_url_base.rstrip("/")
        self._callback_url = None

    @staticmethod
    def _random_chrome_version():
        """随机选择一个 Chrome 版本"""
        profile = random.choice(_CHROME_PROFILES)
        major = profile["major"]
        build = profile["build"]
        patch = random.randint(*profile["patch_range"])
        full_ver = f"{major}.0.{build}.{patch}"
        ua = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{full_ver} Safari/537.36"
        return profile["impersonate"], major, full_ver, ua, profile["sec_ch_ua"]

    async def visit_homepage(self):
        url = f"{self.BASE}/"
        try:
            r = await self.session.get(
                url,
                headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Upgrade-Insecure-Requests": "1",
                },
                allow_redirects=True,
            )
            logger("DEBUG", f"Visit homepage: {r.status_code} {str(r.url)}")
        except (RequestsError, CurlError) as e:
            logger("ERROR", f"Visit homepage error: {e}")
            raise RequestException(f"访问 OAI 首页失败: {e}") from e

    async def get_csrf(self) -> str:
        url = f"{self.BASE}/api/auth/csrf"
        try:
            r = await self.session.get(url, headers={"Accept": "application/json", "Referer": f"{self.BASE}/"})
        except (RequestsError, CurlError) as e:
            logger("ERROR", f"Get CSRF error: {e}")
            raise RequestException(f"获取 CSRF token 失败: {e}") from e
        try:
            data = r.json()
        except JSONDecodeError as e:
            logger("ERROR", f"Get CSRF JSON decode error: {e}")
            raise RequestException(f"解析 CSRF token 响应失败: {e}") from e
        token = data.get("csrfToken", "")
        logger("DEBUG", f"Get CSRF: {r.status_code} {token}")
        if not token:
            raise RequestException("Failed to get CSRF token")
        return token

    async def signin(self, email: str, csrf: str) -> str:
        url = f"{self.BASE}/api/auth/signin/openai"
        params = {
            "prompt": "login",
            "ext-oai-did": self.device_id,
            "auth_session_logging_id": str(uuid.uuid4()),
            "screen_hint": "login_or_signup",
            "login_hint": email,
        }
        form_data = {"callbackUrl": f"{self.BASE}/", "csrfToken": csrf, "json": "true"}
        try:
            r = await self.session.post(
                url,
                params=params,
                data=form_data,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                    "Referer": f"{self.BASE}/",
                    "Origin": self.BASE,
                },
            )
        except (RequestsError, CurlError) as e:
            logger("ERROR", f"Signin error: {e}")
            raise RequestException(f"提交邮箱失败: {e}") from e
        data = r.json()
        authorize_url = data.get("url", "")
        logger("DEBUG", f"Signin: {r.status_code} {authorize_url}")
        if not authorize_url:
            raise RequestException("Failed to get authorize URL")
        return authorize_url

    async def authorize(self, url: str) -> str:
        try:
            r = await self.session.get(
                url,
                headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Referer": f"{self.BASE}/",
                    "Upgrade-Insecure-Requests": "1",
                },
                allow_redirects=True,
            )
        except (RequestsError, CurlError) as e:
            logger("ERROR", f"Authorize error: {e}")
            raise RequestException(f"访问授权链接失败: {e}") from e
        final_url = str(r.url)
        logger("DEBUG", f"Authorize: {r.status_code} {final_url}")
        return final_url

    async def wait_for_verification_email_async(self, email_address: str, timeout: int = 10) -> str | None:
        """使用 YYDSMailAPI 异步轮询邮箱以获取 6 位验证码"""
        logger("DEBUG", f"等待邮箱 {email_address} 的验证码，超时 {timeout}s")
        end_time = datetime.now() + timedelta(seconds=timeout)
        while datetime.now() < end_time:
            try:
                msgs = await YYDSMailAPI.fetch_messages_by_address(email_address)
                logger("DEBUG", f"已获取 {email_address} 的邮件列表，共 {getattr(msgs, 'total', 0)} 封邮件")
            except RequestException as e:
                logger("WARNING", f"fetch_messages_by_address 错误: {e}")
                await asyncio.sleep(2)
                continue

            for m in msgs.messages:
                msg_id = m.id
                try:
                    detail = await YYDSMailAPI.fetch_message_detail(msg_id, email_address)
                except RequestException as e:
                    logger("WARNING", f"fetch_message_detail 错误 (msg_id={msg_id}): {e}")
                    continue
                content = detail.text
                if isinstance(content, list):
                    content = "\n".join(content)
                code = extract_verification_code(content)
                if code:
                    logger("DEBUG", f"从邮箱获取到验证码: {code}")
                    return code
            await asyncio.sleep(2)

        logger("WARNING", f"邮箱验证码等待超时: {email_address}")
        return None

        """轮询邮箱以获取完成注册的邮件，并提取其中的链接"""
        try:
            msgs = await YYDSMailAPI.fetch_messages_by_address(email_address)
            logger("DEBUG", f"已获取 {email_address} 的邮件列表，共 {getattr(msgs, 'total', 0)} 封邮件")
        except RequestException as e:
            logger("WARNING", f"fetch_messages_by_address 错误: {e}")
            return None

        for m in msgs.messages:
            if m.subject.find("Finish setting up your account") != -1:
                logger("DEBUG", f"找到需要完成注册的邮件: {m.subject} (id={m.id})")
                msg_id = m.id
                try:
                    detail = await YYDSMailAPI.fetch_message_detail(msg_id, email_address)
                except RequestException as e:
                    logger("WARNING", f"fetch_message_detail 错误 (msg_id={msg_id}): {e}")
                    continue
                content = detail.text
                if isinstance(content, list):
                    content = "\n".join(content)
                urls = re.findall(r"https:\/\/chatgpt\.com\/continue-registration", content)
                if urls and len(urls) == 1:
                    logger("DEBUG", f"从邮箱获取到完成注册的链接: {urls[0]}")
                    return urls[0]

        logger("WARNING", f"邮箱完成注册链接等待超时: {email_address}")
        return None

    async def register(self, email: str, password: str):
        url = f"{self.AUTH}/api/accounts/user/register"
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Referer": f"{self.AUTH}/create-account/password",
            "Origin": self.AUTH,
        }
        headers.update(generate_datadog_trace())
        try:
            r = await self.session.post(url, json={"username": email, "password": password}, headers=headers)
        except (RequestsError, CurlError) as e:
            logger("ERROR", f"Register error: {e}")
            raise RequestException(f"注册失败: {e}") from e
        data = r.json()
        logger("DEBUG", f"Register: {r.status_code} {data}")

    async def send_otp(self):
        url = f"{self.AUTH}/api/accounts/email-otp/send"
        try:
            await self.session.get(
                url,
                headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Referer": f"{self.AUTH}/create-account/password",
                    "Upgrade-Insecure-Requests": "1",
                },
                allow_redirects=True,
            )
        except (RequestsError, CurlError) as e:
            logger("ERROR", f"Send OTP error: {e}")
            raise RequestException(f"发送 OTP 请求失败: {e}") from e

    async def validate_otp(self, code: str):
        url = f"{self.AUTH}/api/accounts/email-otp/validate"
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Referer": f"{self.AUTH}/email-verification",
            "Origin": self.AUTH,
        }
        try:
            r = await self.session.post(url, json={"code": code}, headers=headers)
        except (RequestsError, CurlError) as e:
            logger("ERROR", f"Validate OTP error: {e}")
            raise RequestException(f"验证 OTP 失败: {e}") from e
        data = r.json()
        logger("DEBUG", f"Validate OTP: {r.status_code} {data}")

    async def create_account(self, name: str, birthdate: str):
        url = f"{self.AUTH}/api/accounts/create_account"
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Referer": f"{self.AUTH}/about-you",
            "Origin": self.AUTH,
        }
        headers.update(generate_datadog_trace())
        try:
            r = await self.session.post(url, json={"name": name, "birthdate": birthdate}, headers=headers)
        except (RequestsError, CurlError) as e:
            logger("ERROR", f"Create Account error: {e}")
            raise RequestException(f"创建账号失败: {e}") from e
        if r.status_code != 200:
            logger("ERROR", f"Create Account failed: {r.status_code} {r.text}")
            raise RequestException(f"创建账号失败: {r.status_code}")
        data = r.json()
        logger("DEBUG", f"Create Account: {r.status_code} {data}")
        if isinstance(data, dict):
            cb = data.get("continue_url") or data.get("url") or data.get("redirect_url")
            if cb:
                self._callback_url = cb

    async def callback(self):
        """完成注册回调"""
        url = f"{self.AUTH}/api/accounts/authorize/callback"
        try:
            r = await self.session.get(
                url,
                headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Referer": f"{self.AUTH}/about-you",
                },
                allow_redirects=True,
            )
        except (RequestsError, CurlError) as e:
            logger("ERROR", f"Callback error: {e}")
            raise RequestException(f"访问注册回调链接失败: {e}") from e
        if r.status_code == 200:
            logger("DEBUG", f"访问注册回调链接成功: {self._callback_url}")
        logger("DEBUG", f"Callback: {r.status_code} {str(r.url)}")
