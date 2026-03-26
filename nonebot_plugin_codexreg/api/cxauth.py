"""
OAuth 客户端模块 - 处理 Codex OAuth 登录流程
"""

import re
import json
import time
import base64
import random
import asyncio
import secrets

from curl_cffi.requests import AsyncSession
from curl_cffi.requests.errors import CurlError, RequestsError

from ..config import config
from .yyds_mail import YYDSMailAPI
from ..log import cx_logger as logger
from ..schemas import CXLoginResponse
from ..exception import RequestException
from ..utils import (
    generate_pkce,
    extract_code_from_url,
    generate_datadog_trace,
    extract_verification_code,
    async_build_sentinel_token,
)

# ---------- Chrome 指纹池 ----------
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


def _random_chrome():
    """随机生成 Chrome 指纹，返回 (impersonate, ua, sec_ch_ua)"""
    p = random.choice(_CHROME_PROFILES)
    ver = f"{p['major']}.0.{p['build']}.{random.randint(*p['patch_range'])}"
    ua = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver} Safari/537.36"
    return p["impersonate"], ua, p["sec_ch_ua"]


class OAuthClient:
    """OAuth 客户端 - 异步获取 Access Token 和 Refresh Token"""

    def __init__(self):
        self.AUTH = config.oauth_url_base.rstrip("/")
        self.client_id = config.oauth_client_id
        self.redirect_uri = config.oauth_redirect_uri

        self.impersonate, self.ua, self.sec_ch_ua = _random_chrome()
        self.device_id = secrets.token_hex(16)

        self.session = AsyncSession(impersonate=self.impersonate)
        self.session.headers.update(
            {
                "User-Agent": self.ua,
                "Accept-Language": "en-US,en;q=0.9",
                "sec-ch-ua": self.sec_ch_ua,
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Windows"',
            }
        )
        self.session.cookies.set("oai-did", self.device_id, domain="auth.openai.com")
        if config.oai_proxy_url:
            self.session.proxies = {"http": config.oai_proxy_url, "https": config.oai_proxy_url}

    # ------------------------------------------------------------------ #
    #  公开入口
    # ------------------------------------------------------------------ #

    async def login(self, email: str, password: str) -> CXLoginResponse:
        """
        完整 OAuth 登录流程，返回 tokens 字典。

        Args:
            email: 邮箱
            password: 密码

        Returns:
            包含 access_token / refresh_token / id_token 的字典
        """
        code_verifier, code_challenge = generate_pkce()
        state = secrets.token_urlsafe(32)

        authorize_params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": "openid profile email offline_access",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
        }

        # 1. Bootstrap — 获取 login_session cookie
        referer = await self._bootstrap(authorize_params)

        # 2. 提交邮箱
        continue_url, page_type = await self._submit_email(email, referer)

        # 3. 提交密码
        continue_url, page_type, need_otp = await self._submit_password(
            password,
            continue_url,
            page_type,
        )

        # 4. OTP (如果需要)
        if need_otp:
            continue_url, page_type = await self._handle_otp(email, continue_url, page_type)

        # 5. Consent / Workspace / Org 选择 → 拿到 authorization code
        code = await self._resolve_consent(continue_url, page_type)

        # 6. 用 code 换 tokens
        return CXLoginResponse(**await self._exchange_code(code, code_verifier))

    # ------------------------------------------------------------------ #
    #  内部步骤
    # ------------------------------------------------------------------ #

    async def _bootstrap(self, params: dict) -> str:
        """GET /oauth/authorize 获取 login_session cookie，返回 referer URL"""
        logger("DEBUG", "OAuth 步骤1: Bootstrap session")
        url = f"{self.AUTH}/oauth/authorize"
        try:
            r = await self.session.get(
                url,
                params=params,
                headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Upgrade-Insecure-Requests": "1",
                    "Referer": "https://chatgpt.com/",
                },
                allow_redirects=True,
                timeout=30,
            )
        except (RequestsError, CurlError) as e:
            raise RequestException(f"Bootstrap 失败: {e}") from e

        final_url = str(r.url)
        logger("DEBUG", f"Bootstrap -> {r.status_code}, final={final_url[:80]}")
        return final_url if final_url.startswith(self.AUTH) else f"{self.AUTH}/log-in"

    async def _build_sentinel(self, flow: str) -> str:
        """构建 sentinel token，失败时抛异常"""
        token = await async_build_sentinel_token(
            self.session,
            self.device_id,
            flow=flow,
            user_agent=self.ua,
            sec_ch_ua=self.sec_ch_ua,
            impersonate=self.impersonate,
        )
        if not token:
            raise RequestException(f"无法获取 sentinel token ({flow})")
        return token

    async def _submit_email(self, email: str, referer: str) -> tuple[str, str]:
        """POST /api/accounts/authorize/continue 提交邮箱"""
        logger("DEBUG", "OAuth 步骤2: 提交邮箱")
        sentinel = await self._build_sentinel("authorize_continue")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Referer": referer,
            "Origin": self.AUTH,
            "oai-device-id": self.device_id,
            "openai-sentinel-token": sentinel,
        }
        headers.update(generate_datadog_trace())

        try:
            r = await self.session.post(
                f"{self.AUTH}/api/accounts/authorize/continue",
                json={"username": {"kind": "email", "value": email}},
                headers=headers,
                timeout=30,
                allow_redirects=False,
            )
        except (RequestsError, CurlError) as e:
            raise RequestException(f"提交邮箱失败: {e}") from e

        if r.status_code != 200:
            raise RequestException(f"提交邮箱失败: {r.status_code} {r.text[:180]}")

        data = r.json()
        continue_url = data.get("continue_url", "")
        page_type = data.get("page", {}).get("type", "")
        logger("DEBUG", f"提交邮箱 -> page={page_type or '-'}")
        return continue_url, page_type

    async def _submit_password(
        self,
        password: str,
        continue_url: str,
        page_type: str,
    ) -> tuple[str, str, bool]:
        """POST /api/accounts/password/verify 提交密码，返回 (continue_url, page_type, need_otp)"""
        logger("DEBUG", "OAuth 步骤3: 提交密码")
        sentinel = await self._build_sentinel("password_verify")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Referer": f"{self.AUTH}/log-in/password",
            "Origin": self.AUTH,
            "oai-device-id": self.device_id,
            "openai-sentinel-token": sentinel,
        }
        headers.update(generate_datadog_trace())

        try:
            r = await self.session.post(
                f"{self.AUTH}/api/accounts/password/verify",
                json={"password": password},
                headers=headers,
                timeout=30,
                allow_redirects=False,
            )
        except (RequestsError, CurlError) as e:
            raise RequestException(f"密码验证失败: {e}") from e

        if r.status_code != 200:
            raise RequestException(f"密码验证失败: {r.status_code} {r.text[:180]}")

        data = r.json()
        continue_url = data.get("continue_url", "") or continue_url
        page_type = data.get("page", {}).get("type", "") or page_type

        need_otp = (
            page_type == "email_otp_verification"
            or "email-verification" in (continue_url or "")
            or "email-otp" in (continue_url or "")
        )
        logger("DEBUG", f"密码验证 -> page={page_type or '-'}, need_otp={need_otp}")
        return continue_url, page_type, need_otp

    # -------------------- OTP --------------------

    async def _handle_otp(
        self,
        email: str,
        continue_url: str,
        page_type: str,
        timeout: int = 30,
    ) -> tuple[str, str]:
        """轮询邮箱获取 OTP 并验证，返回更新后的 (continue_url, page_type)"""
        logger("DEBUG", "OAuth 步骤4: OTP 验证")
        tried: set[str] = set()
        deadline = time.time() + timeout

        while time.time() < deadline:
            codes = await self._fetch_otp_candidates(email, tried)
            if not codes:
                await asyncio.sleep(2)
                continue

            for otp in codes:
                tried.add(otp)
                logger("DEBUG", f"尝试 OTP: {otp}")
                try:
                    r = await self.session.post(
                        f"{self.AUTH}/api/accounts/email-otp/validate",
                        json={"code": otp},
                        headers={
                            "Content-Type": "application/json",
                            "Accept": "application/json",
                            "Referer": f"{self.AUTH}/email-verification",
                            "Origin": self.AUTH,
                            "oai-device-id": self.device_id,
                            **generate_datadog_trace(),
                        },
                        timeout=30,
                        allow_redirects=False,
                    )
                except (RequestsError, CurlError):
                    continue

                if r.status_code != 200:
                    continue

                data = r.json()
                logger("DEBUG", "OTP 验证通过")
                return (
                    data.get("continue_url", "") or continue_url,
                    data.get("page", {}).get("type", "") or page_type,
                )

            await asyncio.sleep(2)

        raise RequestException(f"OTP 验证超时，已尝试 {len(tried)} 个验证码")

    async def _fetch_otp_candidates(self, email: str, exclude: set[str]) -> list[str]:
        """通过 YYDSMailAPI 获取新的 OTP 验证码候选列表"""
        try:
            msgs = await YYDSMailAPI.fetch_messages_by_address(email)
        except RequestException:
            return []

        codes: list[str] = []
        for m in msgs.messages[:12]:
            try:
                detail = await YYDSMailAPI.fetch_message_detail(m.id, email)
            except RequestException:
                continue
            content = detail.text
            if isinstance(content, list):
                content = "\n".join(content)
            code = extract_verification_code(content)
            if code and code not in exclude:
                codes.append(code)
        return codes

    # -------------------- Consent / Workspace / Org --------------------

    async def _resolve_consent(self, continue_url: str, page_type: str) -> str:
        """处理 consent 流程，最终返回 authorization code"""
        logger("DEBUG", "OAuth 步骤5: 解析 consent 获取 code")

        consent_url = self._normalize_url(continue_url)

        # 先看 URL 里有没有直接带 code
        code = extract_code_from_url(consent_url or "")
        if code:
            return code

        # 跟随 continue_url
        if consent_url:
            code = await self._follow_redirects_for_code(consent_url)
            if code:
                return code

        # Workspace / Org 选择
        if self._looks_like_consent(consent_url, page_type):
            consent_url = consent_url or f"{self.AUTH}/sign-in-with-chatgpt/codex/consent"
            code = await self._submit_workspace_and_org(consent_url)
            if code:
                return code

        # 最终回退
        fallback = f"{self.AUTH}/sign-in-with-chatgpt/codex/consent"
        for attempt in range(3):
            if attempt:
                await asyncio.sleep(0.5)
            code = await self._submit_workspace_and_org(fallback)
            if code:
                return code
            code = await self._follow_redirects_for_code(fallback)
            if code:
                return code

        raise RequestException("未获取到 authorization code")

    def _normalize_url(self, url: str) -> str:
        if url and url.startswith("/"):
            return f"{self.AUTH}{url}"
        return url

    @staticmethod
    def _looks_like_consent(url: str | None, page_type: str) -> bool:
        keywords = ("consent", "sign-in-with-chatgpt", "workspace", "organization")
        return any(kw in (url or "") or kw in page_type for kw in keywords)

    async def _follow_redirects_for_code(self, start_url: str, max_hops: int = 16) -> str | None:
        """手动跟随重定向直到拿到 code 或用尽跳转次数"""
        code = extract_code_from_url(start_url)
        if code:
            return code

        current = start_url
        for _ in range(max_hops):
            try:
                r = await self.session.get(
                    current,
                    headers={
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Upgrade-Insecure-Requests": "1",
                    },
                    allow_redirects=False,
                    timeout=30,
                )
            except (RequestsError, CurlError) as e:
                # 可能 localhost 重定向触发连接异常
                m = re.search(r'(https?://localhost[^\s\'"]+)', str(e))
                if m:
                    code = extract_code_from_url(m.group(1))
                    if code:
                        return code
                return None

            code = extract_code_from_url(str(r.url))
            if code:
                return code

            if r.status_code not in (301, 302, 303, 307, 308):
                return None

            location = r.headers.get("Location", "")
            if not location:
                return None

            location = self._normalize_url(location)
            code = extract_code_from_url(location)
            if code:
                return code
            current = location

        return None

    async def _submit_workspace_and_org(self, consent_url: str) -> str | None:
        """提交 workspace 和 organization 选择"""
        session_data = self._decode_session_cookie()
        if not session_data:
            return None

        workspaces = session_data.get("workspaces", [])
        if not workspaces:
            return None

        workspace_id = (workspaces[0] or {}).get("id")
        if not workspace_id:
            return None

        logger("DEBUG", f"选择 workspace: {workspace_id}")
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Origin": self.AUTH,
            "Referer": consent_url,
            "oai-device-id": self.device_id,
            **generate_datadog_trace(),
        }

        try:
            r = await self.session.post(
                f"{self.AUTH}/api/accounts/workspace/select",
                json={"workspace_id": workspace_id},
                headers=headers,
                allow_redirects=False,
                timeout=30,
            )
        except (RequestsError, CurlError):
            return None

        # 重定向中可能直接带 code
        code = self._code_from_redirect(r)
        if code:
            return code

        if r.status_code != 200:
            return None

        data = r.json()
        # 尝试 org 选择
        code = await self._try_org_select(data, headers)
        if code:
            return code

        # 跟随 workspace/select 返回的 continue_url
        ws_continue = data.get("continue_url", "")
        if ws_continue:
            return await self._follow_redirects_for_code(self._normalize_url(ws_continue))

        return None

    async def _try_org_select(self, ws_data: dict, headers: dict) -> str | None:
        """从 workspace/select 响应中提取 org 并提交选择"""
        orgs = ws_data.get("data", {}).get("orgs", [])
        if not orgs:
            return None

        org = orgs[0] or {}
        org_id = org.get("id")
        if not org_id:
            return None

        logger("DEBUG", f"选择 organization: {org_id}")
        body: dict = {"org_id": org_id}
        projects = org.get("projects", [])
        if projects:
            body["project_id"] = projects[0].get("id")

        try:
            r = await self.session.post(
                f"{self.AUTH}/api/accounts/organization/select",
                json=body,
                headers=headers,
                allow_redirects=False,
                timeout=30,
            )
        except (RequestsError, CurlError):
            return None

        code = self._code_from_redirect(r)
        if code:
            return code

        if r.status_code == 200:
            org_continue = r.json().get("continue_url", "")
            if org_continue:
                return await self._follow_redirects_for_code(self._normalize_url(org_continue))

        return None

    def _code_from_redirect(self, response) -> str | None:
        """从 3xx 响应的 Location header 中提取 code"""
        if response.status_code not in (301, 302, 303, 307, 308):
            return None
        location = self._normalize_url(response.headers.get("Location", ""))
        return extract_code_from_url(location)

    def _decode_session_cookie(self) -> dict | None:
        """解码 oai-client-auth-session cookie"""
        value = self.session.cookies.get("oai-client-auth-session")
        if not value:
            return None
        try:
            return json.loads(base64.b64decode(value))
        except Exception:
            return None

    # -------------------- Token Exchange --------------------

    async def _exchange_code(self, code: str, code_verifier: str) -> dict:
        """POST /oauth/token 用 code 换取 tokens"""
        logger("DEBUG", "OAuth 步骤6: 换取 tokens")
        try:
            r = await self.session.post(
                f"{self.AUTH}/oauth/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": self.redirect_uri,
                    "client_id": self.client_id,
                    "code_verifier": code_verifier,
                },
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                },
                timeout=60,
            )
        except (RequestsError, CurlError) as e:
            raise RequestException(f"换取 tokens 失败: {e}") from e

        if r.status_code != 200:
            raise RequestException(f"换取 tokens 失败: {r.status_code} {r.text[:200]}")

        logger("DEBUG", "OAuth 登录成功")
        return r.json()
