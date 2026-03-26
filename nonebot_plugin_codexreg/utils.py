"""
通用工具函数模块
"""

import re
import json
import base64
import random
import string
import hashlib
import secrets
from json import JSONDecodeError

from .sentinel_token import SentinelTokenGenerator


def decode_jwt_payload(token):
    """解析 JWT token 的 payload 部分"""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding
        decoded = base64.urlsafe_b64decode(payload)
        import json

        return json.loads(decoded)
    except JSONDecodeError:
        return {}


def generate_password(length=14):
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    digits = string.digits
    special = "!@#$%&*"
    pwd = [random.choice(lower), random.choice(upper), random.choice(digits), random.choice(special)]
    all_chars = lower + upper + digits + special
    pwd += [random.choice(all_chars) for _ in range(length - 4)]
    random.shuffle(pwd)
    return "".join(pwd)


def random_name():
    first = random.choice(
        [
            "James",
            "Emma",
            "Liam",
            "Olivia",
            "Noah",
            "Ava",
            "Ethan",
            "Sophia",
            "Lucas",
            "Mia",
            "Mason",
            "Isabella",
            "Logan",
            "Charlotte",
            "Alexander",
            "Amelia",
            "Benjamin",
            "Harper",
            "William",
            "Evelyn",
            "Henry",
            "Abigail",
            "Sebastian",
            "Emily",
            "Jack",
            "Elizabeth",
        ]
    )
    last = random.choice(
        [
            "Smith",
            "Johnson",
            "Brown",
            "Davis",
            "Wilson",
            "Moore",
            "Taylor",
            "Clark",
            "Hall",
            "Young",
            "Anderson",
            "Thomas",
            "Jackson",
            "White",
            "Harris",
            "Martin",
            "Thompson",
            "Garcia",
            "Robinson",
            "Lewis",
            "Walker",
            "Allen",
            "King",
            "Wright",
            "Scott",
            "Green",
        ]
    )
    return f"{first} {last}"


def random_birthdate():
    y = random.randint(1985, 2002)
    m = random.randint(1, 12)
    d = random.randint(1, 28)
    return f"{y}-{m:02d}-{d:02d}"


def generate_datadog_trace():
    """生成 Datadog APM 追踪头"""
    trace_id = str(random.getrandbits(64))
    parent_id = str(random.getrandbits(64))
    trace_hex = format(int(trace_id), "016x")
    parent_hex = format(int(parent_id), "016x")
    return {
        "traceparent": f"00-0000000000000000{trace_hex}-{parent_hex}-01",
        "tracestate": "dd=s:1;o:rum",
        "x-datadog-origin": "rum",
        "x-datadog-parent-id": parent_id,
        "x-datadog-sampling-priority": "1",
        "x-datadog-trace-id": trace_id,
    }


def generate_pkce():
    """生成 PKCE code_verifier 和 code_challenge"""
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


def extract_code_from_url(url):
    """从 URL 中提取 authorization code"""
    if not url or "code=" not in url:
        return None
    try:
        from urllib.parse import parse_qs, urlparse

        return parse_qs(urlparse(url).query).get("code", [None])[0]
    except Exception:
        return None


def extract_verification_code(email_content: str) -> str | None:
    if not email_content:
        return None
    patterns = [
        r"Verification code:?\s*(\d{6})",
        r"code is\s*(\d{6})",
        r"代码为[:：]?\s*(\d{6})",
        r"验证码[:：]?\s*(\d{6})",
        r">\s*(\d{6})\s*<",
        r"(?<![#&])\b(\d{6})\b",
    ]
    for pattern in patterns:
        matches = re.findall(pattern, email_content, re.IGNORECASE)
        for code in matches:
            if code == "177010":
                continue
            return code
    return None


def fetch_sentinel_challenge(
    session, device_id, flow="authorize_continue", user_agent=None, sec_ch_ua=None, impersonate=None
):
    """调用 sentinel 后端 API 获取 challenge 数据"""
    generator = SentinelTokenGenerator(device_id=device_id, user_agent=user_agent)
    req_body = {
        "p": generator.generate_requirements_token(),
        "id": device_id,
        "flow": flow,
    }

    headers = {
        "Content-Type": "text/plain;charset=UTF-8",
        "Referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html",
        "Origin": "https://sentinel.openai.com",
        "User-Agent": user_agent or "Mozilla/5.0",
        "sec-ch-ua": sec_ch_ua or '"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
    }

    kwargs = {
        "data": json.dumps(req_body),
        "headers": headers,
        "timeout": 20,
    }
    if impersonate:
        kwargs["impersonate"] = impersonate

    try:
        resp = session.post("https://sentinel.openai.com/backend-api/sentinel/req", **kwargs)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass

    return None


def build_sentinel_token(
    session, device_id, flow="authorize_continue", user_agent=None, sec_ch_ua=None, impersonate=None
):
    """构建完整的 openai-sentinel-token JSON 字符串"""
    challenge = fetch_sentinel_challenge(
        session, device_id, flow=flow, user_agent=user_agent, sec_ch_ua=sec_ch_ua, impersonate=impersonate
    )

    if not challenge:
        return None

    c_value = challenge.get("token", "")
    if not c_value:
        return None

    pow_data = challenge.get("proofofwork") or {}
    generator = SentinelTokenGenerator(device_id=device_id, user_agent=user_agent)

    if pow_data.get("required") and pow_data.get("seed"):
        p_value = generator.generate_token(
            seed=pow_data.get("seed"),
            difficulty=pow_data.get("difficulty", "0"),
        )
    else:
        p_value = generator.generate_requirements_token()

    return json.dumps(
        {
            "p": p_value,
            "t": "",
            "c": c_value,
            "id": device_id,
            "flow": flow,
        },
        separators=(",", ":"),
    )


async def async_fetch_sentinel_challenge(
    session, device_id, flow="authorize_continue", user_agent=None, sec_ch_ua=None, impersonate=None
):
    """异步调用 sentinel 后端 API 获取 challenge 数据"""
    generator = SentinelTokenGenerator(device_id=device_id, user_agent=user_agent)
    req_body = {
        "p": generator.generate_requirements_token(),
        "id": device_id,
        "flow": flow,
    }

    headers = {
        "Content-Type": "text/plain;charset=UTF-8",
        "Referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html",
        "Origin": "https://sentinel.openai.com",
        "User-Agent": user_agent or "Mozilla/5.0",
        "sec-ch-ua": sec_ch_ua or '"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
    }

    kwargs = {
        "data": json.dumps(req_body),
        "headers": headers,
        "timeout": 20,
    }
    if impersonate:
        kwargs["impersonate"] = impersonate

    resp = await session.post("https://sentinel.openai.com/backend-api/sentinel/req", **kwargs)
    if resp.status_code == 200:
        return resp.json()
    return None


async def async_build_sentinel_token(
    session, device_id, flow="authorize_continue", user_agent=None, sec_ch_ua=None, impersonate=None
):
    """异步构建完整的 openai-sentinel-token JSON 字符串"""
    challenge = await async_fetch_sentinel_challenge(
        session, device_id, flow=flow, user_agent=user_agent, sec_ch_ua=sec_ch_ua, impersonate=impersonate
    )

    if not challenge:
        return None

    c_value = challenge.get("token", "")
    if not c_value:
        return None

    pow_data = challenge.get("proofofwork") or {}
    generator = SentinelTokenGenerator(device_id=device_id, user_agent=user_agent)

    if pow_data.get("required") and pow_data.get("seed"):
        p_value = generator.generate_token(
            seed=pow_data.get("seed"),
            difficulty=pow_data.get("difficulty", "0"),
        )
    else:
        p_value = generator.generate_requirements_token()

    return json.dumps(
        {
            "p": p_value,
            "t": "",
            "c": c_value,
            "id": device_id,
            "flow": flow,
        },
        separators=(",", ":"),
    )
