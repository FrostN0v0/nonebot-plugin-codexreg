import io
import random
import string
import asyncio
import zipfile
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime, timezone, timedelta

from nonebot import require
from nonebot.params import Depends
from nonebot.adapters.milky import Bot
from arclet.alconna import Args, Alconna
from nonebot.permission import SuperUser
from nonebot.plugin import PluginMetadata, inherit_supported_adapters

require("nonebot_plugin_alconna")
require("nonebot_plugin_localstore")
require("nonebot_plugin_apscheduler")
require("nonebot_plugin_uninfo")

from nonebot_plugin_uninfo import Uninfo
from nonebot_plugin_alconna import Match, Option, Subcommand, UniMessage, on_alconna

from .quota import UserQuota
from .config import Config, config
from .schemas import CXAccountInfo
from .log import cx_logger as logger
from .exception import RequestException
from .api import OAuthClient, YYDSMailAPI, OAIRegisterAPI
from .utils import random_name, random_birthdate, generate_password, decode_jwt_payload

__plugin_meta__ = PluginMetadata(
    name="codexreg",
    description="Automatic registration plugin for some AI platform accounts",
    usage="cx --help",
    config=Config,
    type="application",
    homepage="https://github.com/FrostN0v0/nonebot-plugin-codexreg",
    supported_adapters=inherit_supported_adapters("nonebot_plugin_alconna"),
    extra={
        "author": "FrostN0v0 <1614591760@qq.com>",
        "version": "0.1.0",
    },
)

codex = on_alconna(
    Alconna("codex", Subcommand("reg", Option("-r|retry|--retry", Args["num", int]))),
    use_cmd_start=True,
    aliases={"cx"},
)


# ------------------------------------------------------------------ #
#  核心注册流程（供 reg 和 reg.retry 共用）
# ------------------------------------------------------------------ #


async def _pick_domain() -> str:
    if config.domain_whitelist:
        return random.choice(config.domain_whitelist)
    return random.choice(await YYDSMailAPI.fetch_domains()).domain


async def _do_register() -> CXAccountInfo:
    """执行一次完整注册流程，成功返回 CXAccountInfo，失败抛出 RequestException"""
    domain = await _pick_domain()
    chars = string.ascii_lowercase + string.digits
    prefix = "".join(random.choice(chars) for _ in range(random.randint(8, 13)))
    inbox = await YYDSMailAPI.create_temp_inbox(prefix, domain)
    password = generate_password()
    name = random_name()
    birthdate = random_birthdate()

    oai = OAIRegisterAPI()
    await oai.visit_homepage()
    csrf_token = await oai.get_csrf()
    auth_url = await oai.signin(inbox.address, csrf_token)
    final_url = await oai.authorize(auth_url)
    final_path = urlparse(final_url).path

    if "email-verification" in final_path or "email-otp" in final_path:
        raise RequestException("需要邮箱验证，无法自动处理")

    if "about-you" not in final_path and "callback" not in final_path and "chatgpt.com" not in final_url:
        await oai.register(inbox.address, password)
        await oai.send_otp()
        otp_code = await oai.wait_for_verification_email_async(inbox.address)
        if not otp_code:
            raise RequestException("等待验证码超时")
        await oai.validate_otp(otp_code)

    if "callback" not in final_path and "chatgpt.com" not in final_url:
        await oai.create_account(name, birthdate)
        await oai.callback()

    tokens = await OAuthClient().login(inbox.address, password)
    payload = decode_jwt_payload(tokens.access_token)
    auth_info = payload.get("https://api.openai.com/auth", {})
    account_id = auth_info.get("chatgpt_account_id", "")
    now = datetime.now(tz=timezone(timedelta(hours=8)))
    exp_timestamp = payload.get("exp")
    expired_str = (
        datetime.fromtimestamp(exp_timestamp, tz=timezone(timedelta(hours=8))).strftime("%Y-%m-%dT%H:%M:%S+08:00")
        if isinstance(exp_timestamp, int) and exp_timestamp > 0
        else ""
    )
    return CXAccountInfo(
        type="codex",
        email=inbox.address,
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        id_token=tokens.id_token,
        expired=expired_str,
        account_id=account_id,
        last_refresh=now.strftime("%Y-%m-%dT%H:%M:%S+08:00"),
    )


def _build_file(results: list[CXAccountInfo]) -> tuple[bytes, str]:
    """
    将结果列表打包为文件内容。
    单个账号 → JSON 字节 + 文件名；
    多个账号 → ZIP 字节 + 文件名。
    """
    if len(results) == 1:
        a = results[0]
        return a.model_dump_json(indent=2).encode(), f"{a.email}.json"

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for a in results:
            zf.writestr(f"{a.email}.json", a.model_dump_json(indent=2))
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return buf.getvalue(), f"codex_accounts_{ts}.zip"


async def _send_results(bot: Bot, session: Uninfo, results: list[CXAccountInfo]) -> None:
    data, filename = _build_file(results)
    file_path = Path("temp") / filename
    file_path.parent.mkdir(exist_ok=True, parents=True)
    if session.scene.is_group:
        await bot.upload_group_file(
            group_id=int(session.scene.id),
            raw=data,
            file_name=filename,
        )
    else:
        await bot.upload_private_file(
            user_id=int(session.user.id),
            raw=data,
            file_name=filename,
        )


@codex.assign("reg.$main")
async def _(session: Uninfo, is_superuser: bool = Depends(SuperUser())):
    uid = session.user.id
    remaining = await UserQuota.check_and_get_remaining(uid, config.reg_max_user_per_day)
    if remaining <= 0 and not is_superuser:
        await UniMessage.text(f"今日已达注册上限（{config.reg_max_user_per_day} 个），请明日再试").finish()

    try:
        account = await _do_register()
    except RequestException as e:
        await UniMessage.text(f"注册失败: {e}").finish()

    await UserQuota.increment(uid)
    await UniMessage.text(f"注册成功！邮箱: {account.email}\nAccount Json:\n{account.model_dump_json()}").send()


@codex.assign("reg.retry")
async def _(bot: Bot, session: Uninfo, num: Match[str], is_superuser: bool = Depends(SuperUser())):
    """并发批量注册：max_thread_workers 个协程同时运行，每个账号最多尝试 retry_max_attempts 次"""
    uid = session.user.id
    target = int(num.result) if num.available else 1
    if target < 1:
        await UniMessage.text("数量必须 >= 1").finish()
    if not is_superuser:
        # 注册前检查配额：剩余可注册数
        remaining = await UserQuota.check_and_get_remaining(uid, config.reg_max_user_per_day)
        if remaining <= 0:
            await UniMessage.text(f"今日已达注册上限（{config.reg_max_user_per_day} 个），请明日再试").finish()
        # 实际目标不超过剩余配额
        target = min(target, remaining)
        if target < target:
            await UniMessage.text(f"今日剩余配额 {remaining} 个，目标已调整为 {target} 个").send()

    workers = config.max_thread_workers
    max_attempts = config.retry_max_attempts
    await UniMessage.text(f"开始批量注册，目标: {target} 个，并发: {workers}，单账号最大尝试: {max_attempts} 次").send()

    results: list[CXAccountInfo] = []
    stop_event = asyncio.Event()
    results_lock = asyncio.Lock()

    async def _worker(worker_id: int):
        """持续注册直到全局目标达成或本账号耗尽重试次数"""
        while not stop_event.is_set():
            for attempt in range(1, max_attempts + 1):
                if stop_event.is_set():
                    return
                try:
                    account = await _do_register()
                    async with results_lock:
                        results.append(account)
                        cnt = len(results)
                        # 每次成功立即持久化配额
                        await UserQuota.increment(uid)
                        logger("INFO", f"[W{worker_id}] 注册成功({cnt}/{target}) attempt={attempt}: {account.email}")
                        await UniMessage.text(f"[{cnt}/{target}] 注册成功: {account.email}").send()
                        if cnt >= target:
                            stop_event.set()
                    break  # 本账号注册成功，重置计数进入下一轮
                except RequestException as e:
                    logger("WARNING", f"[W{worker_id}] 第 {attempt}/{max_attempts} 次失败: {e}")
            else:
                # 超过最大重试次数仍未成功，停止本 worker
                logger("WARNING", f"[W{worker_id}] 已达最大尝试次数 {max_attempts}，worker 退出")
                return

    await asyncio.gather(*[_worker(i) for i in range(workers)])

    await UniMessage.text(f"批量注册完成！共获得 {len(results)} 个账号（目标 {target}）").send()
    if results:
        await _send_results(bot, session, results)
