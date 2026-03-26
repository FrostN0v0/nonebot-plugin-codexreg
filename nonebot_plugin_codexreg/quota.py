import json
import asyncio
from pathlib import Path
from json import JSONDecodeError
from datetime import datetime, timezone, timedelta

from nonebot_plugin_localstore import get_plugin_data_dir


class UserQuota:
    """用户每日注册配额管理（线程安全，数据持久化为 JSON）"""

    _lock = asyncio.Lock()

    @staticmethod
    def _quota_file() -> Path:
        return get_plugin_data_dir() / "user_quota.json"

    @staticmethod
    def _today() -> str:
        return datetime.now(tz=timezone(timedelta(hours=8))).strftime("%Y-%m-%d")

    @classmethod
    def _load(cls) -> dict:
        f = cls._quota_file()
        if f.exists():
            try:
                return json.loads(f.read_text(encoding="utf-8"))
            except JSONDecodeError:
                pass
        return {}

    @classmethod
    def _save(cls, data: dict) -> None:
        f = cls._quota_file()
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    @classmethod
    def get_used(cls, uid: str) -> int:
        """同步读取用户今日已成功注册数（无锁，仅用于非并发场景）"""
        today = cls._today()
        entry = cls._load().get(uid, {})
        if entry.get("date") != today:
            return 0
        return entry.get("count", 0)

    @classmethod
    async def check_and_get_remaining(cls, uid: str, limit: int) -> int:
        """
        在锁内读取今日已用量，返回剩余可注册数。
        若已达上限返回 0。
        """
        async with cls._lock:
            today = cls._today()
            entry = cls._load().get(uid, {})
            used = entry.get("count", 0) if entry.get("date") == today else 0
            return max(0, limit - used)

    @classmethod
    async def increment(cls, uid: str, delta: int = 1) -> int:
        """
        在锁内将用户今日成功数递增 delta，持久化后返回更新后的累计值。
        跨天时自动重置为 delta。
        """
        async with cls._lock:
            data = cls._load()
            today = cls._today()
            entry = data.get(uid, {})
            if entry.get("date") != today:
                # 新的一天，重置计数
                entry = {"date": today, "count": 0}
            entry["count"] = entry["count"] + delta
            data[uid] = entry
            cls._save(data)
            return entry["count"]
