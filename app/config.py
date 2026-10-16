"""项目路径与数据库 URL 的集中解析（单一真相来源）。

本模块被 ``app/main.py``（应用运行时）与 ``migrations/env.py``（Alembic 迁移）
**共同导入**，从而保证「应用连接的库」和「迁移改动的库」永远是同一个，
杜绝「服务连 A 库、迁移改 B 库」这类最难排查的事故。
"""
from __future__ import annotations

import os
from pathlib import Path

# app/config.py -> app/ -> cyberwatch-starter/
BASE_DIR = Path(__file__).resolve().parent.parent

#: 显式覆盖数据库位置的环境变量（供测试与未来部署使用）
DATABASE_URL_ENV = "CYBERWATCH_DATABASE_URL"

#: 默认数据库文件：项目根目录下的绝对路径，与进程当前工作目录无关
DEFAULT_DATABASE_PATH = BASE_DIR / "cyberwatch.db"


def default_database_url() -> str:
    """默认数据库 URL（`<项目根>/cyberwatch.db` 的绝对路径）。"""
    return f"sqlite:///{DEFAULT_DATABASE_PATH.as_posix()}"


def resolve_database_url(explicit: str | None = None) -> str:
    """按**明确优先级**解析数据库 URL。

    优先级（高 → 低）：

    1. ``explicit`` —— 调用方显式传入的 URL。测试与程序化调用（如 Alembic 的
       ``Config``）用它指向临时库；**它绝不允许被下面的环境变量或默认值覆盖**。
    2. 环境变量 ``CYBERWATCH_DATABASE_URL`` —— 供测试与未来部署覆盖数据库位置。
    3. 项目根目录下的 ``cyberwatch.db``（绝对路径）。

    空白字符串视为「未设置」，继续向下传递。
    """
    if explicit is not None and explicit.strip():
        return explicit.strip()
    override = os.environ.get(DATABASE_URL_ENV)
    if override is not None and override.strip():
        return override.strip()
    return default_database_url()


def sqlite_file_path(url: str) -> Path | None:
    """从 SQLite URL 中取出文件路径；非 SQLite 或内存库返回 ``None``。"""
    prefix = "sqlite:///"
    if not url.startswith(prefix):
        return None
    raw = url[len(prefix):]
    if not raw or raw.startswith(":memory:"):
        return None
    return Path(raw)
