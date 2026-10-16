"""Alembic 运行环境配置。

核心目标：让 Alembic 使用的数据库 URL 与 FastAPI 应用**完全一致**，
并且**绝不覆盖调用方（尤其是测试）显式指定的临时数据库 URL**。

URL 解析优先级（见 app/config.py::resolve_database_url）：
    1. 调用方在 Config 上显式设置的 sqlalchemy.url  ← 最高，测试用
    2. 环境变量 CYBERWATCH_DATABASE_URL
    3. <项目根>/cyberwatch.db（绝对路径）
"""
from __future__ import annotations

import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool
from sqlmodel import SQLModel

# 让 migrations/env.py 在任意 cwd 下都能 import app 包。
# （alembic.ini 的 prepend_sys_path = . 是相对 cwd 的，不够可靠）
BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app.config import resolve_database_url  # noqa: E402  与 app 共用的唯一解析逻辑
import app.main  # noqa: E402,F401  确保所有模型注册进 SQLModel.metadata

config = context.config

# --- 关键：先读调用方是否已显式指定 URL，有就以它为准 -------------------------
_caller_url = (config.get_main_option("sqlalchemy.url") or "").strip()
config.set_main_option(
    "sqlalchemy.url",
    resolve_database_url(explicit=_caller_url or None),
)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = SQLModel.metadata


def run_migrations_offline() -> None:
    """离线模式：只生成 SQL，不连接数据库（`alembic upgrade head --sql`）。"""
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=False,
        output_buffer=config.output_buffer,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """在线模式：连接数据库并真正执行迁移。"""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=False,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
