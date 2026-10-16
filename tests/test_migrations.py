"""Alembic 迁移测试（需求 7、12）：全部在系统临时目录的独立 SQLite 库上进行。

安全约定（每条用例都强制断言）：
- 使用的数据库文件必须位于系统临时目录内；
- 永远不读取、不写入项目里的真实 ``cyberwatch.db``；
- 迁移 URL 通过 ``Config.set_main_option`` 显式传入，``migrations/env.py``
  不得把它覆盖掉。
"""
from __future__ import annotations

import io
import sqlite3
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlmodel import SQLModel

from app.config import BASE_DIR, DATABASE_URL_ENV
from app.main import engine as app_engine  # noqa: F401  触发模型注册

MIGRATIONS_DIR = BASE_DIR / "migrations"
ALEMBIC_INI = BASE_DIR / "alembic.ini"

OLD_COLUMNS = ["title", "severity", "description", "id", "created_at"]
NEW_COLUMNS = {"title", "severity", "status", "description", "id", "created_at"}

# 与真实库完全相同的 3 行数据（id 与 created_at 都由我们显式指定，便于逐字段比对）
SEED_ROWS = [
    (1, "Suspicious Login Attempt", "high",
     "Multiple failed login attempts detected from IP 192.0.2.10 within 5 minutes.",
     "2026-10-13 11:30:32.106745"),
    (2, "Dashboard lab event", "medium",
     "Created from pink dashboard to verify POST /events",
     "2026-10-13 14:19:56.286246"),
    (3, "浏览器访问未知外部资讯站点", "low",
     "员工终端访问未收录的资讯类网站，不存在恶意域名、病毒下载行为，仅网页浏览，做常规记录",
     "2026-10-13 14:30:53.561363"),
]


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------
def alembic_config(db_path: Path, *, url: str | None = None, buffer: io.StringIO | None = None) -> Config:
    cfg = Config(str(ALEMBIC_INI))
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    cfg.set_main_option(
        "sqlalchemy.url", url if url is not None else f"sqlite:///{db_path.as_posix()}"
    )
    cfg.output_buffer = buffer
    return cfg


def connect(db_path: Path) -> sqlite3.Connection:
    """只读连接，避免测试脚本自己写文件。"""
    return sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)


def columns_of(db_path: Path, table: str = "event") -> list[str]:
    with connect(db_path) as con:
        return [row[1] for row in con.execute(f"PRAGMA table_info({table})")]


def schema_by_name(db_path: Path, table: str = "event") -> dict[str, tuple]:
    """按**列名**取结构（列、类型、是否 NOT NULL、默认值）。

    刻意不比较物理列顺序：`ADD COLUMN` 只能追加到末尾，
    顺序与 `create_all` 不同是预期内的，按位置比较会误报。
    """
    with connect(db_path) as con:
        rows = list(con.execute(f"PRAGMA table_info({table})"))
    return {row[1]: (row[2], row[3], row[4]) for row in rows}


def selects(db_path: Path, sql: str) -> list[tuple]:
    with connect(db_path) as con:
        return list(con.execute(sql))


def seed_old_rows(db_path: Path) -> None:
    """在「旧结构」的表里插入种子数据（显式指定 id 与 created_at）。"""
    con = sqlite3.connect(str(db_path))
    try:
        con.executemany(
            "insert into event (id, title, severity, description, created_at) "
            "values (?, ?, ?, ?, ?)",
            SEED_ROWS,
        )
        con.commit()
    finally:
        con.close()


def assert_in_tempdir(db_path: Path, in_tempdir) -> None:
    """需求：迁移测试必须断言实际数据库路径位于系统临时目录。"""
    assert in_tempdir(db_path), f"迁移测试用到了非临时目录：{db_path}"
    assert db_path.resolve() != (BASE_DIR / "cyberwatch.db").resolve()


# ---------------------------------------------------------------------------
# 1) 核心：旧库迁移后数据零损失，且旧事件 status 默认 open
# ---------------------------------------------------------------------------
def test_migration_preserves_existing_data(tmp_path, in_tempdir):
    db = tmp_path / "legacy.db"
    assert_in_tempdir(db, in_tempdir)
    cfg = alembic_config(db)

    # ① 先建出「旧的 5 列结构」
    command.upgrade(cfg, "0001")
    assert db.exists()
    assert columns_of(db) == OLD_COLUMNS
    assert selects(db, "select name from sqlite_master where name='alembic_version'")

    # ② 写入旧数据
    seed_old_rows(db)
    before = selects(
        db, "select id,title,severity,description,created_at from event order by id"
    )
    assert len(before) == 3

    # ③ 升级到 head（唯一的真实变更：ADD COLUMN status）
    command.upgrade(cfg, "head")

    # ④ 逐字段比对：id / title / severity / description / created_at 一字不差
    after = selects(
        db,
        "select id,title,severity,description,created_at from event order by id",
    )
    assert after == before
    for row_after, row_before in zip(after, before):
        assert row_after[0] == row_before[0]                       # id 保持不变
        assert row_after[4] == row_before[4]                       # created_at 含微秒
        assert row_after[4].endswith(("106745", "286246", "561363"))

    # ⑤ 已有事件的 status 默认值必须是 open
    statuses = [row[0] for row in selects(db, "select status from event order by id")]
    assert statuses == ["open", "open", "open"]

    # ⑥ 版本记录指向 head
    assert selects(db, "select version_num from alembic_version") == [("0002",)]


def test_migration_adds_status_column_with_server_default(tmp_path, in_tempdir):
    db = tmp_path / "legacy2.db"
    assert_in_tempdir(db, in_tempdir)
    cfg = alembic_config(db)
    command.upgrade(cfg, "0001")
    seed_old_rows(db)
    command.upgrade(cfg, "head")

    assert columns_of(db) == OLD_COLUMNS + ["status"]  # ADD COLUMN 只能追加到末尾
    col_type, notnull, default = schema_by_name(db)["status"]
    assert col_type == "VARCHAR(13)"
    assert notnull == 1
    assert default == "'open'"

    # 裸 SQL 只插 id：新列必须自动获得 open（server_default 生效），不抛 NOT NULL
    con = sqlite3.connect(str(db))
    try:
        con.execute("insert into event (id, title, severity, description, created_at) "
                    "values (99, 'no status given', 'low', 'd', '2026-10-16 00:00:00.000000')")
        con.commit()
    finally:
        con.close()
    assert selects(db, "select status from event where id=99") == [("open",)]


# ---------------------------------------------------------------------------
# 2) 迁移出的结构 == 模型 create_all 出的结构（防止两条建表路径长期漂移）
# ---------------------------------------------------------------------------
def test_migrated_schema_matches_model_schema(tmp_path, in_tempdir):
    migrated = tmp_path / "migrated.db"
    assert_in_tempdir(migrated, in_tempdir)
    command.upgrade(alembic_config(migrated), "head")

    model_db = tmp_path / "model.db"
    assert_in_tempdir(model_db, in_tempdir)
    from sqlmodel import create_engine

    model_engine = create_engine(f"sqlite:///{model_db.as_posix()}")
    try:
        SQLModel.metadata.create_all(model_engine)
    finally:
        model_engine.dispose()

    migrated_schema = schema_by_name(migrated)
    model_schema = schema_by_name(model_db)

    assert set(migrated_schema) == set(model_schema) == NEW_COLUMNS
    for name in sorted(model_schema):
        assert migrated_schema[name] == model_schema[name], name


# ---------------------------------------------------------------------------
# 3) 幂等 / 升级路径
# ---------------------------------------------------------------------------
def test_upgrade_head_is_idempotent(tmp_path, in_tempdir):
    db = tmp_path / "idem.db"
    assert_in_tempdir(db, in_tempdir)
    cfg = alembic_config(db)
    command.upgrade(cfg, "0001")
    seed_old_rows(db)
    command.upgrade(cfg, "head")
    first = selects(db, "select id,status from event order by id")

    command.upgrade(cfg, "head")  # 再跑一次不得报错、不得改数据
    assert selects(db, "select id,status from event order by id") == first
    assert selects(db, "select version_num from alembic_version") == [("0002",)]


def test_fresh_database_upgrade_head(tmp_path, in_tempdir):
    db = tmp_path / "fresh.db"
    assert_in_tempdir(db, in_tempdir)
    command.upgrade(alembic_config(db), "head")
    assert db.exists()
    assert columns_of(db) == OLD_COLUMNS + ["status"]
    assert selects(db, "select count(*) from event") == [(0,)]


# ---------------------------------------------------------------------------
# 4) 回退（downgrade）
# ---------------------------------------------------------------------------
def test_downgrade_removes_status_but_keeps_data(tmp_path, in_tempdir):
    db = tmp_path / "down.db"
    assert_in_tempdir(db, in_tempdir)
    cfg = alembic_config(db)
    command.upgrade(cfg, "0001")
    seed_old_rows(db)
    command.upgrade(cfg, "head")

    command.downgrade(cfg, "0001")

    assert "status" not in columns_of(db)
    after = selects(
        db, "select id,title,severity,description,created_at from event order by id"
    )
    assert after == [
        (r[0], r[1], r[2], r[3], r[4]) for r in SEED_ROWS
    ], after
    assert selects(db, "select version_num from alembic_version") == [("0001",)]


def test_downgrade_and_reupgrade_round_trip(tmp_path, in_tempdir):
    db = tmp_path / "round.db"
    assert_in_tempdir(db, in_tempdir)
    cfg = alembic_config(db)
    command.upgrade(cfg, "0001")
    seed_old_rows(db)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "0001")
    command.upgrade(cfg, "head")

    assert columns_of(db) == OLD_COLUMNS + ["status"]
    assert [r[0] for r in selects(db, "select status from event order by id")] == [
        "open", "open", "open",
    ]


# ---------------------------------------------------------------------------
# 5) 离线 SQL：完整迁移 + 本轮增量，都要能先过目再执行
# ---------------------------------------------------------------------------
def test_offline_sql_full_upgrade(tmp_path, in_tempdir):
    db = tmp_path / "offline-full.db"
    assert_in_tempdir(db, in_tempdir)
    buffer = io.StringIO()
    command.upgrade(alembic_config(db, buffer=buffer), "head", sql=True)
    sql = buffer.getvalue()

    assert "CREATE TABLE event" in sql
    assert "ALTER TABLE event ADD COLUMN status VARCHAR(13) DEFAULT 'open' NOT NULL" in sql
    # 离线模式不得真的碰数据库
    assert not db.exists(), "离线模式（--sql）不应创建任何数据库文件"
    # 生成的 SQL 里不得出现真实库路径
    real = str(BASE_DIR / "cyberwatch.db").replace("\\", "/")
    assert real not in sql.replace("\\", "/")


def test_offline_sql_incremental_0001_to_0002(tmp_path, in_tempdir):
    db = tmp_path / "offline-inc.db"
    assert_in_tempdir(db, in_tempdir)
    buffer = io.StringIO()
    command.upgrade(alembic_config(db, buffer=buffer), "0001:0002", sql=True)
    sql = buffer.getvalue()

    assert "ALTER TABLE event ADD COLUMN status VARCHAR(13) DEFAULT 'open' NOT NULL" in sql
    assert "CREATE TABLE event" not in sql, "增量 SQL 不应包含建表语句"
    assert not db.exists()


# ---------------------------------------------------------------------------
# 6) env.py 不得覆盖调用方指定的临时库 URL（本轮修正的核心安全问题）
# ---------------------------------------------------------------------------
def test_env_py_respects_caller_url_and_never_falls_back_to_env_var(
    tmp_path, monkeypatch, in_tempdir
):
    caller_db = tmp_path / "caller.db"
    decoy_db = tmp_path / "decoy.db"
    assert_in_tempdir(caller_db, in_tempdir)
    assert_in_tempdir(decoy_db, in_tempdir)

    # 环境变量指向「诱饵」库：如果 env.py 覆盖了调用方 URL，迁移就会落到这里
    monkeypatch.setenv(DATABASE_URL_ENV, f"sqlite:///{decoy_db.as_posix()}")

    command.upgrade(alembic_config(caller_db), "head")

    assert caller_db.exists() and columns_of(caller_db) == OLD_COLUMNS + ["status"]
    assert not decoy_db.exists(), "env.py 覆盖了调用方显式指定的 URL"


def test_env_py_uses_env_var_when_caller_gives_nothing(tmp_path, monkeypatch, in_tempdir):
    """调用方没给 URL 时，才轮到环境变量生效。"""
    env_db = tmp_path / "from-env.db"
    assert_in_tempdir(env_db, in_tempdir)
    monkeypatch.setenv(DATABASE_URL_ENV, f"sqlite:///{env_db.as_posix()}")

    cfg = Config(str(ALEMBIC_INI))
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    cfg.set_main_option("sqlalchemy.url", "")  # 与 alembic.ini 的留空一致

    command.upgrade(cfg, "head")
    assert env_db.exists() and columns_of(env_db) == OLD_COLUMNS + ["status"]
