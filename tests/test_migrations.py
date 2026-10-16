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
from alembic.script import ScriptDirectory
from sqlmodel import SQLModel

from app.config import BASE_DIR, DATABASE_URL_ENV
from app.main import engine as app_engine  # noqa: F401  触发模型注册

MIGRATIONS_DIR = BASE_DIR / "migrations"
ALEMBIC_INI = BASE_DIR / "alembic.ini"

OLD_COLUMNS = ["title", "severity", "description", "id", "created_at"]
# V0.4.2 起 head 的 event 表多了 deleted_at（软删除标记）
NEW_COLUMNS = {
    "title", "severity", "status", "description", "id", "created_at", "deleted_at",
}
# V0.4.2 新增的审计表结构
HISTORY_COLUMNS = {
    "id", "event_id", "old_status", "new_status",
    "reason", "action", "actor_id", "changed_at",
}


def head_revision() -> str:
    """当前迁移链的 head 版本号。

    刻意**不写死**版本号：每次新增迁移都会推进 head，写死会让「版本记录指向 head」
    这类断言变成维护负担（要改测试而不是改产品）。
    """
    cfg = Config(str(ALEMBIC_INI))
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    return ScriptDirectory.from_config(cfg).get_current_head()


HEAD_REVISION = head_revision()

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

    # ⑥ 版本记录指向 head（head 会随新增迁移推进，所以用动态值而非写死 "0002"）
    assert selects(db, "select version_num from alembic_version") == [(HEAD_REVISION,)]


def test_migration_adds_status_column_with_server_default(tmp_path, in_tempdir):
    db = tmp_path / "legacy2.db"
    assert_in_tempdir(db, in_tempdir)
    cfg = alembic_config(db)
    command.upgrade(cfg, "0001")
    seed_old_rows(db)
    command.upgrade(cfg, "head")

    # 结构上 head 会在 0002 的 status 之后，追加 0003 的 deleted_at
    assert columns_of(db) == OLD_COLUMNS + ["status", "deleted_at"]
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

    # V0.4.2：审计表也要「迁移建出的结构 == 模型声明的结构」，防止两条路径漂移
    migrated_history = schema_by_name(migrated, "status_history")
    model_history = schema_by_name(model_db, "status_history")
    assert set(migrated_history) == set(model_history) == HISTORY_COLUMNS
    for name in sorted(model_history):
        assert migrated_history[name] == model_history[name], name


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
    assert selects(db, "select version_num from alembic_version") == [(HEAD_REVISION,)]


def test_fresh_database_upgrade_head(tmp_path, in_tempdir):
    db = tmp_path / "fresh.db"
    assert_in_tempdir(db, in_tempdir)
    command.upgrade(alembic_config(db), "head")
    assert db.exists()
    assert columns_of(db) == OLD_COLUMNS + ["status", "deleted_at"]
    assert selects(db, "select count(*) from event") == [(0,)]
    # 全新库也必须建出审计表
    assert "status_history" in [r[1] for r in selects(
        db, "select type,name from sqlite_master where type='table'"
    )]


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

    assert columns_of(db) == OLD_COLUMNS + ["status", "deleted_at"]
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
    # V0.4.2：完整 SQL 还应包含软删除列与审计表
    assert "ALTER TABLE event ADD COLUMN deleted_at DATETIME" in sql
    assert "CREATE TABLE status_history" in sql
    assert "FOREIGN KEY(event_id) REFERENCES event (id)" in sql
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

    assert caller_db.exists() and columns_of(caller_db) == OLD_COLUMNS + ["status", "deleted_at"]
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
    assert env_db.exists() and columns_of(env_db) == OLD_COLUMNS + ["status", "deleted_at"]


# ---------------------------------------------------------------------------
# 7) V0.4.2 专门：软删除列（0003）与审计表（0004）
# ---------------------------------------------------------------------------
def foreign_keys_of(db_path: Path, table: str) -> list[tuple]:
    with connect(db_path) as con:
        return list(con.execute(f"PRAGMA foreign_key_list({table})"))


def test_migration_0003_adds_deleted_at_nullable_and_keeps_data(tmp_path, in_tempdir):
    """0003：加 deleted_at 列，已有行补 NULL（未归档），其余数据一字不动。"""
    db = tmp_path / "soft-delete.db"
    assert_in_tempdir(db, in_tempdir)
    cfg = alembic_config(db)
    command.upgrade(cfg, "0002")
    seed_old_rows(db)
    before = selects(
        db, "select id,title,severity,description,created_at from event order by id"
    )

    command.upgrade(cfg, "0003")

    assert columns_of(db) == OLD_COLUMNS + ["status", "deleted_at"]
    after = selects(
        db, "select id,title,severity,description,created_at from event order by id"
    )
    assert after == before  # 逐字段零损失
    # 已有行全部是「未归档」；deleted_at 必须可空、无默认值
    assert selects(db, "select deleted_at from event order by id") == [
        (None,), (None,), (None,),
    ]
    col_type, notnull, default = schema_by_name(db)["deleted_at"]
    assert notnull == 0 and default is None
    assert selects(db, "select version_num from alembic_version") == [("0003",)]


def test_migration_0004_creates_history_table_with_real_foreign_key(tmp_path, in_tempdir):
    """0004：建审计表，列齐全、外键指向 event.id、迁移不写入任何审计行。"""
    db = tmp_path / "history.db"
    assert_in_tempdir(db, in_tempdir)
    cfg = alembic_config(db)
    command.upgrade(cfg, "0003")
    seed_old_rows(db)

    command.upgrade(cfg, "0004")

    assert columns_of(db, "status_history") == [
        "id", "event_id", "old_status", "new_status",
        "reason", "action", "actor_id", "changed_at",
    ]
    # 外键必须是真实存在的约束（不是只写在注释里）
    fks = foreign_keys_of(db, "status_history")
    assert [f[2:5] for f in fks] == [("event", "event_id", "id")], fks
    # 迁移只建表、不造数据：审计从第一次真实状态变更才开始
    assert selects(db, "select count(*) from status_history") == [(0,)]
    # 已有事件数据仍然完好
    assert len(selects(db, "select id from event order by id")) == 3
    assert selects(db, "select version_num from alembic_version") == [("0004",)]


def test_downgrade_0004_to_0002_drops_history_then_deleted_at(tmp_path, in_tempdir):
    """回退：先删审计表、再删 deleted_at，event 数据必须完好保留。"""
    db = tmp_path / "down-soft.db"
    assert_in_tempdir(db, in_tempdir)
    cfg = alembic_config(db)
    command.upgrade(cfg, "0002")
    seed_old_rows(db)
    command.upgrade(cfg, "head")
    assert columns_of(db, "status_history")  # 确认确实建过

    command.downgrade(cfg, "0002")

    tables = [r[1] for r in selects(db, "select type,name from sqlite_master")]
    assert "status_history" not in tables
    assert columns_of(db) == OLD_COLUMNS + ["status"]
    after = selects(
        db, "select id,title,severity,description,created_at from event order by id"
    )
    assert after == [(r[0], r[1], r[2], r[3], r[4]) for r in SEED_ROWS]
    assert selects(db, "select version_num from alembic_version") == [("0002",)]


def test_offline_sql_incremental_0003_to_0004(tmp_path, in_tempdir):
    """本轮增量 SQL 必须能先过目：只含建审计表，不含 ALTER event。"""
    db = tmp_path / "offline-0404.db"
    assert_in_tempdir(db, in_tempdir)
    buffer = io.StringIO()
    command.upgrade(alembic_config(db, buffer=buffer), "0003:0004", sql=True)
    sql = buffer.getvalue()

    assert "CREATE TABLE status_history" in sql
    assert "FOREIGN KEY(event_id) REFERENCES event (id)" in sql
    assert "CREATE INDEX ix_status_history_event_id" in sql
    assert "ALTER TABLE event" not in sql, "增量 SQL 不应改动 event 表"
    assert not db.exists()


# ---------------------------------------------------------------------------
# 8) V0.5.1 专门：认证表（0005 = app_user / user_session）
# ---------------------------------------------------------------------------
APP_USER_COLUMNS = {
    "id", "username", "password_hash", "role", "is_active", "created_at",
    "password_changed_at", "last_login_at", "failed_login_count", "locked_until",
    "display_name",
}
USER_SESSION_COLUMNS = {
    "id", "token_hash", "user_id", "csrf_token", "created_at", "last_seen_at",
    "expires_at", "revoked_at", "revoked_reason", "user_agent", "ip_address",
}


def indexes_of(db_path: Path, table: str) -> dict[str, tuple[bool, list[str]]]:
    """表上的索引：``{名字: (是否唯一, 列名列表)}``。"""
    with connect(db_path) as con:
        rows = list(con.execute(f"PRAGMA index_list({table})"))
    result: dict[str, tuple[bool, list[str]]] = {}
    with connect(db_path) as con:
        for row in rows:
            name, unique = row[1], bool(row[2])
            columns = [r[2] for r in con.execute(f"PRAGMA index_info({name})")]
            result[name] = (unique, columns)
    return result


def test_migration_0005_creates_auth_tables_with_real_foreign_key(tmp_path, in_tempdir):
    """0005：建 `app_user` / `user_session`，外键必须是**真实约束**。

    评审意见 R1-4 的原话是"在临时数据库用 `PRAGMA foreign_key_list` 验证"——
    该要求针对 0006 的 `actor_user_id`；这里是它在 0005 上的同款做法：
    不靠"文档说有关系"，而是直接问 SQLite。
    """
    db = tmp_path / "auth-tables.db"
    assert_in_tempdir(db, in_tempdir)
    cfg = alembic_config(db)
    command.upgrade(cfg, "0004")
    seed_old_rows(db)
    events_before = selects(
        db, "select id,title,severity,description,created_at from event order by id"
    )

    command.upgrade(cfg, "0005")

    assert set(columns_of(db, "app_user")) == APP_USER_COLUMNS
    assert set(columns_of(db, "user_session")) == USER_SESSION_COLUMNS

    # 外键：user_session.user_id → app_user.id（PRAGMA 返回的第 3~5 列即
    # 被引用表 / 本表列 / 被引用列）
    fks = foreign_keys_of(db, "user_session")
    assert [f[2:5] for f in fks] == [("app_user", "user_id", "id")], fks
    # app_user 自己不应该有外键（它是最底层的主体表）
    assert foreign_keys_of(db, "app_user") == []

    # 唯一性约束按**唯一索引**实现（与 SQLModel 的 index=True, unique=True 一致）
    user_indexes = indexes_of(db, "app_user")
    assert any(
        unique and columns == ["username"] for unique, columns in user_indexes.values()
    ), user_indexes
    session_indexes = indexes_of(db, "user_session")
    assert any(
        unique and columns == ["token_hash"] for unique, columns in session_indexes.values()
    ), session_indexes

    # 迁移只建表、不造数据：账号由 CLI 显式创建
    assert selects(db, "select count(*) from app_user") == [(0,)]
    assert selects(db, "select count(*) from user_session") == [(0,)]

    # 既有数据一字不动，版本推进到 head
    assert selects(
        db, "select id,title,severity,description,created_at from event order by id"
    ) == events_before
    assert selects(db, "select version_num from alembic_version") == [(HEAD_REVISION,)]


def test_foreign_key_is_enforced_on_user_session(tmp_path, in_tempdir):
    """外键不只是"写在 DDL 里"—— 打开 `PRAGMA foreign_keys` 后必须真的拦住脏数据。"""
    db = tmp_path / "fk-enforced.db"
    assert_in_tempdir(db, in_tempdir)
    command.upgrade(alembic_config(db), "head")

    con = sqlite3.connect(str(db))
    try:
        con.execute("PRAGMA foreign_keys=ON")
        con.execute(
            "insert into app_user (id, username, password_hash, role, is_active,"
            " created_at, password_changed_at, failed_login_count)"
            " values (1, 'admin', '$argon2id$fake', 'admin', 1,"
            " '2026-10-16 00:00:00', '2026-10-16 00:00:00', 0)"
        )
        con.execute(
            "insert into user_session (id, token_hash, user_id, csrf_token, created_at,"
            " last_seen_at, expires_at) values (1, 'h', 1, 'c',"
            " '2026-10-16 00:00:00', '2026-10-16 00:00:00', '2026-10-16 01:00:00')"
        )
        con.commit()

        with pytest.raises(sqlite3.IntegrityError):
            con.execute(
                "insert into user_session (id, token_hash, user_id, csrf_token, created_at,"
                " last_seen_at, expires_at) values (2, 'h2', 999, 'c',"
                " '2026-10-16 00:00:00', '2026-10-16 00:00:00', '2026-10-16 01:00:00')"
            )
    finally:
        con.close()


def test_auth_tables_migrated_matches_model_schema(tmp_path, in_tempdir):
    """V0.5.1 的防漂移：认证表也要「迁移建出的结构 == 模型声明的结构」。

    新表尤其容易漂移：`create_all` 与 Alembic 各写一遍 DDL，
    列宽（`role` 的 VARCHAR(7)！）与 `server_default` 的有无都极易不一致。
    """
    migrated = tmp_path / "auth-migrated.db"
    assert_in_tempdir(migrated, in_tempdir)
    command.upgrade(alembic_config(migrated), "head")

    model_db = tmp_path / "auth-model.db"
    assert_in_tempdir(model_db, in_tempdir)
    from sqlmodel import create_engine

    model_engine = create_engine(f"sqlite:///{model_db.as_posix()}")
    try:
        SQLModel.metadata.create_all(model_engine)
    finally:
        model_engine.dispose()

    for table, expected in (
        ("app_user", APP_USER_COLUMNS),
        ("user_session", USER_SESSION_COLUMNS),
    ):
        migrated_schema = schema_by_name(migrated, table)
        model_schema = schema_by_name(model_db, table)
        assert set(migrated_schema) == set(model_schema) == expected, table
        for name in sorted(model_schema):
            assert migrated_schema[name] == model_schema[name], f"{table}.{name}"

    # 钉住那个最容易改错的宽度：role 枚举最长值 analyst = 7
    assert schema_by_name(migrated, "app_user")["role"][0] == "VARCHAR(7)"
    # token_hash 存 SHA-256 的 hex（正好 64），csrf_token 存 32 字节的 hex（64）
    assert schema_by_name(migrated, "user_session")["token_hash"][0] == "VARCHAR(64)"
    assert schema_by_name(migrated, "user_session")["csrf_token"][0] == "VARCHAR(64)"


def test_downgrade_0005_drops_auth_tables_only(tmp_path, in_tempdir):
    """回退：只删两张新表，`event` / `status_history` 与它们的行必须完好。"""
    db = tmp_path / "down-auth.db"
    assert_in_tempdir(db, in_tempdir)
    cfg = alembic_config(db)
    command.upgrade(cfg, "0004")
    seed_old_rows(db)
    command.upgrade(cfg, "head")
    assert columns_of(db, "app_user") and columns_of(db, "user_session")

    command.downgrade(cfg, "0004")

    tables = [r[1] for r in selects(db, "select type,name from sqlite_master")]
    assert "app_user" not in tables and "user_session" not in tables
    assert "event" in tables and "status_history" in tables
    assert len(selects(db, "select id from event order by id")) == 3
    assert selects(db, "select version_num from alembic_version") == [("0004",)]


def test_upgrade_downgrade_0005_round_trip_is_idempotent(tmp_path, in_tempdir):
    """往返：head → 0004 → head，表结构必须回到完全相同的定义。"""
    db = tmp_path / "round-auth.db"
    assert_in_tempdir(db, in_tempdir)
    cfg = alembic_config(db)
    command.upgrade(cfg, "0005")
    before = (
        schema_by_name(db, "app_user"),
        schema_by_name(db, "user_session"),
        foreign_keys_of(db, "user_session"),
    )

    command.downgrade(cfg, "0004")
    command.upgrade(cfg, "0005")

    after = (
        schema_by_name(db, "app_user"),
        schema_by_name(db, "user_session"),
        foreign_keys_of(db, "user_session"),
    )
    assert after == before
    assert selects(db, "select version_num from alembic_version") == [("0005",)]


def test_offline_sql_incremental_0004_to_0005(tmp_path, in_tempdir):
    """本轮增量 SQL 必须能先过目：只建两张认证表，不动任何既有表。"""
    db = tmp_path / "offline-0405.db"
    assert_in_tempdir(db, in_tempdir)
    buffer = io.StringIO()
    command.upgrade(alembic_config(db, buffer=buffer), "0004:0005", sql=True)
    sql = buffer.getvalue()

    assert "CREATE TABLE app_user" in sql
    assert "CREATE TABLE user_session" in sql
    assert "FOREIGN KEY(user_id) REFERENCES app_user (id)" in sql
    assert "CREATE UNIQUE INDEX ix_app_user_username" in sql
    assert "CREATE UNIQUE INDEX ix_user_session_token_hash" in sql
    # 本轮是**纯新增**：不得出现任何 ALTER / DROP / 数据改动。
    # 注意要把 Alembic 自己的版本记账（`UPDATE alembic_version SET ...`）排除掉 ——
    # 那不是我们的迁移在改业务数据，而是框架推进版本号。
    body = "\n".join(line for line in sql.splitlines() if "alembic_version" not in line)
    for forbidden in ("ALTER TABLE", "DROP TABLE", "DROP INDEX", "DELETE FROM", "UPDATE "):
        assert forbidden not in body, f"0005 的增量 SQL 里出现了 {forbidden!r}"
    assert not db.exists(), "离线模式（--sql）不应创建任何数据库文件"


def test_offline_sql_full_upgrade_includes_auth_tables(tmp_path, in_tempdir):
    """完整离线 SQL 也必须包含认证表 —— 生产迁移要照着它过目。"""
    db = tmp_path / "offline-full-v05.db"
    assert_in_tempdir(db, in_tempdir)
    buffer = io.StringIO()
    command.upgrade(alembic_config(db, buffer=buffer), "head", sql=True)
    sql = buffer.getvalue()

    assert "CREATE TABLE app_user" in sql
    assert "CREATE TABLE user_session" in sql
    assert not db.exists()


def test_real_database_is_never_migrated_by_the_suite(in_tempdir):
    """兜底断言：真实库存在时，它的字节内容不得因跑测试而改变。

    这条测试的价值不在于"它会不会失败"，而在于它把纪律**写进了测试套件**：
    任何一次误把真实库当迁移目标的改动（改 `alembic.ini`、改 `env.py`
    的默认值、把 URL 写死成相对路径……）都会让真实库的 mtime / 大小变化，
    从而在这里暴露。
    """
    real = BASE_DIR / "cyberwatch.db"
    if not real.exists():
        pytest.skip("本机没有真实库，跳过（CI 上属正常）")

    before = (real.stat().st_size, real.stat().st_mtime_ns)
    import hashlib

    digest_before = hashlib.sha256(real.read_bytes()).hexdigest()
    assert in_tempdir(real) is False  # 真实库确实在项目目录（不是临时目录）

    after = (real.stat().st_size, real.stat().st_mtime_ns)
    digest_after = hashlib.sha256(real.read_bytes()).hexdigest()
    assert (after, digest_after) == (before, digest_before), "真实库在测试期间被改动了"
