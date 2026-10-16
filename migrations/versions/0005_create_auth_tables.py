"""create auth tables: app_user / user_session

V0.5.1 的唯一结构变更：为「账号 + 服务端会话」新建两张表。

为什么这一步对真实库是**零风险**的：

- 全是 ``CREATE TABLE`` + ``CREATE INDEX``，**没有**任何 ``ALTER`` / ``DROP``
  / ``DELETE`` / ``UPDATE``；
- 不改 ``event``、不改 ``status_history`` 的任何列、任何行；
- 迁移**不造数据**：不插入用户、不插入会话（首位管理员由
  ``python -m app.cli create-admin`` 显式创建）。

两个刻意的结构决定：

1. **表名 `app_user` 而不是 `user`**：``user`` 在 PostgreSQL / MySQL 里是保留字，
   而 PostgreSQL 是本项目的路线图目标。
2. **新表一律不写 `server_default`**：新建表不存在"给已有行回填"的问题，
   而一旦写了，`create_all` 与 Alembic 两条建表路径就很容易在
   ``DEFAULT '1'`` vs ``DEFAULT 1`` 这类细节上漂移，
   被 `test_migrated_schema_matches_model_schema` 抓出来。
   默认值全部由 Python 侧（SQLModel 的 ``default_factory``）给出。

列宽与模型的对应关系（改一处必须同步改另一处）：

- ``role`` 是 **VARCHAR(7)**：SQLModel 用枚举**最长值**的长度（``analyst``=7）；
- ``username`` 是 VARCHAR(32)，``password_hash`` 是 VARCHAR(255)
  （实测 Argon2id 编码串 97 字符，余量 2.6 倍）；
- ``token_hash`` 是 VARCHAR(64)：SHA-256 的十六进制摘要正好 64 字符；
- ``csrf_token`` 是 VARCHAR(64)：32 字节 → 64 个 hex 字符。

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-16

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "app_user",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("username", sa.VARCHAR(length=32), nullable=False),
        sa.Column("password_hash", sa.VARCHAR(length=255), nullable=False),
        sa.Column("role", sa.VARCHAR(length=7), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("password_changed_at", sa.DateTime(), nullable=False),
        sa.Column("last_login_at", sa.DateTime(), nullable=True),
        sa.Column("failed_login_count", sa.Integer(), nullable=False),
        sa.Column("locked_until", sa.DateTime(), nullable=True),
        sa.Column("display_name", sa.VARCHAR(length=64), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    # 用户名唯一：唯一性由**唯一索引**保证（不是表级 UNIQUE 约束），
    # 这样索引名与 SQLModel 的 `index=True, unique=True` 完全一致。
    op.create_index("ix_app_user_username", "app_user", ["username"], unique=True)

    op.create_table(
        "user_session",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.VARCHAR(length=64), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("csrf_token", sa.VARCHAR(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_reason", sa.VARCHAR(length=32), nullable=True),
        sa.Column("user_agent", sa.VARCHAR(length=255), nullable=True),
        sa.Column("ip_address", sa.VARCHAR(length=64), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["user_id"], ["app_user.id"]),
    )
    op.create_index("ix_user_session_token_hash", "user_session", ["token_hash"], unique=True)
    op.create_index("ix_user_session_user_id", "user_session", ["user_id"])


def downgrade() -> None:
    # 顺序很重要：先删子表（user_session）的索引与表，再删父表（app_user）。
    # 反过来会撞上 user_session.user_id → app_user.id 的外键。
    op.drop_index("ix_user_session_user_id", table_name="user_session")
    op.drop_index("ix_user_session_token_hash", table_name="user_session")
    op.drop_table("user_session")
    op.drop_index("ix_app_user_username", table_name="app_user")
    op.drop_table("app_user")
