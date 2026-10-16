"""add status_history table (append-only audit log)

新增状态变更历史表 ``status_history``：每次状态切换 / 归档 / 恢复都追加一行。

为什么能保住已有数据：
- 这是**纯新增表**，不改 event 表、不删任何列、不碰任何已有数据行；
- ``CREATE TABLE`` + ``CREATE INDEX`` 两条语句，没有 ``DROP`` / ``DELETE``。

审计「只追加」怎么保证：
- 应用层不提供任何修改 / 删除本表的接口（见 app/main.py 的路由清单）；
- 唯一写入口是「状态变更 / 归档」这条业务链路，且与状态修改同事务提交。

外键说明：
- ``event_id`` 对 ``event.id`` 建真实外键。SQLite 默认不强制外键，应用与
  Alembic 连接都会执行 ``PRAGMA foreign_keys=ON``（见 app/config.py），
  因此这条约束是**真实生效**的，不是装饰。
- 因为 event 采用软删除（0003），本表引用的 event 行永远存在，外键不会悬挂。

降级顺序（重要）：
- ``downgrade()`` 必须先删本表，再让 ``0003`` 删 ``event.deleted_at``；
  Alembic 按 revision 逆序执行，顺序天然正确。

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-16

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "status_history",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("event_id", sa.Integer(), nullable=False),
        sa.Column("old_status", sa.VARCHAR(length=13), nullable=False),
        sa.Column("new_status", sa.VARCHAR(length=13), nullable=False),
        sa.Column("reason", sa.VARCHAR(length=1000), nullable=False),
        sa.Column("action", sa.VARCHAR(length=50), nullable=False),
        sa.Column("actor_id", sa.VARCHAR(length=64), nullable=False),
        sa.Column("changed_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["event_id"], ["event.id"]),
    )
    op.create_index("ix_status_history_event_id", "status_history", ["event_id"])


def downgrade() -> None:
    op.drop_index("ix_status_history_event_id", table_name="status_history")
    op.drop_table("status_history")
