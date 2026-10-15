"""add event.status

本轮唯一的真实结构变更：给 event 表增加 status 列。

生成（upgrade）的 SQL 只有一句：
    ALTER TABLE event ADD COLUMN status VARCHAR(13) DEFAULT 'open' NOT NULL

为什么这样能保住已有数据：
- ADD COLUMN 只改表结构定义，不移动、不删除任何已有数据行；
- 因为新列是 NOT NULL，SQLite 强制要求给出非 NULL 常量默认值，
  加列的同一瞬间旧行就逻辑上获得了 'open'，**无需 UPDATE 回填**；
- 整个 upgrade 路径上没有任何 DROP / DELETE 语句。

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-16

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "event",
        sa.Column("status", sa.VARCHAR(length=13), nullable=False, server_default="open"),
    )


def downgrade() -> None:
    # 本机 sqlite3 3.49.1 支持原生 DROP COLUMN（需 >= 3.35）。
    # 若将来部署到更老的 SQLite，改成：
    #     with op.batch_alter_table("event") as batch:
    #         batch.drop_column("status")
    op.drop_column("event", "status")
