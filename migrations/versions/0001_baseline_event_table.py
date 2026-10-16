"""baseline: existing event table (V0.3 structure)

本脚本把 V0.3 时期**已经存在**的 event 表结构写成基线。
对已有库它会被 `alembic stamp 0001` 跳过（表已存在，不需要重建）；
对全新库它会真实建出这张表。

Revision ID: 0001
Revises:
Create Date: 2026-10-16

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "event",
        sa.Column("title", sa.VARCHAR(length=100), nullable=False),
        sa.Column("severity", sa.VARCHAR(length=6), nullable=False),
        sa.Column("description", sa.VARCHAR(length=1000), nullable=False),
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("event")
