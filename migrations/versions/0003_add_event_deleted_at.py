"""add event.deleted_at for soft delete (archive)

为 event 表增加 deleted_at 列，用于**软删除 / 归档**：

- ``NULL``   = 未归档（普通列表可见，正常参与业务）
- 非 ``NULL`` = 已归档，值为归档时间（UTC）

为什么这样能保住已有数据：
- ``ADD COLUMN`` 只改表结构定义，不移动、不删除任何已有数据行；
- ``deleted_at`` 可空且**无默认值**，SQLite 对已有行直接补 ``NULL``（即「未归档」），
  不需要任何 ``UPDATE`` 回填；
- 整条 upgrade 路径上没有任何 ``DROP`` / ``DELETE`` 语句。

为什么软删除而不是物理删除：
- ``status_history.event_id`` 对 ``event.id`` 建了真实外键。若物理删除事件，
  历史记录的外键会悬挂（或在外键强制下报错）。软删除让 event 行始终存在，
  外键永远有效，审计记录也永远不会因为「删事件」而丢失。

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-16

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("event", sa.Column("deleted_at", sa.DateTime(), nullable=True))
    op.create_index("ix_event_deleted_at", "event", ["deleted_at"])


def downgrade() -> None:
    # 先删索引再删列（SQLite 不允许在被索引引用的列上直接 DROP COLUMN）。
    op.drop_index("ix_event_deleted_at", table_name="event")
    op.drop_column("event", "deleted_at")
