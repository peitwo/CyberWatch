"""全部领域模型与请求/响应 schema（V0.5 新增，集中式单一真相）。

**为什么把所有模型放在一个模块里**（评审意见 R1-1）：
V0.5 之前 `Event` / `StatusHistory` 在 `app/main.py`，而设计初稿把
`User` / `UserSession` 放进 `app/auth.py`。这会造成两个问题：

1. `auth.py` 要用 `StatusHistory` 做审计关联、`main.py` 要用 `User` 做鉴权，
   两边互相 import → **循环导入**；
2. 同一类东西散落两处，改表结构时容易只改一半。

因此本模块是**唯一**声明 SQLModel 表模型的地方。依赖方向严格单向：

    models.py  ←  permissions.py  ←  auth.py  ←  main.py

本模块只依赖 `sqlmodel` / `pydantic` / 标准库，**不** import 任何其它 `app.*`
模块（`app/main.py` 会 re-export 这里的全部公开名字，保持既有导入路径可用）。
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import ConfigDict, SecretStr, model_validator
from sqlmodel import Field, SQLModel

# ---------------------------------------------------------------------------
# 0) 审计动作常量
# ---------------------------------------------------------------------------
#: 审计动作类型。当前实现三种：状态变更 / 归档 / 恢复。
ACTION_STATUS_CHANGE = "status_change"
ACTION_ARCHIVE = "archive"
ACTION_RESTORE = "restore"

#: 操作主体（actor）的**开发环境占位身份**（V0.4.2 及以前写入的全部历史行）。
#: V0.5.1 仍然使用它（真实用户归属在 V0.5.3 落地），语义上代表
#: 「这条审计记录属于"还没有账号系统"的年代」。
LEGACY_ACTOR_ID = "local-dev"

#: 向后兼容别名：既有代码与测试按 `DEFAULT_ACTOR_ID` 取用。
#: 注意 —— 它的含义从"新写入的默认值"变成了"历史行标记"，
#: 但**取值不变**，因此既有断言（`actor_id == "local-dev"`）继续成立。
DEFAULT_ACTOR_ID = LEGACY_ACTOR_ID

#: 未来系统动作（自动归档、CLI 批处理、迁移脚本）的 actor 标识。
SYSTEM_ACTOR_ID = "system"


def utcnow() -> datetime:
    """aware UTC 时间（保留在 models 层，便于 `default_factory` 使用）。"""
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# 1) 枚举
# ---------------------------------------------------------------------------
class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class Status(str, Enum):
    """安全事件的生命周期状态。三个值之间**可任意方向切换**（不实现状态机）。"""

    open = "open"
    investigating = "investigating"
    resolved = "resolved"


class Role(str, Enum):
    """账号角色。**最长值 `analyst` = 7 字符**，因此 DDL 类型是 ``VARCHAR(7)``。

    改这里时要同步改迁移 0005 的 ``sa.VARCHAR(length=7)``，否则
    `test_migrated_schema_matches_model_schema` 会立刻变红（这是刻意设计的护栏）。
    """

    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


# ---------------------------------------------------------------------------
# 2) 安全事件领域
# ---------------------------------------------------------------------------
class EventBase(SQLModel):
    title: str = Field(min_length=3, max_length=100)
    severity: Severity = Severity.low
    # default 负责「应用新建事件默认 open」；server_default 负责「迁移时给已有行补 open」，
    # 并且让 create_all 建出的表与 Alembic 迁移出的表结构完全一致。
    status: Status = Field(default=Status.open, sa_column_kwargs={"server_default": "open"})
    description: str = Field(default="", max_length=1000)


class Event(EventBase, table=True):
    id: int | None = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=utcnow)
    # 软删除 / 归档标记：NULL = 未归档（普通列表可见）；非 NULL = 已归档（值为归档时间 UTC）。
    # 采用软删除而不是物理删除，是为了让 status_history 的外键永远有效、审计记录永不丢失。
    deleted_at: datetime | None = Field(default=None, index=True)


class StatusHistory(SQLModel, table=True):
    """状态变更历史（只追加的审计日志）。

    每次「状态切换 / 归档 / 恢复」追加一行，**永不修改、永不删除**：

    - 应用层不提供任何修改或删除本表的接口（见 `app/main.py` 的路由清单）；
    - 唯一写入口是状态变更 / 归档 / 恢复这三条业务链路，且与业务字段修改
      （状态、deleted_at）**同事务提交**。

    ``old_status`` / ``new_status`` 用 ``Status`` 枚举：DDL 类型为 ``VARCHAR(13)``
    （与 ``event.status`` 完全一致），值域由 Pydantic 在写入前把关。
    归档动作的 old/new 相同（状态本身没变，靠 ``action`` 区分语义）。

    ``actor_id`` 是**用户名快照**：V0.4.2 及以前恒为 ``"local-dev"``；
    V0.5.3 起写入真实登录用户名，并同时写入可空外键 ``actor_user_id``
    （0006 迁移新增）。历史行**永不回填** —— 不能凭空把旧操作归属给新管理员。
    """

    __tablename__ = "status_history"

    id: int | None = Field(default=None, primary_key=True)
    event_id: int = Field(foreign_key="event.id", index=True)
    old_status: Status
    new_status: Status
    reason: str = Field(default="", max_length=1000)
    action: str = Field(default=ACTION_STATUS_CHANGE, max_length=50)
    actor_id: str = Field(default=LEGACY_ACTOR_ID, max_length=64)
    changed_at: datetime = Field(default_factory=utcnow)


class EventCreate(EventBase):
    # 未知字段（通常是拼写错误）直接拒绝，避免字段被静默忽略
    model_config = ConfigDict(extra="forbid")


class EventUpdate(SQLModel):
    # 同上：拼错字段名返回 422，而不是悄悄跳过
    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, min_length=3, max_length=100)
    severity: Severity | None = None
    status: Status | None = None
    description: str | None = Field(default=None, max_length=1000)
    # 状态变更的原因说明。它**不是 event 表的列**，只是 PATCH 请求里
    # 「本次变更为什么」的载体，会被写入 status_history.reason。
    # 因此在 update_event 里必须先把它从更新数据中取出，不能交给 sqlmodel_update。
    reason: str | None = Field(default=None, max_length=1000)

    @model_validator(mode="before")
    @classmethod
    def reject_explicit_null(cls, data):
        """区分「字段未提交」与「字段被显式设为 null」。

        未提交的字段保持原值（局部更新语义）；显式传 null 会导致
        sqlmodel_update 把 None 写入 NOT NULL 列，commit 时抛 IntegrityError
        变成 HTTP 500。这里提前拦截，统一返回 422。

        注意：这里遍历的是**整个提交体**，不枚举字段名，所以将来新增字段
        （如 status）会自动获得同样的 null 防护。
        """
        if isinstance(data, dict):
            null_fields = [name for name, value in data.items() if value is None]
            if null_fields:
                raise ValueError(
                    "字段 " + "、".join(null_fields)
                    + " 不能为 null；如需保持原值请省略该字段"
                )
        return data


class EventRead(EventBase):
    model_config = ConfigDict(from_attributes=True)
    id: int
    created_at: datetime


class StatusHistoryRead(SQLModel):
    """状态变更历史的只读响应模型（时间线数据来源）。"""

    model_config = ConfigDict(from_attributes=True)

    id: int
    event_id: int
    old_status: Status
    new_status: Status
    reason: str
    action: str
    actor_id: str
    changed_at: datetime


class ArchivedEventRead(EventRead):
    """归档中心使用的响应模型。

    比普通 ``EventRead`` 多一个 ``deleted_at``：归档列表需要展示归档时间，
    而普通列表不需要（普通列表里这一列恒为 NULL）。
    """

    deleted_at: datetime


class ArchivedEventCount(SQLModel):
    """归档事件总数。

    归档中心采用「分页加载」：单次请求至多拿到 ``limit`` 条，
    所以头部「共 N 条」里的 N 必须由数据库 ``COUNT(*)`` 给出，
    不能拿「已加载条数」去凑（那会把总数显示成当前页大小）。
    """

    total: int


#: 需要强制填写原因的状态转移（后端权威规则，前端只是体验层）。
#: 注意：这里**不包含** open → resolved —— 需求只要求 investigating → resolved
#: 与 resolved → open/investigating 两种情况填原因，多要求会破坏既有测试语义。
REASON_REQUIRED_FROM_INVESTIGATING = Status.resolved
REASON_REQUIRED_FROM_RESOLVED = (Status.open, Status.investigating)


def requires_status_reason(old: Status, new: Status) -> bool:
    """判断某个状态转移是否**强制要求**填写原因。

    - ``investigating → resolved``：必须有「解决原因」
    - ``resolved → open / investigating``：必须有「重新打开原因」
    - 其它方向（含状态未发生变化）：原因可选

    这是纯函数：给定 (旧状态, 新状态) 就有确定答案，便于单测覆盖，
    不依赖运行时上下文，也不靠前端自觉。
    """
    if old == new:
        return False
    if old == Status.investigating and new == REASON_REQUIRED_FROM_INVESTIGATING:
        return True
    if old == Status.resolved and new in REASON_REQUIRED_FROM_RESOLVED:
        return True
    return False


# ---------------------------------------------------------------------------
# 3) 账号与会话（V0.5）
# ---------------------------------------------------------------------------
class User(SQLModel, table=True):
    """平台账号。

    **表名是 `app_user` 而不是 `user`**：`user` 在 PostgreSQL / MySQL 里是保留字，
    而 PostgreSQL 是本项目的路线图目标。类名保持 `User` 以便阅读。

    设计要点：

    - 用户**只停用、不物理删除**（`is_active=False`）→ 审计外键永不悬挂；
    - `password_changed_at` 是「改密后旧会话立即失效」的兜底判据；
    - `failed_login_count` / `locked_until` 是账号级登录限流；
    - 新表一律**不写 `server_default`**（D8），默认值只由 Python 侧给出，
      避免 `create_all` 与迁移两条路径的 DDL 漂移。
    """

    __tablename__ = "app_user"

    id: int | None = Field(default=None, primary_key=True)
    #: 统一小写存储与比较；允许 [a-z0-9._-]{3,32}
    username: str = Field(max_length=32, unique=True, index=True)
    #: Argon2id 编码串（实测 97 字符，列宽留了 2.6 倍余量）
    password_hash: str = Field(max_length=255)
    role: Role = Field(default=Role.viewer)
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=utcnow)
    #: 早于该时刻创建的会话一律无效（改密 / 管理员重置后的兜底防线）
    password_changed_at: datetime = Field(default_factory=utcnow)
    last_login_at: datetime | None = Field(default=None)
    failed_login_count: int = Field(default=0)
    #: 非 NULL 且未过期时，即使密码正确也拒绝登录
    locked_until: datetime | None = Field(default=None)
    #: 仅用于 UI 展示，**不参与任何鉴权**
    display_name: str | None = Field(default=None, max_length=64)


class UserSession(SQLModel, table=True):
    """服务端会话（多设备各自一行）。

    - ``token_hash`` 存的是 SHA-256(令牌)，**明文令牌只在 Cookie 里**；
      这样即使数据库被拖走，也无法直接拿来冒用会话。
    - ``csrf_token`` 存在服务端：CSRF 校验是「双提交 + 服务端比对」，
      比纯双提交更强（不依赖"攻击者读不到 Cookie"这一假设）。
    """

    __tablename__ = "user_session"

    id: int | None = Field(default=None, primary_key=True)
    token_hash: str = Field(max_length=64, unique=True, index=True)
    user_id: int = Field(foreign_key="app_user.id", index=True)
    csrf_token: str = Field(max_length=64)
    created_at: datetime = Field(default_factory=utcnow)
    last_seen_at: datetime = Field(default_factory=utcnow)
    #: **绝对**过期时间
    expires_at: datetime = Field(default_factory=utcnow)
    revoked_at: datetime | None = Field(default=None)
    #: logout / password_change / admin_reset / deactivated / expired / rotated
    revoked_reason: str | None = Field(default=None, max_length=32)
    user_agent: str | None = Field(default=None, max_length=255)
    #: 信息性记录，**不参与鉴权决策**
    ip_address: str | None = Field(default=None, max_length=64)


# ---------------------------------------------------------------------------
# 4) 认证请求 / 响应 schema
# ---------------------------------------------------------------------------
class LoginRequest(SQLModel):
    """登录请求。

    - ``extra="forbid"``：与既有风格一致，拼错字段直接 422；
    - 密码用 ``SecretStr``：避免它被 repr / 日志 / 报错信息顺带打印出来；
    - 这里**不做**长度校验：长度策略在 `app/auth.py` 里显式实现
      （下限走 `security.validate_password_strength`，上限是防 DoS）。
      刻意不用 `Field(max_length=...)`：``SecretStr`` 是包装类型，
      对它施加长度约束在不同 pydantic 版本下行为不一致，
      宁可写成**可读、可测的显式判断**。
    """

    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=32)
    password: SecretStr


class UserRead(SQLModel):
    """对外暴露的账号信息。**绝不包含 `password_hash`。**"""

    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    role: Role
    display_name: str | None = None
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None = None


class PasswordChangeRequest(SQLModel):
    """改自己的密码（需要旧密码，防"会话被劫持后直接改密"）。

    长度上限同样在 `app/auth.py` 里显式校验（理由见 :class:`LoginRequest`）。
    """

    model_config = ConfigDict(extra="forbid")

    old_password: SecretStr
    new_password: SecretStr


class MessageResponse(SQLModel):
    """通用消息体（登出提示、改密成功等）。"""

    detail: str
