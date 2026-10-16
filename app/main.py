"""CyberWatch V0.1: a learning-oriented security event API."""
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ConfigDict, model_validator
from sqlmodel import Field, Session, SQLModel, create_engine, func, select

from app.config import (
    BASE_DIR,
    DATABASE_URL_ENV,
    enable_sqlite_foreign_keys,
    resolve_database_url,
    sqlite_file_path,
)

# 数据库 URL 由 app/config.py 统一解析（优先级：显式参数 > 环境变量 > 项目根绝对路径）。
# 这样做的目的：让「应用连接的库」与「Alembic 迁移的库」永远是同一个，
# 且默认路径基于项目根目录、不再随进程 cwd 漂移。
DATABASE_URL = resolve_database_url()
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
# 让 status_history.event_id → event.id 的外键**真实生效**（SQLite 默认不校验外键）
enable_sqlite_foreign_keys(engine)

#: 审计动作类型。当前实现三种：状态变更 / 归档 / 恢复。
ACTION_STATUS_CHANGE = "status_change"
ACTION_ARCHIVE = "archive"
ACTION_RESTORE = "restore"

#: 操作主体（actor）的**开发环境占位身份**。
#: 未来接入账号系统后，这里改为从认证上下文（当前登录用户）读取，其余代码不变。
DEFAULT_ACTOR_ID = "local-dev"


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class Status(str, Enum):
    """安全事件的生命周期状态。三个值之间**可任意方向切换**（不实现状态机）。"""

    open = "open"
    investigating = "investigating"
    resolved = "resolved"


class EventBase(SQLModel):
    title: str = Field(min_length=3, max_length=100)
    severity: Severity = Severity.low
    # default 负责「应用新建事件默认 open」；server_default 负责「迁移时给已有行补 open」，
    # 并且让 create_all 建出的表与 Alembic 迁移出的表结构完全一致。
    status: Status = Field(default=Status.open, sa_column_kwargs={"server_default": "open"})
    description: str = Field(default="", max_length=1000)


class Event(EventBase, table=True):
    id: int | None = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    # 软删除 / 归档标记：NULL = 未归档（普通列表可见）；非 NULL = 已归档（值为归档时间 UTC）。
    # 采用软删除而不是物理删除，是为了让 status_history 的外键永远有效、审计记录永不丢失。
    deleted_at: datetime | None = Field(default=None, index=True)


class StatusHistory(SQLModel, table=True):
    """状态变更历史（只追加的审计日志）。

    每次「状态切换 / 归档 / 恢复」追加一行，**永不修改、永不删除**：

    - 应用层不提供任何修改或删除本表的接口（见文件末尾的路由清单）；
    - 唯一写入口是状态变更 / 归档 / 恢复这三条业务链路，且与业务字段修改
      （状态、deleted_at）**同事务提交**。

    ``old_status`` / ``new_status`` 用 ``Status`` 枚举：DDL 类型为 ``VARCHAR(13)``
    （与 ``event.status`` 完全一致），值域由 Pydantic 在写入前把关。
    归档动作的 old/new 相同（状态本身没变，靠 ``action`` 区分语义）。
    """

    __tablename__ = "status_history"

    id: int | None = Field(default=None, primary_key=True)
    event_id: int = Field(foreign_key="event.id", index=True)
    old_status: Status
    new_status: Status
    reason: str = Field(default="", max_length=1000)
    action: str = Field(default=ACTION_STATUS_CHANGE, max_length=50)
    actor_id: str = Field(default=DEFAULT_ACTOR_ID, max_length=64)
    changed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


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


def get_session():
    with Session(engine) as session:
        yield session


SessionDep = Annotated[Session, Depends(get_session)]


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 启动时只做**只读**结构检查，绝不修改数据库。
    # （结构变更的唯一入口是 Alembic：`alembic upgrade head`）
    ensure_schema_ready()
    yield


def ensure_schema_ready() -> None:
    """只读地确认数据库结构已是最新，否则给出中文操作指引。

    不使用 ``create_all``：它只能建"不存在的表"，永远无法给已有表加列，
    会与 Alembic 形成双轨（`create_all` 建的表不写 `alembic_version`，
    之后 `upgrade` 会因为"表已存在"而失败）。因此结构变更一律交给 Alembic。
    """
    db_file = sqlite_file_path(DATABASE_URL)
    if db_file is not None and not db_file.exists():
        # 先判断文件是否存在，避免连接动作顺手创建一个空库文件。
        raise RuntimeError(
            f"数据库文件不存在：{db_file}\n"
            "请先执行迁移创建结构：\n"
            "    alembic upgrade head\n"
            f"（如需改用其它数据库位置，请设置环境变量 {DATABASE_URL_ENV}）"
        )

    with engine.connect() as connection:
        event_columns = [
            row[1] for row in connection.exec_driver_sql("PRAGMA table_info(event)")
        ]
        history_tables = connection.exec_driver_sql(
            "select name from sqlite_master where type='table' and name='status_history'"
        ).fetchall()

    missing = []
    if "status" not in event_columns:
        missing.append("event.status")
    if "deleted_at" not in event_columns:
        missing.append("event.deleted_at")
    if not history_tables:
        missing.append("status_history 表")

    if missing:
        raise RuntimeError(
            "数据库结构不是最新，缺少：" + "、".join(missing) + "\n"
            f"当前数据库：{DATABASE_URL}\n"
            "请先执行迁移：\n"
            "    alembic upgrade head"
        )


app = FastAPI(title="CyberWatch", version="0.1.0", lifespan=lifespan)


@app.get("/")
def home():
    return {"app": "CyberWatch", "version": "0.1.0", "docs": "/docs", "dashboard": "/dashboard"}


@app.get("/dashboard")
def dashboard():
    return FileResponse(BASE_DIR / "templates" / "dashboard.html")


@app.post("/events", response_model=EventRead, status_code=201)
def create_event(payload: EventCreate, session: SessionDep):
    event = Event.model_validate(payload)
    session.add(event)
    session.commit()
    session.refresh(event)
    return event


@app.get("/events", response_model=list[EventRead])
def list_events(session: SessionDep, severity: Severity | None = None,
                status: Status | None = None,
                offset: int = Query(default=0, ge=0), limit: int = Query(default=20, ge=1, le=100)):
    # 每个筛选条件都用链式 .where() 追加，条件之间自动是 AND。
    # 注意：不要写成「重新 select(Event) 再 where」，那样后一个筛选会覆盖前一个。
    # 默认只看未归档事件：已归档事件从普通列表隐藏（归档中心是未来的独立入口）。
    statement = select(Event).where(Event.deleted_at.is_(None))
    if severity:
        statement = statement.where(Event.severity == severity)
    if status:
        statement = statement.where(Event.status == status)
    statement = statement.order_by(Event.id.desc()).offset(offset).limit(limit)
    return session.exec(statement).all()


# 注意路由顺序：本路由**必须**声明在 `GET /events/{event_id}` 之前。
# FastAPI 按声明顺序匹配，若放在其后，"archived" 会被当成 event_id 去解析成 int，
# 直接返回 422 —— 归档中心的入口就会「莫名其妙打不开」。
@app.get("/events/archived", response_model=list[ArchivedEventRead])
def list_archived_events(
    session: SessionDep,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=100),
):
    """归档中心：返回 ``deleted_at`` 非空的事件（最近归档的排在前面）。

    这是**只读**视图。归档事件对普通接口不可见（``GET /events`` 隐藏、
    ``GET /events/{id}`` 404、``PATCH`` 409），但在这里可以查看，
    并且它的时间线仍可通过 ``GET /events/{id}/history`` 读取。
    """
    statement = (
        select(Event)
        .where(Event.deleted_at.is_not(None))
        .order_by(Event.deleted_at.desc(), Event.id.desc())
        .offset(offset)
        .limit(limit)
    )
    return session.exec(statement).all()


@app.get("/events/archived/count", response_model=ArchivedEventCount)
def count_archived_events(session: SessionDep):
    """归档事件的**准确**总数（归档中心头部「共 N 条」的数据来源）。

    与 ``GET /events/archived`` 同源：条件都是 ``deleted_at IS NOT NULL``，
    因此列表与计数永远不会互相矛盾。分页只影响「当前显示 M 条」，
    不影响这里返回的 N。

    注意路由顺序：本路由**必须**声明在 ``GET /events/{event_id}`` 之前，
    否则 "archived" 会被当成 event_id 解析成 int → 422。
    """
    statement = (
        select(func.count())
        .select_from(Event)
        .where(Event.deleted_at.is_not(None))
    )
    return ArchivedEventCount(total=session.exec(statement).one())


@app.get("/events/{event_id}", response_model=EventRead)
def get_event(event_id: int, session: SessionDep):
    event = session.get(Event, event_id)
    # 已归档事件对普通接口「不存在」：返回 404，未来通过专用归档接口查看。
    # 注意：数据与历史都完整保留在库里，这里只是**可见性**上的隐藏。
    if event is None or event.deleted_at is not None:
        raise HTTPException(404, "Event not found")
    return event


@app.get("/events/{event_id}/history", response_model=list[StatusHistoryRead])
def list_event_history(event_id: int, session: SessionDep):
    """返回某个事件的完整状态变更时间线（按时间升序，从旧到新）。

    这是**只读**接口。系统不提供任何「修改 / 删除历史」的路由，
    因此审计记录在应用层是只追加、不可篡改的。
    已归档事件的历史同样可读（审计数据要能长期复查）。
    """
    event = session.get(Event, event_id)
    if event is None:
        raise HTTPException(404, "Event not found")
    statement = (
        select(StatusHistory)
        .where(StatusHistory.event_id == event_id)
        .order_by(StatusHistory.changed_at, StatusHistory.id)
    )
    return session.exec(statement).all()


@app.patch("/events/{event_id}", response_model=EventRead)
def update_event(event_id: int, payload: EventUpdate, session: SessionDep):
    event = session.get(Event, event_id)
    if event is None:
        raise HTTPException(404, "Event not found")
    # 已归档事件不允许通过普通接口修改（前端隐藏按钮不算数，这里才是真正的闸门）。
    if event.deleted_at is not None:
        raise HTTPException(409, "事件已归档，不能修改；如需继续处理请先恢复该事件")

    data = payload.model_dump(exclude_unset=True)
    # reason 不是 event 的列，必须在交给 sqlmodel_update 之前取出，
    # 否则会试图给 Event 设置一个不存在的属性。
    reason = data.pop("reason", None)
    new_status = data.get("status")

    history: StatusHistory | None = None
    if new_status is not None and new_status != event.status:
        old_status = event.status
        # 后端权威校验：前端弹窗只是体验层，直接调 API 也必须被拦下。
        if requires_status_reason(old_status, new_status) and not (reason or "").strip():
            raise HTTPException(
                422,
                f"{old_status.value} → {new_status.value} 必须填写原因"
                "（解决原因 / 重新打开原因）",
            )
        history = StatusHistory(
            event_id=event.id,
            old_status=old_status,
            new_status=new_status,
            reason=(reason or "").strip(),
            action=ACTION_STATUS_CHANGE,
            actor_id=DEFAULT_ACTOR_ID,
        )

    event.sqlmodel_update(data)
    session.add(event)
    if history is not None:
        session.add(history)
    # 状态修改与审计写入在**同一个事务**里一次提交：
    # 只要中途抛异常，两者一起回滚，不会出现「状态改了但历史没了」的半截状态。
    session.commit()
    session.refresh(event)
    return event


@app.delete("/events/{event_id}", status_code=204)
def delete_event(event_id: int, session: SessionDep):
    """归档事件（软删除）。

    不再物理删除数据行：只把 ``deleted_at`` 置为当前时间，事件本体与它的
    全部历史记录都保留在库中。这样既保住了审计证据，也让
    ``status_history.event_id`` 的外键始终有效。
    """
    event = session.get(Event, event_id)
    if event is None or event.deleted_at is not None:
        raise HTTPException(404, "Event not found")

    event.deleted_at = datetime.now(timezone.utc)
    session.add(event)
    # 归档本身也写入审计：状态没变（old == new），靠 action 区分「归档」语义。
    session.add(
        StatusHistory(
            event_id=event.id,
            old_status=event.status,
            new_status=event.status,
            reason="",
            action=ACTION_ARCHIVE,
            actor_id=DEFAULT_ACTOR_ID,
        )
    )
    # 归档标记与审计记录同一事务提交，避免「事件归档了但没留下归档记录」。
    session.commit()


@app.post("/events/{event_id}/restore", response_model=EventRead)
def restore_event(event_id: int, session: SessionDep):
    """恢复（取消归档）一个已归档事件。

    设计要点：

    - 只把 ``deleted_at`` 置回 NULL，**不改动** ``status`` / ``severity`` /
      ``created_at`` —— 恢复是「让它重新可见」，不是「重置它」；
    - 写入一条 ``action="restore"`` 的审计记录（old == new，靠 action 区分语义）；
    - 两步在**同一事务**一次提交，中途失败则一起回滚，
      不会出现「恢复了但没留痕」或「留痕了但没恢复」的半截状态；
    - 事件不存在 → 404；事件当前**未**处于归档状态（含重复恢复）→ 409。
    """
    event = session.get(Event, event_id)
    if event is None:
        raise HTTPException(404, "Event not found")
    if event.deleted_at is None:
        raise HTTPException(409, "事件未处于归档状态，无需恢复")

    event.deleted_at = None
    session.add(event)
    session.add(
        StatusHistory(
            event_id=event.id,
            old_status=event.status,
            new_status=event.status,
            reason="",
            action=ACTION_RESTORE,
            actor_id=DEFAULT_ACTOR_ID,
        )
    )
    session.commit()
    session.refresh(event)
    return event


app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
