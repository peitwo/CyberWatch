"""CyberWatch V0.1: a learning-oriented security event API."""
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ConfigDict, model_validator
from sqlmodel import Field, Session, SQLModel, create_engine, select

from app.config import BASE_DIR, DATABASE_URL_ENV, resolve_database_url, sqlite_file_path

# 数据库 URL 由 app/config.py 统一解析（优先级：显式参数 > 环境变量 > 项目根绝对路径）。
# 这样做的目的：让「应用连接的库」与「Alembic 迁移的库」永远是同一个，
# 且默认路径基于项目根目录、不再随进程 cwd 漂移。
DATABASE_URL = resolve_database_url()
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})


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
        columns = [row[1] for row in connection.exec_driver_sql("PRAGMA table_info(event)")]

    if "status" not in columns:
        raise RuntimeError(
            "数据库结构不是最新：event 表缺少 status 列。\n"
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
    statement = select(Event)
    if severity:
        statement = statement.where(Event.severity == severity)
    if status:
        statement = statement.where(Event.status == status)
    statement = statement.order_by(Event.id.desc()).offset(offset).limit(limit)
    return session.exec(statement).all()


@app.get("/events/{event_id}", response_model=EventRead)
def get_event(event_id: int, session: SessionDep):
    event = session.get(Event, event_id)
    if event is None:
        raise HTTPException(404, "Event not found")
    return event


@app.patch("/events/{event_id}", response_model=EventRead)
def update_event(event_id: int, payload: EventUpdate, session: SessionDep):
    event = session.get(Event, event_id)
    if event is None:
        raise HTTPException(404, "Event not found")
    event.sqlmodel_update(payload.model_dump(exclude_unset=True))
    session.add(event)
    session.commit()
    session.refresh(event)
    return event


@app.delete("/events/{event_id}", status_code=204)
def delete_event(event_id: int, session: SessionDep):
    event = session.get(Event, event_id)
    if event is None:
        raise HTTPException(404, "Event not found")
    session.delete(event)
    session.commit()


app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
