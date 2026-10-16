"""CyberWatch 应用入口：组装依赖、声明业务路由、挂载静态资源。

V0.5 的结构调整（评审意见 R1-1）：

- **模型全部迁到 `app/models.py`**，本模块只做 **re-export**（保持既有
  `from app.main import Event` 这类导入路径继续可用）；
- **引擎与会话迁到 `app/database.py`**（切断 `main ↔ auth` 的循环导入）；
- **认证/会话/CSRF 在 `app/auth.py`**，权限矩阵在 `app/permissions.py`；
- 本模块的职责收敛为：**组装 + 路由**。既有路由的**函数体一字未改**，
  只在其装饰器上增加了 `dependencies=[Depends(require(...))]`。

依赖方向（严格单向）：config → database → models → permissions → auth → main
"""
from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlmodel import Session, func, select

# ---------------------------------------------------------------------------
# 0) 兼容性 re-export（**不是可选**，见设计文档 §2.0）
#    tests/conftest.py、test_config.py、test_migrations.py、test_restore.py、
#    test_status_history.py 都按 `app.main.X` 取名字。保留这些名字，
#    换来的是它们**零改动**。
# ---------------------------------------------------------------------------
from app.config import (  # noqa: F401  兼容性 re-export
    BASE_DIR,
    DATABASE_URL_ENV,
    enable_sqlite_foreign_keys,
    resolve_database_url,
    sqlite_file_path,
)
from app.database import (  # noqa: F401  兼容性 re-export
    DATABASE_URL,
    SessionDep,
    engine,
    get_session,
)
from app.models import (  # noqa: F401  兼容性 re-export
    ACTION_ARCHIVE,
    ACTION_RESTORE,
    ACTION_STATUS_CHANGE,
    DEFAULT_ACTOR_ID,
    LEGACY_ACTOR_ID,
    SYSTEM_ACTOR_ID,
    ArchivedEventCount,
    ArchivedEventRead,
    Event,
    EventBase,
    EventCreate,
    EventRead,
    EventUpdate,
    Role,
    Severity,
    Status,
    StatusHistory,
    StatusHistoryRead,
    User,
    UserSession,
    requires_status_reason,
    utcnow,
)
from app.auth import (  # noqa: F401  兼容性 re-export
    AUTH_SETTINGS,
    auth_router,
    require,
    require_html_session,
    require_role,
)
from app.permissions import Permission


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 启动时只做**只读**结构检查，绝不修改数据库。
    # （结构变更的唯一入口是 Alembic：`alembic upgrade head`）
    ensure_schema_ready()
    report_configuration()
    yield


def report_configuration() -> None:
    """打印生效配置与安全警告。**绝不含任何密钥或密码。**"""
    print(f"[CyberWatch] 生效配置：{AUTH_SETTINGS.describe()}", file=sys.stderr)
    print(
        f"[CyberWatch] 数据库：{DATABASE_URL}",
        file=sys.stderr,
    )
    for warning in AUTH_SETTINGS.warnings:
        print(f"[CyberWatch] ⚠️  {warning}", file=sys.stderr)


def ensure_schema_ready() -> None:
    """只读地确认数据库结构已是最新，否则给出中文操作指引。

    不使用 ``create_all``：它只能建"不存在的表"，永远无法给已有表加列，
    会与 Alembic 形成双轨（``create_all`` 建的表不写 ``alembic_version``，
    之后 ``upgrade`` 会因为"表已存在"而失败）。因此结构变更一律交给 Alembic。
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
        existing_tables = {
            row[0]
            for row in connection.exec_driver_sql(
                "select name from sqlite_master where type='table'"
            )
        }

    missing = []
    if "status" not in event_columns:
        missing.append("event.status")
    if "deleted_at" not in event_columns:
        missing.append("event.deleted_at")
    if "status_history" not in existing_tables:
        missing.append("status_history 表")
    # V0.5：认证需要两张新表
    if "app_user" not in existing_tables:
        missing.append("app_user 表")
    if "user_session" not in existing_tables:
        missing.append("user_session 表")

    if missing:
        raise RuntimeError(
            "数据库结构不是最新，缺少：" + "、".join(missing) + "\n"
            f"当前数据库：{DATABASE_URL}\n"
            "请先执行迁移：\n"
            "    alembic upgrade head"
        )


# `docs_url` / `redoc_url` / `openapi_url` 一律设为 None（关掉内置文档路由），
# 改由本模块**自己注册**，这样才能按 `docs_mode` 三态施加不同的访问策略。
app = FastAPI(
    title="CyberWatch",
    version="0.5.1",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.include_router(auth_router)


# ---------------------------------------------------------------------------
# 1) 公开路由（例外 E4：不含任何业务数据）
# ---------------------------------------------------------------------------
@app.get("/")
def home():
    return {"app": "CyberWatch", "version": "0.5.1", "docs": "/docs", "login": "/login"}


@app.get("/healthz")
def healthz():
    """探针端点。**刻意只返回一个字段**：不含版本、库路径、用户数，
    避免它变成信息泄露面。"""
    return {"status": "ok"}


def no_store(response: FileResponse) -> FileResponse:
    """给**认证后**才可见的 HTML 加上 ``Cache-Control: no-store``。

    为什么必须显式加：``FileResponse`` 会带上 `etag` / `last-modified`，
    而没有 `Cache-Control` 时浏览器可以自行判断"内容没变，直接用缓存"。
    于是会出现一个很隐蔽的现象 —— 用户退出登录后重新访问 ``/dashboard``，
    Chrome 直接拿缓存渲染出 dashboard 骨架，**根本没有再问服务器**。
    页面上随后发出的 API 请求会 401 并跳回登录页，所以最终结果是对的，
    但"一个无会话的浏览器渲染出已认证页面"这件事本身不该发生。

    这是真实浏览器验收（`tools/browser_acceptance.js`）发现的问题，
    单靠 TestClient 永远看不到 —— 它不实现 HTTP 缓存。
    """
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/login")
def login_page():
    """登录页（HTML）。必须在未登录时可访问，否则永远登不进去。"""
    # 登录页本身不含机密，但它带 `?next=` 参数，缓存住会让人以为"登录后去哪"
    # 是固定的；一并 no-store，代价可忽略（1.7 KB 的静态文件）。
    return no_store(FileResponse(BASE_DIR / "templates" / "login.html"))


@app.get("/dashboard", dependencies=[Depends(require_html_session())])
def dashboard():
    """Dashboard（HTML）。未登录 → 302 → `/login?next=/dashboard`。"""
    return no_store(FileResponse(BASE_DIR / "templates" / "dashboard.html"))


# ---------------------------------------------------------------------------
# 2) 文档路由（`docs_mode` 三态：admin / public / disabled）
# ---------------------------------------------------------------------------
if AUTH_SETTINGS.docs_mode == "admin":
    _docs_guard = [Depends(require_role(Role.admin, html=True))]
    _openapi_guard = [Depends(require_role(Role.admin))]
elif AUTH_SETTINGS.docs_mode == "public":
    _docs_guard = []
    _openapi_guard = []
else:  # disabled
    _docs_guard = None
    _openapi_guard = None

if _docs_guard is not None:

    @app.get("/openapi.json", include_in_schema=False, dependencies=_openapi_guard)
    def openapi_schema():
        return JSONResponse(app.openapi())

    @app.get("/docs", include_in_schema=False, dependencies=_docs_guard)
    def swagger_ui():
        return get_swagger_ui_html(openapi_url="/openapi.json", title="CyberWatch API 文档")

    @app.get("/redoc", include_in_schema=False, dependencies=_docs_guard)
    def redoc_ui():
        return get_redoc_html(openapi_url="/openapi.json", title="CyberWatch API 文档")


# ---------------------------------------------------------------------------
# 3) 安全事件（**全部业务 API 必须认证**，V0.5.1 覆盖清单见 permissions.V051_PROTECTED_ROUTES）
# ---------------------------------------------------------------------------
@app.post(
    "/events",
    response_model=EventRead,
    status_code=201,
    dependencies=[Depends(require(Permission.EVENT_CREATE))],
)
def create_event(payload: EventCreate, session: SessionDep):
    event = Event.model_validate(payload)
    session.add(event)
    session.commit()
    session.refresh(event)
    return event


@app.get(
    "/events",
    response_model=list[EventRead],
    dependencies=[Depends(require(Permission.EVENT_READ))],
)
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
@app.get(
    "/events/archived",
    response_model=list[ArchivedEventRead],
    dependencies=[Depends(require(Permission.EVENT_READ))],
)
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


@app.get(
    "/events/archived/count",
    response_model=ArchivedEventCount,
    dependencies=[Depends(require(Permission.EVENT_READ))],
)
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


@app.get(
    "/events/{event_id}",
    response_model=EventRead,
    dependencies=[Depends(require(Permission.EVENT_READ))],
)
def get_event(event_id: int, session: SessionDep):
    event = session.get(Event, event_id)
    # 已归档事件对普通接口「不存在」：返回 404，未来通过专用归档接口查看。
    # 注意：数据与历史都完整保留在库里，这里只是**可见性**上的隐藏。
    if event is None or event.deleted_at is not None:
        raise HTTPException(404, "Event not found")
    return event


@app.get(
    "/events/{event_id}/history",
    response_model=list[StatusHistoryRead],
    dependencies=[Depends(require(Permission.AUDIT_READ))],
)
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


@app.patch(
    "/events/{event_id}",
    response_model=EventRead,
    dependencies=[Depends(require(Permission.EVENT_UPDATE))],
)
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


@app.delete(
    "/events/{event_id}",
    status_code=204,
    dependencies=[Depends(require(Permission.EVENT_ARCHIVE))],
)
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


@app.post(
    "/events/{event_id}/restore",
    response_model=EventRead,
    dependencies=[Depends(require(Permission.EVENT_RESTORE))],
)
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
