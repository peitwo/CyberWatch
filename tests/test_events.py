"""Isolated CyberWatch API tests using a temporary SQLite database."""
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine

from app.config import enable_sqlite_foreign_keys
from app.main import app, get_session

# 从 conftest 复用测试账号与真实登录助手（conftest 由 pytest 先于本模块导入）
from conftest import ADMIN_USERNAME, login, seed_accounts


@pytest.fixture
def client():
    """Provide a test client backed by a temporary database, never the app DB.

    V0.5（R1-8 批准的**唯一**改动）：本文件自带夹具，所以必须自己完成两件事：

    1. 与 ``conftest`` 一致地开启 ``PRAGMA foreign_keys=ON``
       （原夹具漏了这一步，测试里的外键其实没被强制）；
    2. 播种一个管理员并走**真实** ``POST /auth/login`` 登录，
       这样下面 16 条既有用例的**断言与请求体一字不改**，
       却全部运行在真实认证链路上（而不是靠 ``dependency_overrides`` 绕过）。
    """
    with TemporaryDirectory() as temp:
        db = Path(temp) / "test.db"
        test_engine = create_engine(
            f"sqlite:///{db}", connect_args={"check_same_thread": False}
        )
        enable_sqlite_foreign_keys(test_engine)
        SQLModel.metadata.create_all(test_engine)
        seed_accounts(test_engine, (ADMIN_USERNAME,))

        def override_session():
            with Session(test_engine) as session:
                yield session

        app.dependency_overrides[get_session] = override_session
        try:
            # Do not enter TestClient's context manager: it would run the
            # application's lifespan, which initializes the main database.
            with closing(TestClient(app)) as test_client:
                login(test_client)
                yield test_client
        finally:
            app.dependency_overrides.pop(get_session, None)
            # Dispose the SQLite connection pool *before* TemporaryDirectory
            # removes test.db. Windows otherwise raises WinError 32.
            test_engine.dispose()


def create_event(client, title="Failed login attempts", severity="low",
                 description="来自 10.0.0.8 的连续失败登录"):
    """创建一条事件并返回其 JSON，供编辑 / 删除用例复用。"""
    response = client.post(
        "/events",
        json={"title": title, "severity": severity, "description": description},
    )
    assert response.status_code == 201, response.text
    return response.json()


# --------------------------------------------------------------------------
# V0.2 已有行为：创建 / 查询 / 筛选 / 校验
# --------------------------------------------------------------------------
def test_event_lifecycle(client):
    created = client.post(
        "/events", json={"title": "Failed login attempts", "severity": "high"}
    )
    assert created.status_code == 201, created.text
    event_id = created.json()["id"]
    assert client.get(f"/events/{event_id}").status_code == 200
    assert len(client.get("/events", params={"severity": "high"}).json()) == 1
    updated = client.patch(f"/events/{event_id}", json={"severity": "medium"})
    assert updated.status_code == 200, updated.text
    assert updated.json()["severity"] == "medium"
    assert client.delete(f"/events/{event_id}").status_code == 204
    assert client.get(f"/events/{event_id}").status_code == 404


def test_validation(client):
    response = client.post("/events", json={"title": "a", "severity": "critical"})
    assert response.status_code == 422


# --------------------------------------------------------------------------
# V0.3 编辑：局部更新语义 + 空值 / 未知字段防护
# --------------------------------------------------------------------------
def test_update_all_fields(client):
    """三个字段一起改：全部生效，且 id / created_at 不被改写。"""
    original = create_event(client)
    response = client.patch(
        f"/events/{original['id']}",
        json={
            "title": "Suspicious outbound traffic",
            "severity": "high",
            "description": "检测到异常外连",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["title"] == "Suspicious outbound traffic"
    assert body["severity"] == "high"
    assert body["description"] == "检测到异常外连"
    assert body["id"] == original["id"]
    assert body["created_at"] == original["created_at"]


def test_update_partial_keeps_other_fields(client):
    """只提交 severity 时，未提交字段必须保持原值（局部更新语义）。"""
    original = create_event(client)
    response = client.patch(f"/events/{original['id']}", json={"severity": "high"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["severity"] == "high"
    assert body["title"] == original["title"]
    assert body["description"] == original["description"]
    # 落库后再次读取，确认不是只改了响应
    stored = client.get(f"/events/{original['id']}").json()
    assert stored["title"] == original["title"]
    assert stored["description"] == original["description"]


def test_update_empty_payload_keeps_record(client):
    """空对象不修改任何字段，也不报错。"""
    original = create_event(client)
    response = client.patch(f"/events/{original['id']}", json={})
    assert response.status_code == 200, response.text
    assert response.json() == original


def test_update_rejects_invalid_title(client):
    """标题过短仍应被字段校验拦下（422）。"""
    original = create_event(client)
    response = client.patch(f"/events/{original['id']}", json={"title": "ab"})
    assert response.status_code == 422, response.text


@pytest.mark.parametrize("field", ["title", "severity", "description"])
def test_update_rejects_explicit_null(client, field):
    """显式传 null 必须返回 422，而不是 500（NOT NULL 约束报错）。"""
    original = create_event(client)
    response = client.patch(f"/events/{original['id']}", json={field: None})
    assert response.status_code == 422, response.text
    # 被拒绝的请求不得改动数据
    assert client.get(f"/events/{original['id']}").json() == original


def test_update_rejects_unknown_field(client):
    """拼错字段名必须返回 422，不能被静默忽略。"""
    original = create_event(client)
    response = client.patch(f"/events/{original['id']}", json={"titel": "typo"})
    assert response.status_code == 422, response.text
    assert client.get(f"/events/{original['id']}").json() == original


def test_create_rejects_unknown_field(client):
    """创建接口同样拒绝未知字段，保证两端行为一致。"""
    response = client.post(
        "/events", json={"title": "typo probe", "severty": "high"}
    )
    assert response.status_code == 422, response.text
    assert client.get("/events").json() == []


def test_update_missing_event_returns_404(client):
    response = client.patch("/events/999999", json={"title": "no such event"})
    assert response.status_code == 404, response.text


def test_get_missing_event_returns_404(client):
    assert client.get("/events/999999").status_code == 404


# --------------------------------------------------------------------------
# V0.3 删除
# --------------------------------------------------------------------------
def test_delete_removes_only_target(client):
    """删除只影响目标记录，同库其他事件必须保留。"""
    keeper = create_event(client, title="keep this event")
    doomed = create_event(client, title="delete this event")

    response = client.delete(f"/events/{doomed['id']}")
    assert response.status_code == 204, response.text
    assert response.content == b""

    assert client.get(f"/events/{doomed['id']}").status_code == 404
    remaining = client.get("/events").json()
    assert [item["id"] for item in remaining] == [keeper["id"]]
    assert remaining[0]["title"] == "keep this event"


def test_delete_missing_event_returns_404(client):
    response = client.delete("/events/999999")
    assert response.status_code == 404, response.text


def test_delete_twice_returns_404(client):
    """重复删除同一条：第二次必须是 404，而不是 204 或 500。"""
    event = create_event(client)
    assert client.delete(f"/events/{event['id']}").status_code == 204
    assert client.delete(f"/events/{event['id']}").status_code == 404


# --------------------------------------------------------------------------
# V0.5.1 新增（R1-8）：匿名用户与低权限用户
#   上面 16 条断言一字未改；这里只**新增**，用于证明"前端隐藏按钮 ≠ 权限"，
#   真正的闸门是后端 require() 依赖。
# --------------------------------------------------------------------------
def test_anonymous_cannot_read_or_write(anon_client):
    """未认证：JSON API 一律 401，HTML 页面 302 跳登录（且带 next）。"""
    assert anon_client.get("/events").status_code == 401
    assert anon_client.get("/events/archived").status_code == 401
    assert anon_client.get("/events/archived/count").status_code == 401
    assert anon_client.get("/events/1").status_code == 401
    assert anon_client.get("/events/1/history").status_code == 401
    assert anon_client.get("/auth/me").status_code == 401
    assert (
        anon_client.post("/events", json={"title": "匿名写入", "severity": "low"}).status_code
        == 401
    )
    assert anon_client.patch("/events/1", json={"severity": "high"}).status_code == 401
    assert anon_client.delete("/events/1").status_code == 401
    assert anon_client.post("/events/1/restore").status_code == 401

    # 每个 401 都必须带机器可读的信号，前端才能区分"该跳登录"与"权限不足"
    assert anon_client.get("/events").headers.get("WWW-Authenticate") == "Cookie"

    redirect = anon_client.get("/dashboard", follow_redirects=False)
    assert redirect.status_code == 302
    assert redirect.headers["location"].startswith("/login?next=")
    assert "/dashboard" in redirect.headers["location"]

    # 公开端点不受影响
    assert anon_client.get("/").status_code == 200
    assert anon_client.get("/login").status_code == 200
    assert anon_client.get("/healthz").json() == {"status": "ok"}


@pytest.mark.parametrize(
    "method,path_template,payload",
    [
        ("post", "/events", {"title": "viewer 越权新建", "severity": "low"}),
        ("patch", "/events/{event_id}", {"severity": "high"}),
        ("delete", "/events/{event_id}", None),
    ],
)
def test_viewer_cannot_write_events(make_client, method, path_template, payload):
    """只读角色**绕过前端**直接调 API 也必须被拦成 403（不是 401、也不是 200）。

    这里用的是真实登录出来的 viewer 会话（独立 Cookie 罐），
    没有任何 dependency_overrides 参与 —— 结论来自真实权限链路。
    """
    admin = make_client("admin")
    viewer = make_client("viewer")

    event = admin.post(
        "/events", json={"title": "viewer 越权目标", "severity": "low"}
    ).json()
    path = path_template.format(event_id=event["id"])

    response = (
        getattr(viewer, method)(path, json=payload)
        if payload is not None
        else getattr(viewer, method)(path)
    )
    assert response.status_code == 403, (method, path, response.status_code, response.text)
    assert "权限不足" in response.json()["detail"]

    # 被拒绝的越权请求不得改动任何数据
    assert admin.get(f"/events/{event['id']}").json() == event


def test_viewer_cannot_restore_archived_event(make_client):
    """viewer 连"恢复"也不允许（归档中心里的恢复按钮对它是隐藏的，后端也要拦）。"""
    admin = make_client("admin")
    viewer = make_client("viewer")
    event = admin.post("/events", json={"title": "待归档事件", "severity": "low"}).json()
    assert admin.delete(f"/events/{event['id']}").status_code == 204

    response = viewer.post(f"/events/{event['id']}/restore")
    assert response.status_code == 403, response.text

    # 事件仍处于归档状态，没有被越权恢复
    archived = [row["id"] for row in admin.get("/events/archived").json()]
    assert event["id"] in archived
    assert event["id"] not in [row["id"] for row in admin.get("/events").json()]


def test_viewer_can_still_read_everything_readable(make_client):
    """反向确认：403 不是"什么都拦"——viewer 的全部只读能力必须完好。"""
    admin = make_client("admin")
    viewer = make_client("viewer")
    event = admin.post("/events", json={"title": "只读可见事件", "severity": "low"}).json()

    assert viewer.get("/events").status_code == 200
    assert viewer.get(f"/events/{event['id']}").status_code == 200
    assert viewer.get(f"/events/{event['id']}/history").status_code == 200
    assert viewer.get("/events/archived").status_code == 200
    assert viewer.get("/events/archived/count").status_code == 200
    assert viewer.get("/auth/me").json()["role"] == "viewer"


def test_write_without_csrf_header_is_403(make_client):
    """已登录但**不带** CSRF 头的写请求必须 403 —— 这是 CSRF 防护的硬断言。"""
    admin = make_client("admin")
    bare = make_client("admin", csrf=False)

    # 先确认这个"裸"客户端确实已登录（否则 403 可能来自"未认证"这个别的原因）
    assert bare.get("/auth/me").status_code == 200
    assert "cw_session" in bare.cookies

    event = admin.post("/events", json={"title": "CSRF 目标", "severity": "low"}).json()
    assert bare.post("/events", json={"title": "无 CSRF", "severity": "low"}).status_code == 403
    assert bare.patch(f"/events/{event['id']}", json={"severity": "high"}).status_code == 403
    assert bare.delete(f"/events/{event['id']}").status_code == 403
    assert bare.post(f"/events/{event['id']}/restore").status_code == 403
    # 读方法不需要 CSRF
    assert bare.get("/events").status_code == 200
