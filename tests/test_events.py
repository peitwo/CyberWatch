"""Isolated CyberWatch API tests using a temporary SQLite database."""
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine

from app.main import app, get_session


@pytest.fixture
def client():
    """Provide a test client backed by a temporary database, never the app DB."""
    with TemporaryDirectory() as temp:
        db = Path(temp) / "test.db"
        test_engine = create_engine(
            f"sqlite:///{db}", connect_args={"check_same_thread": False}
        )
        SQLModel.metadata.create_all(test_engine)

        def override_session():
            with Session(test_engine) as session:
                yield session

        app.dependency_overrides[get_session] = override_session
        try:
            # Do not enter TestClient's context manager: it would run the
            # application's lifespan, which initializes the main database.
            with closing(TestClient(app)) as test_client:
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
