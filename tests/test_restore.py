"""V0.4.2 补充：归档中心（查询已归档事件）与恢复（restore）。

覆盖任务一的需求：
1. 查询已归档事件的 API（返回 deleted_at 非空的事件）
2. 恢复事件 API（POST /events/{id}/restore）
3. 恢复时 deleted_at 置 NULL，保留 status / severity / created_at
4. 恢复操作写入 action="restore" 的历史记录
5. deleted_at 更新与恢复审计写入处于**同一事务**
6. 重复恢复返回明确错误（409）
7. 普通列表继续隐藏归档事件
8. 已归档事件仍禁止通过普通 PATCH 修改

安全约定：全部用例使用 conftest 提供的临时库 fixture，
**绝不连接**项目里的真实 ``cyberwatch.db``。
"""
from __future__ import annotations

import pytest
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from app import main
from app.main import Status


# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------
def make_event(client, **overrides):
    payload = {
        "title": "Suspicious Login Attempt",
        "severity": "low",
        "description": "同一账号 5 分钟内失败登录 12 次",
    }
    payload.update(overrides)
    response = client.post("/events", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def archive(client, event_id: int):
    response = client.delete(f"/events/{event_id}")
    assert response.status_code == 204, response.text
    return response


def history_of(engine, event_id: int):
    """直接查库拿审计行（比只看接口响应更能证明数据真的落盘）。"""
    with Session(engine) as session:
        statement = (
            select(main.StatusHistory)
            .where(main.StatusHistory.event_id == event_id)
            .order_by(main.StatusHistory.id)
        )
        return list(session.exec(statement).all())


def event_row(engine, event_id: int) -> main.Event | None:
    with Session(engine) as session:
        return session.get(main.Event, event_id)


# ---------------------------------------------------------------------------
# 1) 归档列表 API
# ---------------------------------------------------------------------------
def test_archived_list_is_empty_initially(client):
    assert client.get("/events/archived").status_code == 200
    assert client.get("/events/archived").json() == []


def test_archived_list_route_is_not_shadowed_by_event_id_path(client):
    """关键守卫：/events/archived 的动态路由顺序。

    若 ``GET /events/{event_id}`` 声明在 ``GET /events/archived`` 之前，
    FastAPI 会先把 "archived" 当成 event_id 去解析 int → 422。
    这条用例专门钉住路由顺序，防止以后重排路由时静默回归。
    """
    response = client.get("/events/archived")
    assert response.status_code == 200, response.text
    assert isinstance(response.json(), list)


def test_archived_list_returns_only_archived_events(client):
    keeper = make_event(client, title="Keep me active")
    gone = make_event(client, title="Archive me")
    archive(client, gone["id"])

    body = client.get("/events/archived").json()
    assert [item["id"] for item in body] == [gone["id"]]
    # 普通列表继续隐藏归档事件（需求 7）
    assert [item["id"] for item in client.get("/events").json()] == [keeper["id"]]


def test_archived_list_exposes_deleted_at(client):
    event = make_event(client, title="Archive me")
    archive(client, event["id"])

    row = client.get("/events/archived").json()[0]
    assert row["id"] == event["id"]
    assert row["deleted_at"] is not None
    # 归档不改动业务字段
    assert row["status"] == event["status"]
    assert row["severity"] == event["severity"]
    assert row["created_at"] == event["created_at"]


def test_archived_list_is_a_read_only_view(client):
    """归档列表只是「查询视图」：不能借此绕过归档事件不可改的闸门。"""
    event = make_event(client)
    archive(client, event["id"])

    body = client.get("/events/archived").json()
    assert [item["id"] for item in body] == [event["id"]]

    # 常规修改依然被拒
    assert client.patch(f"/events/{event['id']}", json={"title": "偷偷改"}).status_code == 409
    # 归档中心看到的事件详情（历史）仍可读
    assert client.get(f"/events/{event['id']}/history").status_code == 200


# ---------------------------------------------------------------------------
# 2) 恢复 API
# ---------------------------------------------------------------------------
def test_restore_clears_deleted_at(client, client_and_engine):
    _, engine = client_and_engine
    event = make_event(client, title="Restore me")
    archive(client, event["id"])

    response = client.post(f"/events/{event['id']}/restore")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["id"] == event["id"]

    row = event_row(engine, event["id"])
    assert row is not None
    assert row.deleted_at is None


def test_restore_keeps_status_severity_created_at(client):
    """需求 3：只清除 deleted_at，业务字段一律不动。"""
    event = make_event(client, title="Keep my fields", severity="high", status="investigating")
    archive(client, event["id"])

    restored = client.post(f"/events/{event['id']}/restore").json()
    assert restored["status"] == "investigating"
    assert restored["severity"] == "high"
    assert restored["created_at"] == event["created_at"]
    assert restored["title"] == "Keep my fields"


def test_restore_writes_restore_audit_record(client, client_and_engine):
    """需求 4：恢复必须写入 action="restore" 的历史记录。"""
    _, engine = client_and_engine
    event = make_event(client, status="resolved", title="Restore me")
    archive(client, event["id"])

    assert client.post(f"/events/{event['id']}/restore").status_code == 200

    rows = history_of(engine, event["id"])
    assert [row.action for row in rows] == ["archive", "restore"]
    restore_row = rows[-1]
    assert restore_row.actor_id == "local-dev"
    assert restore_row.old_status == Status.resolved
    assert restore_row.new_status == Status.resolved  # 状态本身没变，靠 action 区分


def test_restore_makes_event_visible_in_normal_list_again(client):
    """需求 7 的反向面：恢复后事件重新出现在普通列表。"""
    event = make_event(client, title="Come back")
    archive(client, event["id"])
    assert client.get("/events").json() == []

    assert client.post(f"/events/{event['id']}/restore").status_code == 200
    body = client.get("/events").json()
    assert [item["id"] for item in body] == [event["id"]]
    assert client.get(f"/events/{event['id']}").status_code == 200
    assert client.get("/events/archived").json() == []


def test_restored_event_can_be_patched_again(client):
    """恢复后普通 PATCH 应重新可用（闸门随 deleted_at 一起解除）。"""
    event = make_event(client, title="Editable again", status="investigating")
    archive(client, event["id"])
    assert client.patch(f"/events/{event['id']}", json={"title": "still archived"}).status_code == 409

    assert client.post(f"/events/{event['id']}/restore").status_code == 200
    response = client.patch(
        f"/events/{event['id']}", json={"status": "resolved", "reason": "恢复后继续处置"}
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "resolved"


def test_restore_missing_event_returns_404(client):
    assert client.post("/events/999999/restore").status_code == 404


def test_restore_twice_returns_409(client):
    """需求 6：重复恢复必须给出明确错误，而不是静默成功。"""
    event = make_event(client, title="Restore me once")
    archive(client, event["id"])
    assert client.post(f"/events/{event['id']}/restore").status_code == 200
    response = client.post(f"/events/{event['id']}/restore")
    assert response.status_code == 409, response.text


def test_restore_on_active_event_returns_409(client):
    """未归档的事件调用恢复 = 语义错误，同样是 409。"""
    event = make_event(client)
    assert client.post(f"/events/{event['id']}/restore").status_code == 409


def test_history_persists_across_archive_and_restore(client, client_and_engine):
    """需求：历史持久化 —— 归档与恢复都不丢历史，且顺序正确。"""
    client, engine = client_and_engine
    event = make_event(client, status="open", title="Full trail")
    eid = event["id"]

    assert client.patch(f"/events/{eid}", json={"status": "investigating"}).status_code == 200
    assert client.patch(
        f"/events/{eid}", json={"status": "resolved", "reason": "已处置"}
    ).status_code == 200
    archive(client, eid)
    assert client.post(f"/events/{eid}/restore").status_code == 200

    actions = [row.action for row in history_of(engine, eid)]
    assert actions == ["status_change", "status_change", "archive", "restore"]

    body = client.get(f"/events/{eid}/history").json()
    assert [item["action"] for item in body] == actions
    assert body[2]["reason"] == ""            # 归档无原因
    assert body[1]["reason"] == "已处置"       # 原原因未被覆盖


def test_archive_restore_archive_round_trip(client, client_and_engine):
    """归档 → 恢复 → 再归档 应稳定循环，每次动作都留痕。"""
    client, engine = client_and_engine
    event = make_event(client, title="Round trip")
    eid = event["id"]

    archive(client, eid)
    assert client.post(f"/events/{eid}/restore").status_code == 200
    archive(client, eid)

    assert event_row(engine, eid).deleted_at is not None
    assert [row.action for row in history_of(engine, eid)] == ["archive", "restore", "archive"]
    assert [item["id"] for item in client.get("/events/archived").json()] == [eid]
    assert client.get("/events").json() == []


# ---------------------------------------------------------------------------
# 3) 事务原子性：deleted_at 更新与恢复审计同生共死
#    与状态变更为同一手法：用「外键必然失败」制造确定性异常，
#    不依赖 SQLite 不强制执行的 VARCHAR(n) 长度限制。
# ---------------------------------------------------------------------------
def test_restore_and_audit_roll_back_together(client_and_engine, monkeypatch):
    client, engine = client_and_engine
    created = make_event(client, status="open", title="Restore rollback probe")
    eid = created["id"]
    archive(client, eid)
    assert event_row(engine, eid).deleted_at is not None

    real_history = main.StatusHistory

    def broken_history(**kwargs):
        kwargs["event_id"] = 999_999  # 外键必然失败
        return real_history(**kwargs)

    monkeypatch.setattr(main, "StatusHistory", broken_history)

    with pytest.raises(IntegrityError):
        with Session(engine) as session:
            main.restore_event(eid, session)

    monkeypatch.undo()

    # 事务整体回滚：deleted_at 仍非空（事件**没有**被恢复）、审计也没多
    assert event_row(engine, eid).deleted_at is not None
    assert [row.action for row in history_of(engine, eid)] == ["archive"]
    assert [item["id"] for item in client.get("/events/archived").json()] == [eid]


def test_restore_writes_exactly_one_history_row(client, client_and_engine):
    _, engine = client_and_engine
    event = make_event(client, title="One row only")
    archive(client, event["id"])
    before = len(history_of(engine, event["id"]))

    assert client.post(f"/events/{event['id']}/restore").status_code == 200
    assert len(history_of(engine, event["id"])) == before + 1


def test_no_route_allows_modifying_history_still_holds(client):
    """恢复功能上线后，审计表依然是只读：没有任何历史写入路由。"""
    for method, path in [
        ("post", "/events/1/history"),
        ("patch", "/events/1/history"),
        ("put", "/events/1/history"),
        ("delete", "/events/1/history"),
    ]:
        response = getattr(client, method)(path)
        assert response.status_code in (404, 405), f"{method} {path} -> {response.status_code}"
