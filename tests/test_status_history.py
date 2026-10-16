"""V0.4.2：状态变更历史（审计）、原因校验、软删除归档、事务原子性。

覆盖需求：
- 状态变更历史表与只追加策略
- 原因校验（后端权威，防绕过前端）
- 软删除 / 归档审计
- 状态变更与审计写入的**同事务**原子性
- SQLite 外键真实生效

安全约定：全部用例使用 conftest 提供的临时库 fixture，
**绝不连接**项目里的真实 ``cyberwatch.db``。
"""
from __future__ import annotations

import pytest
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from app import main
from app.main import Status

VALID_STATUSES = ["open", "investigating", "resolved"]


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
# 1) requires_status_reason：确定性纯函数（后端权威规则）
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "old,new,expected",
    [
        ("investigating", "resolved", True),   # 必须写「解决原因」
        ("resolved", "open", True),            # 必须写「重新打开原因」
        ("resolved", "investigating", True),   # 必须写「重新打开原因」
        ("open", "investigating", False),      # 可选
        ("open", "resolved", False),           # 需求只要求 investigating→resolved
        ("investigating", "open", False),      # 可选
        ("resolved", "resolved", False),       # 状态没变
        ("open", "open", False),
    ],
)
def test_requires_status_reason_rule(old, new, expected):
    assert main.requires_status_reason(Status(old), Status(new)) is expected


# ---------------------------------------------------------------------------
# 2) 历史持久化与字段正确性
# ---------------------------------------------------------------------------
def test_status_change_writes_one_history_row(client, client_and_engine):
    _, engine = client_and_engine
    event = make_event(client, status="open")

    response = client.patch(
        f"/events/{event['id']}",
        json={"status": "investigating", "reason": "开始排查"},
    )
    assert response.status_code == 200, response.text

    rows = history_of(engine, event["id"])
    assert len(rows) == 1
    row = rows[0]
    assert row.event_id == event["id"]
    assert row.old_status == Status.open
    assert row.new_status == Status.investigating
    assert row.reason == "开始排查"
    assert row.action == "status_change"
    assert row.actor_id == "local-dev"          # 开发环境占位身份
    assert row.changed_at is not None


def test_history_endpoint_returns_timeline_in_order(client, client_and_engine):
    _, engine = client_and_engine
    event = make_event(client, status="open")
    eid = event["id"]

    assert client.patch(f"/events/{eid}", json={"status": "investigating"}).status_code == 200
    assert client.patch(
        f"/events/{eid}", json={"status": "resolved", "reason": "已封禁来源 IP"}
    ).status_code == 200
    assert client.patch(
        f"/events/{eid}", json={"status": "open", "reason": "同样的告警又出现了"}
    ).status_code == 200

    body = client.get(f"/events/{eid}/history").json()
    assert [(item["old_status"], item["new_status"]) for item in body] == [
        ("open", "investigating"),
        ("investigating", "resolved"),
        ("resolved", "open"),
    ]
    assert [item["action"] for item in body] == ["status_change"] * 3
    assert body[1]["reason"] == "已封禁来源 IP"
    assert body[2]["reason"] == "同样的告警又出现了"
    # 接口返回顺序必须与直接查库顺序一致（时间线从旧到新）
    assert [item["id"] for item in body] == [row.id for row in history_of(engine, eid)]


def test_every_transition_direction_writes_history(client, client_and_engine):
    """任意方向都能切换，且每一次都留下一条历史。"""
    _, engine = client_and_engine
    event = make_event(client, status="open")
    eid = event["id"]

    # open → investigating（原因可选）
    assert client.patch(f"/events/{eid}", json={"status": "investigating"}).status_code == 200
    # investigating → resolved（必须给原因）
    assert client.patch(
        f"/events/{eid}", json={"status": "resolved", "reason": "已处置"}
    ).status_code == 200
    # resolved → open（必须给重开原因）
    assert client.patch(
        f"/events/{eid}", json={"status": "open", "reason": "复发"}
    ).status_code == 200

    assert len(history_of(engine, eid)) == 3


def test_history_for_missing_event_returns_404(client):
    assert client.get("/events/999999/history").status_code == 404


def test_history_is_empty_before_any_change(client, client_and_engine):
    _, engine = client_and_engine
    event = make_event(client)
    assert history_of(engine, event["id"]) == []
    assert client.get(f"/events/{event['id']}/history").json() == []


# ---------------------------------------------------------------------------
# 3) 什么时候**不该**写历史
# ---------------------------------------------------------------------------
def test_patching_title_only_writes_no_history(client, client_and_engine):
    _, engine = client_and_engine
    event = make_event(client, status="investigating")

    response = client.patch(f"/events/{event['id']}", json={"title": "改了标题而已"})
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "investigating"   # 状态未被牵连
    assert history_of(engine, event["id"]) == []


def test_patching_same_status_writes_no_history(client, client_and_engine):
    """状态「提交了但没变」不产生噪音记录。"""
    _, engine = client_and_engine
    event = make_event(client, status="resolved")

    response = client.patch(f"/events/{event['id']}", json={"status": "resolved"})
    assert response.status_code == 200, response.text
    assert history_of(engine, event["id"]) == []


def test_empty_payload_writes_no_history(client, client_and_engine):
    _, engine = client_and_engine
    event = make_event(client, status="open")
    assert client.patch(f"/events/{event['id']}", json={}).status_code == 200
    assert history_of(engine, event["id"]) == []


# ---------------------------------------------------------------------------
# 4) 原因校验：后端才是真正的闸门（直接调 API 绕过前端）
# ---------------------------------------------------------------------------
def test_investigating_to_resolved_requires_reason(client, client_and_engine):
    _, engine = client_and_engine
    event = make_event(client, status="investigating")

    response = client.patch(f"/events/{event['id']}", json={"status": "resolved"})
    assert response.status_code == 422, response.text
    # 被拒绝的请求：状态不变、也不留半截历史
    assert client.get(f"/events/{event['id']}").json()["status"] == "investigating"
    assert history_of(engine, event["id"]) == []


@pytest.mark.parametrize("target", ["open", "investigating"])
def test_resolved_to_other_requires_reopen_reason(client, client_and_engine, target):
    _, engine = client_and_engine
    event = make_event(client, status="resolved")

    response = client.patch(f"/events/{event['id']}", json={"status": target})
    assert response.status_code == 422, response.text
    assert client.get(f"/events/{event['id']}").json()["status"] == "resolved"
    assert history_of(engine, event["id"]) == []


@pytest.mark.parametrize("blank", ["", "   ", "\t\n"])
def test_blank_reason_is_rejected_where_required(client, blank):
    """纯空白不算「填写了原因」。"""
    event = make_event(client, status="investigating")
    response = client.patch(
        f"/events/{event['id']}", json={"status": "resolved", "reason": blank}
    )
    assert response.status_code == 422, response.text


def test_optional_direction_accepts_missing_reason(client, client_and_engine):
    _, engine = client_and_engine
    event = make_event(client, status="open")

    response = client.patch(f"/events/{event['id']}", json={"status": "investigating"})
    assert response.status_code == 200, response.text
    rows = history_of(engine, event["id"])
    assert len(rows) == 1 and rows[0].reason == ""     # 原因可选，落库为空串


def test_reason_explicit_null_returns_422(client):
    event = make_event(client, status="open")
    response = client.patch(f"/events/{event['id']}", json={"status": "investigating", "reason": None})
    assert response.status_code == 422, response.text


def test_reason_too_long_returns_422(client):
    event = make_event(client, status="open")
    response = client.patch(
        f"/events/{event['id']}", json={"status": "investigating", "reason": "x" * 1001}
    )
    assert response.status_code == 422, response.text


def test_client_cannot_forge_audit_fields(client):
    """审计字段不接受客户端输入：传 actor_id / action 一律 422。"""
    event = make_event(client, status="open")
    for forged in ({"actor_id": "hacker"}, {"action": "archive"}, {"changed_at": "2000-01-01T00:00:00"}):
        payload = {"status": "investigating", **forged}
        response = client.patch(f"/events/{event['id']}", json=payload)
        assert response.status_code == 422, (forged, response.text)


# ---------------------------------------------------------------------------
# 5) 只追加：不存在任何修改 / 删除历史的接口
# ---------------------------------------------------------------------------
def test_no_route_allows_modifying_history():
    """从路由表层面证明「审计只追加」：history 只有只读 GET。

    这里只审计「与 status_history 资源相关的路由」，不去管 events 自己的
    写方法路由（那些是正常的业务接口）。
    """
    history_paths = [
        (getattr(r, "path", ""), set(getattr(r, "methods", None) or []))
        for r in main.app.routes
        if "status_history" in getattr(r, "path", "")
    ]
    assert history_paths == [], f"不应存在 status_history 资源的独立路由：{history_paths}"

    # 唯一以 /history 结尾的路由，必须是只读 GET
    get_routes = [
        (r.path, set(r.methods))
        for r in main.app.routes
        if getattr(r, "path", "").endswith("/history")
    ]
    assert get_routes == [("/events/{event_id}/history", {"GET"})], get_routes


def test_history_write_endpoints_do_not_exist(client):
    assert client.patch("/status_history/1", json={"reason": "x"}).status_code == 404
    assert client.delete("/status_history/1").status_code == 404
    assert client.put("/status_history/1", json={}).status_code == 404


# ---------------------------------------------------------------------------
# 6) 软删除 / 归档
# ---------------------------------------------------------------------------
def test_delete_archives_instead_of_removing_the_row(client, client_and_engine):
    """删事件 = 归档：行仍在库里，只是 deleted_at 被置位。"""
    _, engine = client_and_engine
    event = make_event(client, title="待归档事件")

    response = client.delete(f"/events/{event['id']}")
    assert response.status_code == 204, response.text
    assert response.content == b""

    row = event_row(engine, event["id"])
    assert row is not None, "软删除不得物理删除数据行（审计与外键依赖它）"
    assert row.deleted_at is not None
    assert row.title == "待归档事件"          # 事件本体完整保留
    assert row.status == Status.open


def test_archived_event_disappears_from_normal_endpoints(client):
    event = make_event(client)
    keeper = make_event(client, title="keep this event")
    assert client.delete(f"/events/{event['id']}").status_code == 204

    # 普通 GET 对已归档事件返回 404（未来通过专用归档接口查看）
    assert client.get(f"/events/{event['id']}").status_code == 404
    # 默认列表不再包含它，但其他事件照常
    remaining = client.get("/events").json()
    assert [item["id"] for item in remaining] == [keeper["id"]]
    # 且不会因为归档而误伤其他筛选
    assert client.get("/events", params={"status": "open"}).json()[0]["id"] == keeper["id"]


def test_archived_event_cannot_be_patched(client):
    """前端隐藏按钮不算数：后端必须真正拦住已归档事件的普通修改。"""
    event = make_event(client)
    assert client.delete(f"/events/{event['id']}").status_code == 204

    response = client.patch(f"/events/{event['id']}", json={"title": "偷偷改一下"})
    assert response.status_code == 409, response.text
    response = client.patch(f"/events/{event['id']}", json={"status": "resolved", "reason": "x"})
    assert response.status_code == 409, response.text


def test_archiving_twice_returns_404(client):
    event = make_event(client)
    assert client.delete(f"/events/{event['id']}").status_code == 204
    assert client.delete(f"/events/{event['id']}").status_code == 404


def test_archive_writes_audit_record(client, client_and_engine):
    """归档本身也要留痕（需求 11：软删除和恢复操作也要预留审计记录机制）。"""
    _, engine = client_and_engine
    event = make_event(client, status="investigating")

    # 先留一条状态变更历史，确认归档不会把它冲掉
    assert client.patch(
        f"/events/{event['id']}", json={"status": "resolved", "reason": "已处置"}
    ).status_code == 200
    assert client.delete(f"/events/{event['id']}").status_code == 204

    rows = history_of(engine, event["id"])
    assert [row.action for row in rows] == ["status_change", "archive"]
    archive_row = rows[-1]
    assert archive_row.actor_id == "local-dev"
    assert archive_row.old_status == Status.resolved
    assert archive_row.new_status == Status.resolved   # 状态本身没变，靠 action 区分


def test_history_still_readable_after_archive(client, client_and_engine):
    """归档只隐藏「事件」，不隐藏审计：历史数据必须保留且可复查。"""
    _, engine = client_and_engine
    event = make_event(client, status="open")
    eid = event["id"]
    assert client.patch(
        f"/events/{eid}", json={"status": "investigating"}
    ).status_code == 200
    assert client.delete(f"/events/{eid}").status_code == 204

    body = client.get(f"/events/{eid}/history").json()
    assert [(item["action"]) for item in body] == ["status_change", "archive"]
    assert len(history_of(engine, eid)) == 2


# ---------------------------------------------------------------------------
# 7) 事务原子性：状态修改与审计写入同生共死
#    刻意**不依赖** VARCHAR 长度限制（SQLite 不强制 VARCHAR(n) 长度，
#    靠它触发失败是无效的），改用「外键必然失败」这一确定性手段。
# ---------------------------------------------------------------------------
def test_status_and_audit_roll_back_together(client_and_engine, monkeypatch):
    client, engine = client_and_engine
    created = make_event(client, status="open", title="Rollback probe")
    eid = created["id"]

    real_history = main.StatusHistory

    def broken_history(**kwargs):
        # 把审计行的 event_id 指向不存在的事件 → 外键约束必然失败
        kwargs["event_id"] = 999_999
        return real_history(**kwargs)

    monkeypatch.setattr(main, "StatusHistory", broken_history)

    # 让失败的会话随 with 退出而回滚（不在这里手动 rollback，才能证明是事务自身回滚）
    with pytest.raises(IntegrityError):
        with Session(engine) as session:
            main.update_event(eid, main.EventUpdate(status=Status.investigating), session)

    monkeypatch.undo()

    # 事务整体回滚：状态没改、审计也没多
    assert event_row(engine, eid).status == Status.open
    assert history_of(engine, eid) == []


def test_foreign_key_is_really_enforced(client_and_engine):
    """PRAGMA foreign_keys=ON 必须真实生效，而不是只写在 DDL 里。"""
    _, engine = client_and_engine
    with pytest.raises(IntegrityError):
        with Session(engine) as session:
            session.add(
                main.StatusHistory(
                    event_id=999_999,
                    old_status=Status.open,
                    new_status=Status.resolved,
                    reason="指向不存在的事件",
                )
            )
            session.commit()


def test_archived_event_row_still_satisfies_foreign_key(client_and_engine):
    """软删除后事件行仍在 → 审计外键始终有效（这是软删除的核心理由）。"""
    client, engine = client_and_engine
    event = make_event(client, status="open")
    eid = event["id"]
    assert client.patch(f"/events/{eid}", json={"status": "investigating"}).status_code == 200
    assert client.delete(f"/events/{eid}").status_code == 204

    # 归档后事件行依然存在（只是 deleted_at 非空），因此外键引用对象没有消失
    row = event_row(engine, eid)
    assert row is not None and row.deleted_at is not None
    assert len(history_of(engine, eid)) == 2          # status_change + archive
