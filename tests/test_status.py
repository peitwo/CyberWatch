"""生命周期 status 字段的测试（需求 1-6、8、13、14）。

这些用例先于实现存在（TDD 红灯）：它们描述「修复后应该成立的行为」。
"""
from __future__ import annotations

import pytest

VALID_STATUSES = ["open", "investigating", "resolved"]


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


# ---------------------------------------------------------------------------
# 需求 1、2：三种有效值；新建默认 open
# ---------------------------------------------------------------------------
def test_create_defaults_to_open(client):
    created = make_event(client)
    assert created["status"] == "open"
    # 落库确认，而不是只看响应
    assert client.get(f"/events/{created['id']}").json()["status"] == "open"


@pytest.mark.parametrize("state", VALID_STATUSES)
def test_create_accepts_every_valid_status(client, state):
    created = make_event(client, status=state)
    assert created["status"] == state
    assert client.get(f"/events/{created['id']}").json()["status"] == state


@pytest.mark.parametrize(
    "bad", ["closed", "OPEN", "Resolved", "", "unknown", "open ", 123, True]
)
def test_create_rejects_invalid_status(client, bad):
    response = client.post(
        "/events", json={"title": "bad status probe", "status": bad}
    )
    assert response.status_code == 422, response.text
    assert client.get("/events").json() == []  # 未落库


# ---------------------------------------------------------------------------
# 需求 3：三个状态之间可任意方向切换（含 resolved 回到 open / investigating）
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "start,target",
    [
        ("open", "investigating"),
        ("open", "resolved"),
        ("investigating", "open"),
        ("investigating", "resolved"),
        ("resolved", "open"),
        ("resolved", "investigating"),
    ],
)
def test_status_can_transition_freely(client, start, target):
    event = make_event(client, status=start)
    response = client.patch(f"/events/{event['id']}", json={"status": target})
    assert response.status_code == 200, response.text
    assert response.json()["status"] == target
    assert client.get(f"/events/{event['id']}").json()["status"] == target


# ---------------------------------------------------------------------------
# 需求 4：severity 与 status 互相独立（双向断言）
# ---------------------------------------------------------------------------
def test_changing_status_does_not_touch_severity(client):
    original = make_event(client, severity="high", status="open")
    response = client.patch(f"/events/{original['id']}", json={"status": "resolved"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "resolved"
    for field in ("severity", "title", "description", "id", "created_at"):
        assert body[field] == original[field], field


def test_changing_severity_does_not_touch_status(client):
    original = make_event(client, severity="low", status="investigating")
    response = client.patch(f"/events/{original['id']}", json={"severity": "high"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["severity"] == "high"
    assert body["status"] == "investigating"
    assert client.get(f"/events/{original['id']}").json()["status"] == "investigating"


# ---------------------------------------------------------------------------
# 需求 5：PATCH 局部更新语义
# ---------------------------------------------------------------------------
def test_partial_update_status_keeps_other_fields(client):
    original = make_event(client, title="Partial update probe", severity="medium")
    response = client.patch(
        f"/events/{original['id']}", json={"status": "investigating"}
    )
    assert response.status_code == 200, response.text
    stored = client.get(f"/events/{original['id']}").json()
    assert stored["status"] == "investigating"
    for field in ("title", "severity", "description", "id", "created_at"):
        assert stored[field] == original[field], field


def test_empty_payload_keeps_status(client):
    original = make_event(client, status="resolved")
    response = client.patch(f"/events/{original['id']}", json={})
    assert response.status_code == 200, response.text
    assert response.json() == original


# ---------------------------------------------------------------------------
# 需求 6：显式 null / 非法值 / 拼错字段 → 422，且不改动数据
# ---------------------------------------------------------------------------
def test_status_explicit_null_returns_422(client):
    original = make_event(client)
    response = client.patch(f"/events/{original['id']}", json={"status": None})
    assert response.status_code == 422, response.text
    assert client.get(f"/events/{original['id']}").json() == original


@pytest.mark.parametrize("bad", ["closed", "OPEN", "", 123, True])
def test_patch_rejects_invalid_status_and_keeps_data(client, bad):
    original = make_event(client)
    response = client.patch(f"/events/{original['id']}", json={"status": bad})
    assert response.status_code == 422, response.text
    assert client.get(f"/events/{original['id']}").json() == original


def test_patch_rejects_misspelled_status_field(client):
    original = make_event(client)
    response = client.patch(f"/events/{original['id']}", json={"statu": "resolved"})
    assert response.status_code == 422, response.text
    assert client.get(f"/events/{original['id']}").json() == original


# ---------------------------------------------------------------------------
# 需求 8、9：列表 / 详情响应带 status；筛选
# ---------------------------------------------------------------------------
def test_responses_include_status(client):
    event = make_event(client, status="resolved")
    assert "status" in client.get("/events").json()[0]
    assert client.get(f"/events/{event['id']}").json()["status"] == "resolved"


def test_filter_by_status(client):
    make_event(client, title="open one", status="open")
    make_event(client, title="open two", status="open")
    make_event(client, title="resolved one", status="resolved")

    resolved = client.get("/events", params={"status": "resolved"}).json()
    assert [item["status"] for item in resolved] == ["resolved"]
    assert len(client.get("/events", params={"status": "open"}).json()) == 2
    assert len(client.get("/events").json()) == 3


def test_filter_by_severity_and_status_together(client):
    """两个筛选条件必须同时生效（旧实现是「重建 statement」，会互相覆盖）。"""
    both = make_event(client, title="high and open", severity="high", status="open")
    make_event(client, title="high but resolved", severity="high", status="resolved")
    make_event(client, title="low and open", severity="low", status="open")

    # 单个条件各自都对
    assert len(client.get("/events", params={"severity": "high"}).json()) == 2
    assert len(client.get("/events", params={"status": "open"}).json()) == 2

    # 组合条件必须是交集，且只有 1 条
    combined = client.get(
        "/events", params={"severity": "high", "status": "open"}
    ).json()
    assert [item["id"] for item in combined] == [both["id"]], combined


def test_filter_with_no_match_returns_empty(client):
    make_event(client, severity="high", status="open")
    assert client.get(
        "/events", params={"severity": "low", "status": "resolved"}
    ).json() == []


def test_filter_by_invalid_status_returns_422(client):
    assert client.get("/events", params={"status": "closed"}).status_code == 422
