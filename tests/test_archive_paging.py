"""V0.4.2 收尾：归档中心的总数与分页。

覆盖本轮需求：

1. 后端提供**准确**的归档事件总数（不靠「已加载数量」去推测）；
2. 跨页加载不重复、不遗漏；
3. 恢复事件后总数正确递减。

安全约定：全部用例使用 conftest 提供的临时库 fixture，
**绝不连接**项目里的真实 ``cyberwatch.db``。
"""
from __future__ import annotations

import pytest


#: 与前端「加载更多」保持一致的页大小。
PAGE = 50


# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------
def make_event(client, **overrides):
    payload = {"title": "Archive candidate", "severity": "low", "description": "分页用"}
    payload.update(overrides)
    response = client.post("/events", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def archive(client, event_id: int):
    response = client.delete(f"/events/{event_id}")
    assert response.status_code == 204, response.text


def archive_many(client, count: int, prefix: str = "bulk"):
    """建 ``count`` 条事件并全部归档，返回按创建顺序的 id 列表。"""
    ids = []
    for index in range(count):
        ids.append(make_event(client, title=f"{prefix}-{index:03d}")["id"])
    for event_id in ids:
        archive(client, event_id)
    return ids


def archived_count(client) -> int:
    response = client.get("/events/archived/count")
    assert response.status_code == 200, response.text
    return response.json()["total"]


def fetch_all_pages(client, page: int = PAGE):
    """按 ``page`` 大小逐页抓取归档事件，返回 (items, pages)。"""
    items, offset, pages = [], 0, 0
    while True:
        response = client.get(f"/events/archived?offset={offset}&limit={page}")
        assert response.status_code == 200, response.text
        chunk = response.json()
        pages += 1
        if not chunk:
            break
        items.extend(chunk)
        offset += len(chunk)
        if len(chunk) < page:
            break
    return items, pages


# ---------------------------------------------------------------------------
# 1) 归档总数接口
# ---------------------------------------------------------------------------
def test_count_is_zero_when_nothing_archived(client):
    make_event(client)
    assert archived_count(client) == 0


def test_count_route_is_not_shadowed_by_event_id_path(client):
    """守卫：``/events/archived/count`` 不能被 ``/events/{event_id}`` 抢先匹配。

    若被抢先，``archived`` 会被当成 int 解析失败 → 422，归档中心的计数直接挂掉。
    """
    response = client.get("/events/archived/count")
    assert response.status_code == 200, response.text
    assert isinstance(response.json().get("total"), int)


def test_count_matches_archived_events_not_active_ones(client):
    keep = make_event(client, title="Keep active")
    gone = [make_event(client, title=f"Gone {i}")["id"] for i in range(3)]
    for event_id in gone:
        archive(client, event_id)

    assert archived_count(client) == 3
    # 普通列表只该剩下未归档的那条
    assert [item["id"] for item in client.get("/events").json()] == [keep["id"]]


def test_count_is_accurate_beyond_one_page(client):
    """核心需求：总数必须来自数据库 COUNT(*)，而不是「本页/已加载条数」。"""
    archive_many(client, PAGE * 3 + 7)

    assert archived_count(client) == PAGE * 3 + 7
    # 单页只拿得到 PAGE 条 —— 若把「已加载条数」当总数就会在这里露馅
    one_page = client.get(f"/events/archived?offset=0&limit={PAGE}").json()
    assert len(one_page) == PAGE
    assert archived_count(client) != len(one_page)


def test_count_decreases_by_one_per_restore(client):
    ids = archive_many(client, 5)
    assert archived_count(client) == 5

    for index, event_id in enumerate(ids, start=1):
        response = client.post(f"/events/{event_id}/restore")
        assert response.status_code == 200, response.text
        assert archived_count(client) == 5 - index

    assert archived_count(client) == 0


def test_count_ignores_restored_then_rearchived(client):
    event = make_event(client)
    archive(client, event["id"])
    assert archived_count(client) == 1

    assert client.post(f"/events/{event['id']}/restore").status_code == 200
    assert archived_count(client) == 0

    archive(client, event["id"])
    assert archived_count(client) == 1


# ---------------------------------------------------------------------------
# 2) 跨页加载：不重复、不遗漏
# ---------------------------------------------------------------------------
def test_paging_covers_every_archived_event_exactly_once(client):
    total = PAGE * 3 + 7
    expected = set(archive_many(client, total))

    items, pages = fetch_all_pages(client)
    got = [item["id"] for item in items]

    assert len(got) == len(set(got)), "跨页出现了重复事件"
    assert set(got) == expected, "跨页出现遗漏"
    # 157 条 / 每页 50 → 50 + 50 + 50 + 7，共 4 页（尾页不足一页即结束）
    assert pages == 4, f"页数应为 4，实际 {pages}"
    assert archived_count(client) == total


def test_paging_is_stable_when_the_same_page_is_read_twice(client):
    """同一页重复读取必须完全一致：分页排序键要确定（deleted_at DESC, id DESC）。"""
    archive_many(client, PAGE + 10)

    first = [item["id"] for item in client.get(f"/events/archived?offset=0&limit={PAGE}").json()]
    second = [item["id"] for item in client.get(f"/events/archived?offset=0&limit={PAGE}").json()]
    assert first == second


def test_paging_order_is_deleted_at_desc_across_pages(client):
    archive_many(client, PAGE + 20)

    items, _ = fetch_all_pages(client)
    stamps = [item["deleted_at"] for item in items]
    assert stamps == sorted(stamps, reverse=True), "归档时间未按倒序排列"


def test_paging_offset_beyond_total_returns_empty_page(client):
    archive_many(client, 5)

    assert client.get(f"/events/archived?offset=5&limit={PAGE}").json() == []
    assert client.get(f"/events/archived?offset=100&limit={PAGE}").json() == []


def test_paging_rejects_limit_above_cap(client):
    assert client.get("/events/archived?offset=0&limit=101").status_code == 422
    assert client.get("/events/archived?offset=-1&limit=10").status_code == 422


def test_paging_after_partial_restore_has_no_gap_or_duplicate(client):
    """恢复掉中间若干条后，重新按页抓取仍应「恰好覆盖」剩余归档事件。

    这是「恢复后分页位置正确」的服务端保证：offset 语义基于**当前**的
    归档集合，而不是客户端缓存的旧下标。
    """
    all_ids = archive_many(client, PAGE + 30)
    first_page = [item["id"] for item in client.get(f"/events/archived?offset=0&limit={PAGE}").json()]

    # 恢复掉第一页里的 3 条（含正中间的那条）
    removed = {first_page[0], first_page[len(first_page) // 2], first_page[-1]}
    for event_id in removed:
        assert client.post(f"/events/{event_id}/restore").status_code == 200

    remaining, _ = fetch_all_pages(client)
    got = [item["id"] for item in remaining]
    assert len(got) == len(set(got)), "恢复后跨页出现重复"
    assert set(got) == set(all_ids) - removed, "恢复后跨页出现遗漏或残留"
    assert archived_count(client) == len(got)
