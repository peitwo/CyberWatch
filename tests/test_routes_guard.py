"""全量路由安全守卫（评审意见 R1-2）。

这三个测试回答的是同一个问题的三个侧面：**"新接口有没有可能漏掉防护？"**

1. `test_every_app_route_is_declared_in_route_policy`
   —— 路由表与 `ROUTE_POLICY` **双向核对**。新增路由忘了登记策略 → 直接红。
2. `test_every_protected_route_rejects_anonymous`
   —— 对每一条"需要认证"的路由发**真实的匿名 HTTP 请求**，必须 401 / 302。
      挂了策略但依赖写错、被中间件放行，都会在这里暴露。
3. `test_every_write_route_requires_csrf`
   —— 对每一条"需要权限的写方法"发**已登录但不带 CSRF 头**的请求，必须 403。
      漏挂 CSRF 的写接口不可能溜过去。

三条都不使用 `dependency_overrides` 绕过认证；`get_session` 的覆盖只用于把
数据库指向临时库（见 `tests/conftest.py` 顶部的纪律说明）。
"""
from __future__ import annotations

import pytest

from app.auth import AUTH_SETTINGS
from app.main import app
from app.permissions import (
    ALL_ROUTE_POLICY,
    PLANNED_ROUTE_POLICY,
    ROUTE_POLICY,
    V051_PROTECTED_ROUTES,
    WRITE_METHODS,
    Permission,
    RoutePolicy,
    policy_for,
)

# ---------------------------------------------------------------------------
# 工具：把 app.routes 展开成 (方法, 路径) 列表
# ---------------------------------------------------------------------------
def iter_route_specs(application=app) -> list[tuple[str, str]]:
    """递归展开应用的全部 HTTP 路由。

    为什么不能直接遍历 `app.routes`：当前 Starlette/FastAPI 版本会把
    `include_router()` 的结果包成一个 `_IncludedRouter` 惰性节点，
    它的内层真实路由挂在 `.original_router.routes` 上。直接用 `app.routes`
    会**看不到 `/auth/*` 四条路由**，守卫就出现了盲区。
    """
    specs: list[tuple[str, str]] = []

    def walk(routes) -> None:
        for route in routes:
            inner_router = getattr(route, "original_router", None)
            if inner_router is not None:
                walk(getattr(inner_router, "routes", []))
                continue
            path = getattr(route, "path", None)
            methods = getattr(route, "methods", None)
            if not path or not methods:
                continue  # 静态资源挂载点 / 无方法的路由
            for method in methods:
                specs.append((method.upper(), path))

    walk(application.routes)
    return specs


def concrete_path(path: str) -> str:
    """把路径参数换成确定的值。

    守卫测试只关心"依赖有没有跑起来"，不关心业务结果，
    所以用合法但必定不存在的 id（1）即可 —— 依赖在**参数校验之前**执行，
    未认证一定先拿到 401，而不会因为"事件不存在"变成 404。
    """
    return path.replace("{event_id}", "1").replace("{user_id}", "1")


def is_docs(entry) -> bool:
    return entry is RoutePolicy.DOCS


# ---------------------------------------------------------------------------
# 1) 路由表 ↔ ROUTE_POLICY 双向核对
# ---------------------------------------------------------------------------
def test_every_app_route_is_declared_in_route_policy():
    actual = set(iter_route_specs())
    declared = set(ROUTE_POLICY)

    undocumented = sorted(actual - declared)
    assert not undocumented, (
        "以下路由没有在 app/permissions.py::ROUTE_POLICY 里登记策略。"
        "新接口**不允许**以「忘了加保护」的方式上线：\n  "
        + "\n  ".join(f"{m} {p}" for m, p in undocumented)
    )

    docs_declared = {(m, p) for (m, p) in declared if is_docs(ROUTE_POLICY[(m, p)])}
    if AUTH_SETTINGS.docs_mode == "disabled":
        # 关闭文档时这三条路由**不应该存在**
        assert not (actual & docs_declared), "docs_mode=disabled 时不应注册文档路由"
        stale = sorted(declared - actual - docs_declared)
    else:
        stale = sorted(declared - actual)
    assert not stale, (
        "ROUTE_POLICY 里登记了并不存在的路由（幽灵条目）：\n  "
        + "\n  ".join(f"{m} {p}" for m, p in stale)
        + "\n（若这是还没实现的路由，请放进 PLANNED_ROUTE_POLICY）"
    )


def test_planned_routes_are_not_implemented_yet():
    """计划中路由（V0.5.2 的 `/users*`）与已实现路由必须**零重叠**。

    这条测试是 `PLANNED_ROUTE_POLICY` 存在的意义所在：
    它把"两张表"从"随手放"变成"有方向的迁移"——

    - 一旦有人实现了 `/users`，它会同时出现在 `app.routes` 与
      `PLANNED_ROUTE_POLICY` 里 → 这条测试变红，逼他把条目搬进
      `ROUTE_POLICY`（搬进去之后，第 1 条双向核对与匿名/CSRF 守卫
      会自动开始保护这些新接口）。
    - 反过来，`ROUTE_POLICY` 与 `PLANNED_ROUTE_POLICY` 也不能有重复键，
      否则同一路由有两份策略，真相就不唯一了。

    换句话说：**新接口不可能靠"留在计划表里"绕过守卫。**
    """
    actual = set(iter_route_specs())
    overlap_implemented = sorted(set(PLANNED_ROUTE_POLICY) & actual)
    assert not overlap_implemented, (
        "以下路由已经实现了，却还留在 PLANNED_ROUTE_POLICY：\n  "
        + "\n  ".join(f"{m} {p}" for m, p in overlap_implemented)
        + "\n请把它们搬进 ROUTE_POLICY，让守卫开始保护它们。"
    )

    duplicated = sorted(set(ROUTE_POLICY) & set(PLANNED_ROUTE_POLICY))
    assert not duplicated, f"同一路由在两张表里各有一份策略：{duplicated}"


def test_route_policy_covers_every_v051_protected_business_route():
    """V0.5.1 的验收硬指标：**全部既有业务 API** 都在受保护清单里，一条不少。"""
    actual = set(iter_route_specs())
    missing_route = [entry for entry in V051_PROTECTED_ROUTES if entry not in actual]
    assert not missing_route, f"这些既有业务路由不存在了（被误删？）：{missing_route}"

    unprotected = []
    for method, path in V051_PROTECTED_ROUTES:
        entry = policy_for(method, path)
        if not (isinstance(entry, Permission) or entry is RoutePolicy.AUTH):
            unprotected.append((method, path, entry))
    assert not unprotected, f"这些既有业务路由没有挂认证/权限：{unprotected}"


# ---------------------------------------------------------------------------
# 2) 匿名请求：受保护路由一律拒绝
# ---------------------------------------------------------------------------
def test_every_protected_route_rejects_anonymous(anon_client):
    checked = 0
    for method, path in sorted(iter_route_specs()):
        entry = policy_for(method, path)
        assert entry is not None, f"{method} {path} 未登记策略"
        if isinstance(entry, Permission):
            response = getattr(anon_client, method.lower())(
                concrete_path(path), follow_redirects=False
            )
            assert response.status_code == 401, (
                f"{method} {path} 对匿名请求返回了 {response.status_code}，应为 401"
            )
            assert response.headers.get("WWW-Authenticate") == "Cookie", (method, path)
            checked += 1
        elif entry is RoutePolicy.AUTH:
            response = getattr(anon_client, method.lower())(
                concrete_path(path), follow_redirects=False
            )
            assert response.status_code == 302, (
                f"{method} {path} 是 HTML 路由，匿名应 302 跳登录，"
                f"实际 {response.status_code}"
            )
            assert response.headers["location"].startswith("/login?next="), (method, path)
            checked += 1
    # 防止"策略表被清空 → 循环没跑 → 测试假绿"
    assert checked >= len(V051_PROTECTED_ROUTES), (
        f"匿名守卫只检查了 {checked} 条受保护路由，少于预期下限 {len(V051_PROTECTED_ROUTES)}"
    )


# ---------------------------------------------------------------------------
# 3) 写方法：已登录但缺 CSRF → 403
# ---------------------------------------------------------------------------
def test_every_write_route_requires_csrf(make_client):
    admin = make_client("admin")          # 已登录 + 自动带 CSRF（用于造数据/对照）
    bare = make_client("admin", csrf=False)  # 已登录，但**故意不带** CSRF 头

    # 前置确认：403 必须来自"缺 CSRF"，而不是来自"未认证"
    assert bare.get("/auth/me").status_code == 200
    assert "cw_session" in bare.cookies
    assert bare.get("/events").status_code == 200

    event = admin.post(
        "/events", json={"title": "CSRF 守卫目标", "severity": "low"}
    ).json()

    checked = 0
    for method, path in sorted(iter_route_specs()):
        if method not in WRITE_METHODS:
            continue
        entry = policy_for(method, path)
        if not isinstance(entry, Permission):
            continue  # /auth/login（PUBLIC）与 /auth/logout（LOGOUT）是例外，另测
        target = path.replace("{event_id}", str(event["id"])).replace("{user_id}", "1")
        # httpx 的 `Client.delete()` **不接受** json 参数（只有 post/patch/put 接受），
        # 直接传会 TypeError；DELETE 的 CSRF 校验与请求体无关，不带 body 即可。
        kwargs = {} if method == "DELETE" else {"json": {}}
        response = getattr(bare, method.lower())(target, **kwargs)
        assert response.status_code == 403, (
            f"{method} {target} 在缺少 X-CSRF-Token 时返回 {response.status_code}，"
            "应为 403（CSRF 校验失败）"
        )
        assert "CSRF" in response.json()["detail"], (method, target)
        checked += 1
    assert checked >= 5, f"写方法只检查了 {checked} 条，守卫覆盖不足"


def test_write_route_with_correct_csrf_passes(make_client):
    """反向确认：带上正确 CSRF 后，写请求不再被判为 CSRF 失败。

    （409 来自"事件已归档"这类业务规则，属于**通过了** CSRF 与权限之后的判定。）
    """
    admin = make_client("admin")
    event = admin.post("/events", json={"title": "对照事件", "severity": "low"}).json()
    assert admin.patch(f"/events/{event['id']}", json={"severity": "high"}).status_code == 200
    assert admin.delete(f"/events/{event['id']}").status_code == 204
    assert admin.post(f"/events/{event['id']}/restore").status_code == 200
    assert admin.post("/events", json={"title": "再来一条", "severity": "low"}).status_code == 201


# ---------------------------------------------------------------------------
# 4) 例外路由（E1 / E2 / E3 / E4）——例外必须"可被看见、可被验证"
# ---------------------------------------------------------------------------
def test_logout_is_idempotent_and_never_401(anon_client, make_client):
    """E1：登出永远 204（幂等），未登录调用也不是 401。"""
    assert anon_client.post("/auth/logout").status_code == 204

    admin = make_client("admin")
    assert admin.post("/auth/logout").status_code == 204
    assert admin.post("/auth/logout").status_code == 204  # 再来一次仍然 204


def test_logout_with_session_requires_csrf(make_client):
    """E1 的补偿控制：**有会话**时必须带正确 CSRF，否则第三方可强制登出。"""
    bare = make_client("admin", csrf=False)
    assert bare.get("/auth/me").status_code == 200
    assert bare.post("/auth/logout").status_code == 403
    # 会话没有被吊销，用户仍然在线
    assert bare.get("/auth/me").status_code == 200


def test_login_is_the_only_unauthenticated_write_route(anon_client):
    """E2：`POST /auth/login` 是唯一无会话可用的写接口，且它仍有补偿控制。"""
    unauthenticated_writes = []
    for method, path in iter_route_specs():
        if method not in WRITE_METHODS:
            continue
        entry = policy_for(method, path)
        if entry in (RoutePolicy.PUBLIC, RoutePolicy.LOGOUT):
            unauthenticated_writes.append((method, path))
    assert sorted(unauthenticated_writes) == [
        ("POST", "/auth/login"),
        ("POST", "/auth/logout"),
    ], unauthenticated_writes

    # 跨站 Origin 的登录请求必须被拒（补偿控制之一）
    cross_site = anon_client.post(
        "/auth/login",
        json={"username": "admin", "password": "whatever-long-enough"},
        headers={"Origin": "https://evil.example"},
    )
    assert cross_site.status_code == 403, cross_site.text


def test_public_routes_leak_nothing_sensitive(anon_client):
    """E4：四个公开端点都不得泄露业务数据或部署细节。"""
    root = anon_client.get("/").json()
    assert set(root) == {"app", "version", "docs", "login"}

    assert anon_client.get("/healthz").json() == {"status": "ok"}
    assert anon_client.get("/healthz").content == b'{"status":"ok"}'

    login_page = anon_client.get("/login")
    assert login_page.status_code == 200
    assert "password" in login_page.text.lower()


def test_docs_route_registration_matches_docs_mode():
    """E3：文档路由的**注册情况**必须与 `docs_mode` 一致。

    三态的行为矩阵（admin 下非管理员 403 等）在 V0.5.2 用独立进程逐个模式验收；
    本轮先锁死"注册面"这一层，避免出现"配置说 disabled、路由却还在"的错位。
    """
    actual = set(iter_route_specs())
    docs_paths = {("GET", "/docs"), ("GET", "/redoc"), ("GET", "/openapi.json")}
    present = docs_paths & actual
    if AUTH_SETTINGS.docs_mode == "disabled":
        assert not present, f"docs_mode=disabled 却仍注册了文档路由：{present}"
    else:
        assert present == docs_paths, f"文档路由缺失：{sorted(docs_paths - present)}"


@pytest.mark.parametrize(
    "entry", sorted(ALL_ROUTE_POLICY.items(), key=lambda kv: kv[0])
)
def test_route_policy_entries_are_valid(entry):
    """策略表本身不能出现"既不公开、也没权限、又不是已知类型"的第三条路。

    遍历的是 `ALL_ROUTE_POLICY`（已实现 + 计划中）：计划中的条目也要
    满足同样的合法性要求，免得 V0.5.2 实现时才策略写错了。
    """
    (method, path), value = entry
    assert method == method.upper(), (method, path)
    assert path.startswith("/"), (method, path)
    assert isinstance(value, (Permission, RoutePolicy)), (method, path, value)


# ---------------------------------------------------------------------------
# 5) 页面级缓存：已认证的 HTML 绝不能被浏览器缓存
# ---------------------------------------------------------------------------
def test_authenticated_pages_are_not_cacheable(client, anon_client):
    """`/dashboard` 与 `/login` 必须带 ``Cache-Control: no-store``。

    这条测试的来历（值得写下来，因为它解释了"为什么单测不够"）：

    真浏览器验收时发现，退出登录后重新访问 ``/dashboard``，Chrome 会
    直接从缓存渲染出 dashboard 骨架，**根本没有再问服务器**。
    `FileResponse` 自带 `etag` / `last-modified`，没有 `Cache-Control`
    时浏览器可以自行决定复用缓存。随后的 API 请求会 401 并跳回登录页，
    所以最终结果是对的 —— 但"无会话的浏览器渲染出已认证页面"这件事
    本身就不该发生。

    TestClient 不实现 HTTP 缓存，所以这个缺陷**永远不可能**在这里被发现；
    这里是把它固化成回归测试，防止以后有人顺手把 no-store 去掉。
    """
    authed = client.get("/dashboard")
    assert authed.status_code == 200
    assert authed.headers.get("cache-control") == "no-store"

    login_page = anon_client.get("/login")
    assert login_page.status_code == 200
    assert login_page.headers.get("cache-control") == "no-store"


def test_anonymous_dashboard_redirect_is_not_cacheable(anon_client):
    """匿名访问 `/dashboard` 的 302 同样要带 no-store。

    302 本身不属于 RFC 9111 里"可被启发式缓存"的状态码，但显式声明更确定；
    这里钉住它，避免以后有人把跳转改成 301（301 **是**可被缓存的，
    那会让"登录后永远被跳回登录页"变成一个极难排查的问题）。
    """
    response = anon_client.get("/dashboard", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"].startswith("/login?next=")
    assert response.headers.get("cache-control") == "no-store"
