"""权限常量、角色矩阵与路由策略表（V0.5 新增）。

本模块是**权限的唯一真相来源**，只依赖 `app.models.Role`，不 import
`app.auth` / `app.main`（因此不会参与循环导入，见设计文档 §2.0）。

三件东西：

1. :class:`Permission` —— 权限键的枚举（字符串值即文档里 API 矩阵的"权限键"）；
2. :data:`ROLE_PERMISSIONS` —— 角色 → 权限集合。**改权限只改这一张表。**
3. :class:`RoutePolicy` / :data:`ROUTE_POLICY` —— 路由 → 策略。守卫测试会用
   它和 `app.routes` 双向核对，**新增路由忘登记会直接测试失败**（评审意见 R1-2）。

为什么权限不是散落在路由里的 ``if role == "admin"``：
那样写，权限矩阵就只存在于每个人的脑子里 —— 既无法被测试遍历，
也无法回答"到底谁能归档事件"。集中成数据后，矩阵本身可以被参数化测试。
"""
from __future__ import annotations

from enum import Enum

from app.models import Role

#: HTTP 写方法（需要 CSRF 校验的方法集合）。
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class Permission(str, Enum):
    """权限键。字符串值同时作为 API 契约（文档 / 测试断言）的一部分。"""

    EVENT_READ = "event.read"
    EVENT_CREATE = "event.create"
    EVENT_UPDATE = "event.update"
    EVENT_ARCHIVE = "event.archive"
    EVENT_RESTORE = "event.restore"
    AUDIT_READ = "audit.read"
    USER_READ = "user.read"
    USER_CREATE = "user.create"
    USER_UPDATE = "user.update"
    USER_RESET_PASSWORD = "user.reset_password"
    SESSION_SELF = "session.self"


#: 角色 → 权限集合（**单一真相来源**）。
#:
#: - `viewer`：只读。能看列表 / 详情 / 归档中心 / 时间线，写操作一律 403；
#: - `analyst`：安全分析员的完整事件操作面；**不能**管理用户；
#: - `admin`：全部（含用户管理，V0.5.2 交付 API/UI）。
ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.viewer: frozenset(
        {
            Permission.EVENT_READ,
            Permission.AUDIT_READ,
            Permission.SESSION_SELF,
        }
    ),
    Role.analyst: frozenset(
        {
            Permission.EVENT_READ,
            Permission.EVENT_CREATE,
            Permission.EVENT_UPDATE,
            Permission.EVENT_ARCHIVE,
            Permission.EVENT_RESTORE,
            Permission.AUDIT_READ,
            Permission.SESSION_SELF,
        }
    ),
    Role.admin: frozenset(Permission),  # 全部权限
}


def has_permission(role: Role | str | None, permission: Permission) -> bool:
    """判断角色是否拥有某权限。未知 / ``None`` 角色一律 False（默认拒绝）。"""
    if role is None:
        return False
    try:
        normalized = role if isinstance(role, Role) else Role(role)
    except ValueError:
        return False
    return permission in ROLE_PERMISSIONS.get(normalized, frozenset())


def roles_for(permission: Permission) -> frozenset[Role]:
    """反查：哪些角色拥有该权限（供文档生成与矩阵测试使用）。"""
    return frozenset(
        role for role, grants in ROLE_PERMISSIONS.items() if permission in grants
    )


class RoutePolicy(str, Enum):
    """路由的**策略类别**（不是权限，权限请用 :class:`Permission`）。

    - :attr:`PUBLIC`  —— 完全公开：`/`、`/login`、`/healthz`、`/static/*`
    - :attr:`AUTH`    —— 只要登录（任意角色）：`/dashboard`
    - :attr:`PERM`    —— 需要具体权限（认证 + 角色 + 写方法时 CSRF）
    - :attr:`DOCS`    —— 由 `docs_mode` 决定：`/docs`、`/redoc`、`/openapi.json`
    - :attr:`LOGOUT`  —— 特例：永远 204 幂等（例外 E1，见设计文档 §4.2.2）
    """

    PUBLIC = "public"
    AUTH = "auth"
    PERM = "perm"
    DOCS = "docs"
    LOGOUT = "logout"


#: 路由 → 策略。键为 ``(HTTP 方法大写, 路径)``。
#:
#: **登记规则（守卫测试强制）**：`app.routes` 里出现的每一条业务路由都必须
#: 在这里出现，反之亦然。新接口不能"忘了挂权限"就上线 —— 忘了登记，
#: `tests/test_routes_guard.py` 会直接失败。
ROUTE_POLICY: dict[tuple[str, str], RoutePolicy | Permission] = {
    # --- 公开 ---
    ("GET", "/"): RoutePolicy.PUBLIC,
    ("GET", "/login"): RoutePolicy.PUBLIC,
    ("GET", "/healthz"): RoutePolicy.PUBLIC,
    # --- 只要登录（HTML 路由，未认证 302 跳登录） ---
    ("GET", "/dashboard"): RoutePolicy.AUTH,
    # --- 文档（由 docs_mode 决定） ---
    ("GET", "/docs"): RoutePolicy.DOCS,
    ("GET", "/redoc"): RoutePolicy.DOCS,
    ("GET", "/openapi.json"): RoutePolicy.DOCS,
    # --- 认证 ---
    ("POST", "/auth/login"): RoutePolicy.PUBLIC,  # 例外 E2：无会话可用，靠 Origin + 限流
    ("POST", "/auth/logout"): RoutePolicy.LOGOUT,  # 例外 E1：永远 204 幂等
    ("GET", "/auth/me"): Permission.SESSION_SELF,
    ("POST", "/auth/password"): Permission.SESSION_SELF,
    # --- 安全事件（全部业务 API 都在这里，V0.5.1 必须逐条挂上） ---
    ("GET", "/events"): Permission.EVENT_READ,
    ("POST", "/events"): Permission.EVENT_CREATE,
    ("GET", "/events/archived"): Permission.EVENT_READ,
    ("GET", "/events/archived/count"): Permission.EVENT_READ,
    ("GET", "/events/{event_id}"): Permission.EVENT_READ,
    ("GET", "/events/{event_id}/history"): Permission.AUDIT_READ,
    ("PATCH", "/events/{event_id}"): Permission.EVENT_UPDATE,
    ("DELETE", "/events/{event_id}"): Permission.EVENT_ARCHIVE,
    ("POST", "/events/{event_id}/restore"): Permission.EVENT_RESTORE,
}

#: **V0.5.2 才实现**的路由 → 策略。提前登记，实现时不会漏掉权限设计。
#:
#: 为什么要和 :data:`ROUTE_POLICY` 分开，而不是塞在一起（评审意见 R1-2 的落地细节）：
#:
#: 守卫测试对 `ROUTE_POLICY` 做的是**双向**核对 —— 路由表里有而表里没有要报错，
#: 表里有而路由表里没有（"幽灵条目"）同样要报错。后者正是防"接口删了、
#: 权限条目留着腐烂"的关键。若把尚未实现的 `/users*` 混进去，
#: 双向核对就会长期为红，守卫只能被关掉 —— 那就等于没有守卫。
#:
#: 拆成两张表之后，两边都能被严格校验：
#:
#: - `ROUTE_POLICY`  ↔ 已实现路由，**必须精确相等**；
#: - `PLANNED_ROUTE_POLICY` ← 计划中路由，**不得**与已实现路由重叠
#:   （一旦实现，就必须搬进 `ROUTE_POLICY`，见
#:   `tests/test_routes_guard.py::test_planned_routes_are_not_implemented_yet`）。
PLANNED_ROUTE_POLICY: dict[tuple[str, str], RoutePolicy | Permission] = {
    ("GET", "/users"): Permission.USER_READ,
    ("POST", "/users"): Permission.USER_CREATE,
    ("GET", "/users/{user_id}"): Permission.USER_READ,
    ("PATCH", "/users/{user_id}"): Permission.USER_UPDATE,
    ("POST", "/users/{user_id}/password"): Permission.USER_RESET_PASSWORD,
    ("DELETE", "/users/{user_id}/sessions"): Permission.USER_UPDATE,
}

#: 已实现 + 计划中的全集。供"策略取值是否合法"这类与实现进度无关的检查遍历。
ALL_ROUTE_POLICY: dict[tuple[str, str], RoutePolicy | Permission] = {
    **ROUTE_POLICY,
    **PLANNED_ROUTE_POLICY,
}

#: 应该在 V0.5.1 真正挂上依赖的"既有业务 API"清单。
#: 守卫测试用它断言"一个都没漏"，开发报告用它做验收对照。
V051_PROTECTED_ROUTES: tuple[tuple[str, str], ...] = (
    ("GET", "/dashboard"),
    ("GET", "/auth/me"),
    ("POST", "/auth/password"),
    ("GET", "/events"),
    ("POST", "/events"),
    ("GET", "/events/archived"),
    ("GET", "/events/archived/count"),
    ("GET", "/events/{event_id}"),
    ("GET", "/events/{event_id}/history"),
    ("PATCH", "/events/{event_id}"),
    ("DELETE", "/events/{event_id}"),
    ("POST", "/events/{event_id}/restore"),
)


def policy_for(method: str, path: str) -> RoutePolicy | Permission | None:
    """查询某条路由的策略；未登记返回 ``None``。

    只看**已实现**的 `ROUTE_POLICY`。运行时鉴权就依赖它 ——
    计划中的 `/users*` 在本轮根本没有对应路由，不需要也不应该参与判定
    （一旦 V0.5.2 实现了它们，就必须搬进 `ROUTE_POLICY`）。
    """
    return ROUTE_POLICY.get((method.upper(), path))
