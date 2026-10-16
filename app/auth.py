"""会话、Cookie、CSRF、鉴权依赖与 `/auth/*` 路由（V0.5 新增）。

依赖方向（见设计文档 §2.0，严格单向、无环）::

    config → database → models → permissions → auth → main

本模块**只**使用 `app/models.py` 的模型，自己不再声明任何模型 —— 这正是
评审意见 R1-1 要消除的"模型散落两处、auth 与 main 循环导入"问题。

三件核心机制：

1. **服务端会话**：Cookie 里放随机令牌，库里只存 ``sha256(令牌)``。
   数据库泄露 ≠ 会话被冒用，且不需要任何签名密钥。
2. **CSRF 防护写进 `require()` 依赖内部**：任何走 `require()` 的写接口
   **自动**获得 CSRF 校验，结构上不存在"某个写接口忘了加"。
3. **`require()` 一次做三件事**：认证（401）→ 角色（403）→ 写方法 CSRF（403）。
   顺序固定，便于测试断言，也无法只做一半。
"""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from typing import Annotated, Callable
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlmodel import Session, delete, select

from app.config import AuthSettings, load_auth_settings
from app.database import SessionDep
from app.models import (
    LoginRequest,
    PasswordChangeRequest,
    Role,
    User,
    UserRead,
    UserSession,
)
from app.permissions import Permission, RoutePolicy, WRITE_METHODS, has_permission
from app.security import (
    MAX_PASSWORD_LENGTH,
    PasswordPolicyError,
    add_seconds,
    constant_time_equals,
    describe_duration,
    generate_csrf_token,
    generate_session_token,
    hash_password,
    hash_session_token,
    normalize_utc,
    password_needs_rehash,
    run_dummy_verify,
    seconds_since,
    utcnow,
    validate_password_strength,
    verify_password,
)

logger = logging.getLogger("cyberwatch.auth")

#: 进程级配置快照。`production` 配置非法时会在此**抛出中文异常**，
#: 即"拒绝启动"，而不是带病运行（见设计文档 §2.9）。
AUTH_SETTINGS: AuthSettings = load_auth_settings()

#: Cookie / 头名称。会话 Cookie 名可由配置覆盖（多实例同域部署时便于区分）。
SESSION_COOKIE = AUTH_SETTINGS.cookie_name
#: CSRF Cookie **故意不是 HttpOnly**：它本身不是凭证（没有会话 Cookie 什么也做不了），
#: 前端必须能读到它才能做"双提交 + 服务端比对"。
CSRF_COOKIE = "cw_csrf"
CSRF_HEADER = "X-CSRF-Token"

#: 账号级登录限流参数（阈值与窗口）。
LOGIN_LOCKOUT_THRESHOLD = 5
LOGIN_LOCKOUT_SECONDS = 15 * 60

#: 空闲续期的写入节流：距上次写入超过该秒数才回写 ``last_seen_at``。
TOUCH_INTERVAL_SECONDS = 10 * 60

#: 失效会话的保留天数（超过才被机会式清理删除）。
SESSION_RETENTION_DAYS = 7

#: 统一登录失败文案。**"用户不存在"与"密码错误"必须完全一致**，
#: 否则就成了用户枚举的漏洞。
LOGIN_FAILED_DETAIL = "用户名或密码错误"


# ---------------------------------------------------------------------------
# 1) 请求上下文
# ---------------------------------------------------------------------------
@dataclass
class AuthContext:
    """一次已认证请求的上下文：账号 + 它当前使用的会话行。"""

    user: User
    session_row: UserSession


def client_ip(request: Request) -> str | None:
    """尽力而为地取得客户端 IP（**仅用于记录，不参与鉴权决策**）。

    只有在显式信任反代（`CYBERWATCH_TRUST_PROXY=true`）且来源在
    `CYBERWATCH_TRUSTED_PROXY_CIDRS` 白名单内时，才解析
    ``X-Forwarded-For``；否则一律用直连地址。

    为什么要校验整条链：只要有一跳不在白名单，就说明转发头可能是伪造的 ——
    此时**整条链作废**，宁可记录直连地址，也不要把攻击者提供的字符串写进日志。
    """
    direct = request.client.host if request.client else None
    if not AUTH_SETTINGS.trust_proxy:
        return direct

    forwarded = request.headers.get("x-forwarded-for")
    if not forwarded:
        return direct
    hops = [part.strip() for part in forwarded.split(",") if part.strip()]
    if not hops:
        return direct

    trusted = []
    for cidr in AUTH_SETTINGS.trusted_proxy_cidrs:
        try:
            trusted.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            logger.warning("配置的受信代理网段无法解析：%r（已忽略）", cidr)
    if not trusted:
        return direct

    def is_trusted(value: str) -> bool:
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            return False
        return any(addr in network for network in trusted)

    # 从最右（离我们最近）往左走：跳过受信代理，第一个非受信地址就是客户端。
    for hop in reversed(hops):
        try:
            ipaddress.ip_address(hop)
        except ValueError:
            return direct  # 出现非法 IPv6/IPv4 字面量 → 整个头不可信
        if not is_trusted(hop):
            return hop
    # 全都是受信代理往上打 → 取最左那个（原始发起方）
    return hops[0] if hops else direct


# ---------------------------------------------------------------------------
# 2) Cookie 读写
# ---------------------------------------------------------------------------
def _cookie_kwargs() -> dict:
    return {
        "path": "/",
        "samesite": "lax",
        "secure": AUTH_SETTINGS.cookie_secure,
        # 刻意**不设 domain**：绑定当前主机，天然排除子域共享
    }


def set_session_cookies(response: Response, raw_token: str, csrf_token: str) -> None:
    """写入会话 Cookie 与 CSRF Cookie（Max-Age = 会话绝对有效期）。"""
    max_age = AUTH_SETTINGS.session_ttl_seconds
    response.set_cookie(SESSION_COOKIE, raw_token, max_age=max_age, httponly=True, **_cookie_kwargs())
    response.set_cookie(CSRF_COOKIE, csrf_token, max_age=max_age, httponly=False, **_cookie_kwargs())


def clear_session_cookies(response: Response) -> None:
    """清掉两个 Cookie。属性必须与写入时一致，否则浏览器不会真正删除。"""
    response.delete_cookie(SESSION_COOKIE, **_cookie_kwargs())
    response.delete_cookie(CSRF_COOKIE, **_cookie_kwargs())


# ---------------------------------------------------------------------------
# 3) 会话生命周期
# ---------------------------------------------------------------------------
def create_session(session: Session, user: User, request: Request) -> tuple[str, str]:
    """为某用户新建一条会话，返回 ``(明文令牌, csrf 令牌)``。

    **登录成功时总是新建**（不复用客户端带来的任何令牌）→
    这是对「会话固定攻击」的结构性防御。
    """
    raw_token = generate_session_token()
    csrf_token = generate_csrf_token()
    now = utcnow()
    session.add(
        UserSession(
            token_hash=hash_session_token(raw_token),
            user_id=user.id,
            csrf_token=csrf_token,
            created_at=now,
            last_seen_at=now,
            expires_at=add_seconds(now, AUTH_SETTINGS.session_ttl_seconds),
            user_agent=(request.headers.get("user-agent") or "")[:255] or None,
            ip_address=(client_ip(request) or "")[:64] or None,
        )
    )
    session.commit()
    return raw_token, csrf_token


def revoke_sessions(
    session: Session,
    *,
    user_id: int | None = None,
    session_rows: list[UserSession] | None = None,
    reason: str,
) -> int:
    """吊销会话（按用户批量，或给具体若干条）。返回被吊销的条数。

    **只吊销仍有效的行**（``revoked_at is None``），避免覆盖掉更早的原因
    （例如先 ``deactivated`` 后 ``logout``，保留第一次的原因更有诊断价值）。
    """
    targets = session_rows
    if targets is None:
        statement = select(UserSession).where(UserSession.revoked_at.is_(None))
        if user_id is not None:
            statement = statement.where(UserSession.user_id == user_id)
        targets = list(session.exec(statement).all())

    now = utcnow()
    changed = 0
    for row in targets:
        if row.revoked_at is not None:
            continue
        row.revoked_at = now
        row.revoked_reason = reason[:32]
        session.add(row)
        changed += 1
    if changed:
        session.commit()
    return changed


_cleanup_state = {"last": 0.0}


def maybe_cleanup_sessions(session: Session) -> int:
    """机会式清理：**每进程每小时至多一次**，删除 7 天前的失效会话行。

    先用 SQL 粗筛（``revoked_at IS NOT NULL OR expires_at < 粗筛界``），
    再用 Python 精确比较时间 —— 时间比较**绝不下推到 SQL 字符串比较**
    （SQLite 的 DATETIME 无时区，字符串比较是巧合而不是契约）。
    """
    import time  # 局部导入：只有这里需要单调时钟

    now_monotonic = time.monotonic()
    if now_monotonic - _cleanup_state["last"] < 3600:
        return 0
    _cleanup_state["last"] = now_monotonic

    now = utcnow()
    coarse = add_seconds(now, -SESSION_RETENTION_DAYS * 86400 - 86400)
    candidates = list(
        session.exec(
            select(UserSession).where(
                (UserSession.revoked_at.is_not(None)) | (UserSession.expires_at < coarse)
            )
        ).all()
    )
    cutoff = add_seconds(now, -SESSION_RETENTION_DAYS * 86400)
    stale_ids = [
        row.id
        for row in candidates
        if row.id is not None
        and (
            (normalize_utc(row.revoked_at) is not None and normalize_utc(row.revoked_at) < cutoff)
            or (normalize_utc(row.expires_at) is not None and normalize_utc(row.expires_at) < cutoff)
        )
    ]
    if not stale_ids:
        return 0
    session.exec(delete(UserSession).where(UserSession.id.in_(stale_ids)))  # type: ignore[attr-defined]
    session.commit()
    logger.info("机会式清理：删除 %d 条过期会话", len(stale_ids))
    return len(stale_ids)


# ---------------------------------------------------------------------------
# 4) 认证（把 Cookie 变成 AuthContext）
# ---------------------------------------------------------------------------
def _unauthorized(detail: str, *, headers: dict[str, str] | None = None) -> HTTPException:
    merged = {"WWW-Authenticate": "Cookie"}
    if headers:
        merged.update(headers)
    return HTTPException(status.HTTP_401_UNAUTHORIZED, detail, headers=merged)


def resolve_auth_context(request: Request, session: Session) -> AuthContext:
    """校验会话并返回 :class:`AuthContext`；任何一步不通过都抛 401。

    判定顺序（短路，全部通过才放行）—— 与设计文档 §2.3 完全一致：

    1. 有会话 Cookie；
    2. 以 ``sha256(Cookie)`` 能查到会话行；
    3. ``revoked_at is None``；
    4. 未过绝对有效期；
    5. 未过空闲超时；
    6. 用户存在且 ``is_active``；
    7. 会话创建时间不早于用户最后一次改密时间；
    8. （通过后）按 10 分钟节流滚动续期 ``last_seen_at``。
    """
    raw_token = request.cookies.get(SESSION_COOKIE)
    if not raw_token:
        raise _unauthorized("未认证：请先登录")

    row = session.exec(
        select(UserSession).where(UserSession.token_hash == hash_session_token(raw_token))
    ).first()
    if row is None:
        raise _unauthorized("未认证：请先登录")

    if row.revoked_at is not None:
        raise _unauthorized("未认证：请先登录")

    now = utcnow()
    expires_at = normalize_utc(row.expires_at)
    if expires_at is None or now > expires_at:
        revoke_sessions(session, session_rows=[row], reason="expired")
        raise _unauthorized("未认证：会话已过期，请重新登录")

    last_seen = normalize_utc(row.last_seen_at) or normalize_utc(row.created_at)
    # `seconds_since(None)` 返回 +inf，于是"时间戳缺失"天然落进"已超时"分支，
    # 不必再单独写一次 `is None` 判断 —— 少一处可能上下不一致的地方。
    idle_seconds = seconds_since(last_seen, now=now)
    if idle_seconds > AUTH_SETTINGS.session_idle_seconds:
        revoke_sessions(session, session_rows=[row], reason="expired")
        raise _unauthorized("未认证：会话已过期，请重新登录")

    user = session.get(User, row.user_id)
    if user is None or not user.is_active:
        # 停用**立即生效**：顺手把该用户全部会话一起吊销，不留半开状态。
        revoke_sessions(session, user_id=row.user_id, reason="deactivated")
        raise _unauthorized("未认证：请先登录")

    created_at = normalize_utc(row.created_at)
    password_changed_at = normalize_utc(user.password_changed_at)
    if created_at is not None and password_changed_at is not None and created_at < password_changed_at:
        revoke_sessions(session, session_rows=[row], reason="password_change")
        raise _unauthorized("未认证：密码已变更，请重新登录")

    if idle_seconds > TOUCH_INTERVAL_SECONDS:
        row.last_seen_at = now
        session.add(row)
        session.commit()

    return AuthContext(user=user, session_row=row)


def get_auth_context(request: Request, session: SessionDep) -> AuthContext:
    """FastAPI 依赖：未认证直接 401。"""
    return resolve_auth_context(request, session)


def get_current_user(context: Annotated[AuthContext, Depends(get_auth_context)]) -> User:
    """FastAPI 依赖：只取当前用户（V0.5.2 的用户管理接口会用到）。"""
    return context.user


CurrentUserDep = Annotated[User, Depends(get_current_user)]


# ---------------------------------------------------------------------------
# 5) CSRF 校验
# ---------------------------------------------------------------------------
def verify_csrf(request: Request, context: AuthContext) -> None:
    """写方法必须带与服务端一致的 ``X-CSRF-Token``。

    失败返回 **403 而不是 401**：401 的语义是"未认证"，会让前端误判为
    "会话过期"而跳登录页；403 明确表示"你已登录，但这个请求不被接受"。
    """
    provided = request.headers.get(CSRF_HEADER)
    expected = context.session_row.csrf_token
    if not provided or not constant_time_equals(provided, expected):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF 校验失败")


# ---------------------------------------------------------------------------
# 6) 权限依赖工厂
# ---------------------------------------------------------------------------
def require(permission: Permission) -> Callable[..., User]:
    """生成"需要某权限"的依赖：**认证 → 角色 → （写方法）CSRF**。

    返回的函数带 ``__cw_permission__`` 标记，供 `tests/test_routes_guard.py`
    做静态核对（"每条路由都真的挂了依赖"，而不只是写在策略表里）。
    """

    def dependency(request: Request, session: SessionDep) -> User:
        context = resolve_auth_context(request, session)
        if not has_permission(context.user.role, permission):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"权限不足：需要 {permission.value}（当前角色 {context.user.role.value}）",
            )
        if request.method.upper() in WRITE_METHODS:
            verify_csrf(request, context)
        return context.user

    dependency.__cw_permission__ = permission  # type: ignore[attr-defined]
    dependency.__cw_policy__ = RoutePolicy.PERM  # type: ignore[attr-defined]
    return dependency


def require_role(role: Role, *, html: bool = False) -> Callable[..., User]:
    """生成"需要某个具体角色"的依赖（文档路由按 admin 收口时使用）。

    ``html=True`` 时，未认证返回 **302 跳登录页**（浏览器场景），
    否则返回 JSON 401（程序化场景）。
    """

    def dependency(request: Request, session: SessionDep) -> User:
        try:
            context = resolve_auth_context(request, session)
        except HTTPException:
            if html:
                raise HTTPException(
                    status_code=status.HTTP_302_FOUND,
                    detail="未认证：正在跳转登录页",
                    headers={"Location": login_redirect_url(request)},
                )
            raise
        if context.user.role is not role:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"权限不足：需要 {role.value} 角色（当前角色 {context.user.role.value}）",
            )
        if request.method.upper() in WRITE_METHODS:
            verify_csrf(request, context)
        return context.user

    dependency.__cw_role__ = role  # type: ignore[attr-defined]
    return dependency


def require_html_session() -> Callable[..., User]:
    """HTML 路由用：未认证 **302 跳登录页**，而不是返回 JSON 401。

    浏览器场景与程序化调用场景的最优解不同 —— `/dashboard` 属于前者。
    """

    def dependency(request: Request, session: SessionDep) -> User:
        try:
            return resolve_auth_context(request, session).user
        except HTTPException:
            raise HTTPException(
                status_code=status.HTTP_302_FOUND,
                detail="未认证：正在跳转登录页",
                headers={
                    "Location": login_redirect_url(request),
                    # 302 本身不属于"可被启发式缓存"的状态码（RFC 9111 §4.2.2），
                    # 所以不是漏洞；但显式声明更确定 —— 真实浏览器验收里
                    # 我们正是被"缓存住了已认证页面"咬过一次，不打算在
                    # 跳转上再赌一次浏览器实现差异。
                    "Cache-Control": "no-store",
                },
            )

    dependency.__cw_policy__ = RoutePolicy.AUTH  # type: ignore[attr-defined]
    return dependency


def login_redirect_url(request: Request) -> str:
    """构造 ``/login?next=<安全化的原路径>``。"""
    from app.security import normalize_utc as _n  # noqa: F401  保持 import 稳定性

    target = request.url.path or "/dashboard"
    if request.url.query:
        target = f"{target}?{request.url.query}"
    return f"/login?next={safe_next_path(target)}"


def safe_next_path(raw: str | None, *, default: str = "/dashboard") -> str:
    """开放重定向防护：只接受**站内相对路径**。

    拒绝：空、不以 ``/`` 开头、以 ``//`` 开头（协议相对 URL）、含 ``\\``、含 ``:``。
    不满足则回落到 ``default``。
    """
    if not raw:
        return default
    value = raw.strip()
    if not value.startswith("/") or value.startswith("//"):
        return default
    if "\\" in value or ":" in value:
        return default
    return value


def _login_origin_ok(request: Request) -> bool:
    """登录接口的 Origin / Referer 同源校验（例外 E2 的补偿控制之一）。

    - 缺失 Origin/Referer：``development`` 下放行（便于 curl / 测试），
      ``production`` 下**拒绝**；
    - 存在时：必须是 ``null`` 之外的、与请求 ``Host`` 同源的来源。
    """
    origin = request.headers.get("origin")
    referer = request.headers.get("referer")
    candidate = origin or referer
    if not candidate:
        return not AUTH_SETTINGS.is_production
    if candidate.strip().lower() == "null":
        return False
    parsed = urlparse(candidate)
    if not parsed.netloc:
        return False
    host = (request.headers.get("host") or "").strip().lower()
    if not host:
        return False
    return parsed.netloc.lower() == host


# ---------------------------------------------------------------------------
# 7) 业务动作：登录 / 登出 / 改密
# ---------------------------------------------------------------------------
def _password_too_long(password: str) -> bool:
    return len(password) > MAX_PASSWORD_LENGTH


def authenticate(
    session: Session, request: Request, username: str, password: str
) -> User:
    """校验凭据并返回用户；失败抛 401（**文案完全一致**）。

    防枚举的两个手段同时用上：

    - 文案与状态码一致；
    - 用户不存在时照样跑一次 Argon2 校验（时间对齐）。
    """
    normalized = username.strip().lower()
    user = session.exec(select(User).where(User.username == normalized)).first()
    now = utcnow()

    if user is None:
        run_dummy_verify()  # 时间对齐：让"用户不存在"与"密码错误"耗时接近
        logger.warning("登录失败（用户不存在）username=%r ip=%s", normalized, client_ip(request))
        raise _unauthorized(LOGIN_FAILED_DETAIL)

    locked_until = normalize_utc(user.locked_until)
    if locked_until is not None and locked_until > now:
        # 刻意**不返回** `Retry-After`，也刻意不换状态码。
        #
        # 这是一处实测出来的账号枚举旁路（见 V0.5.1 开发报告 §8）：
        # 只要给"已锁定"分支多加一个响应头，攻击者对同一用户名试 5 次之后，
        # 第 6 次响应就会带上 `Retry-After`，而**不存在的用户名永远不会带** ——
        # 于是"账号是否存在"就又泄露了，前面做的统一文案 + 时间对齐全部白费。
        #
        # 剩余时间只写进服务端日志：它属于运维信息，不该出现在无认证的响应里。
        remaining = max((locked_until - now).total_seconds(), 1)
        logger.warning(
            "登录被拒（账号锁定中）username=%r ip=%s 剩余=%s",
            user.username, client_ip(request), describe_duration(remaining),
        )
        raise _unauthorized(LOGIN_FAILED_DETAIL)

    if not verify_password(password, user.password_hash):
        user.failed_login_count = (user.failed_login_count or 0) + 1
        if user.failed_login_count >= LOGIN_LOCKOUT_THRESHOLD:
            user.locked_until = add_seconds(now, LOGIN_LOCKOUT_SECONDS)
            # 锁定事件必须留下告警日志，否则"已知用户名被恶意锁死"会长期无人察觉
            logger.warning(
                "账号已锁定 username=%r ip=%s 连续失败=%d 时长=%s",
                user.username, client_ip(request), user.failed_login_count,
                describe_duration(LOGIN_LOCKOUT_SECONDS),
            )
        session.add(user)
        session.commit()
        logger.warning("登录失败（密码错误）username=%r ip=%s", user.username, client_ip(request))
        raise _unauthorized(LOGIN_FAILED_DETAIL)

    # 密码正确之后再判停用 —— 顺序很关键：这样"停用账号 + 正确密码"与
    # "密码错误"对外表现完全一致，不泄露账号存在性。
    if not user.is_active:
        logger.warning("登录失败（账号已停用）username=%r ip=%s", user.username, client_ip(request))
        raise _unauthorized(LOGIN_FAILED_DETAIL)

    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = now
    # 参数升级：旧的（成本更低的）哈希在登录成功时静默重建，用户无感
    if password_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
        # 注意：**不动** password_changed_at —— 重算哈希不等于改密码，
        # 不应该把用户其它设备上的会话一并踢掉。
    session.add(user)
    session.commit()
    logger.info("登录成功 username=%r role=%s ip=%s", user.username, user.role.value, client_ip(request))
    return user


def change_own_password(session: Session, user: User, old_password: str, new_password: str) -> None:
    """改自己的密码，并**吊销该用户的全部会话（含当前）**。

    为什么连当前会话也吊销：改密往往发生在"怀疑账号被盗"时，
    保留任何旧会话都留有后门。代价只是让用户重新登录一次。
    """
    if not verify_password(old_password, user.password_hash):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "原密码不正确")
    try:
        validate_password_strength(new_password, user.username)
    except PasswordPolicyError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    if verify_password(new_password, user.password_hash):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "新密码不能与原密码相同")

    user.password_hash = hash_password(new_password)
    user.password_changed_at = utcnow()
    session.add(user)
    session.commit()
    revoke_sessions(session, user_id=user.id, reason="password_change")


# ---------------------------------------------------------------------------
# 8) 路由
# ---------------------------------------------------------------------------
auth_router = APIRouter(prefix="/auth", tags=["auth"])


@auth_router.post("/login", response_model=UserRead)
def login(payload: LoginRequest, request: Request, response: Response, session: SessionDep):
    """登录。**唯一**无会话可用的写接口（例外 E2）。

    补偿控制：`SameSite=Lax` + Origin/Referer 同源校验 + 账号级失败限流 +
    登录总是新建会话（抗会话固定）。
    """
    if not payload.username.strip():
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "用户名不能为空")
    if not _login_origin_ok(request):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "登录请求来源校验失败")

    password = payload.password.get_secret_value()
    if not password:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "密码不能为空")
    if _password_too_long(password):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, f"密码过长：最多 {MAX_PASSWORD_LENGTH} 位"
        )

    user = authenticate(session, request, payload.username, password)
    maybe_cleanup_sessions(session)
    raw_token, csrf_token = create_session(session, user, request)
    set_session_cookies(response, raw_token, csrf_token)
    session.refresh(user)
    return user


@auth_router.post("/logout", response_model=None, status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, response: Response, session: SessionDep):
    """登出。**永远 204（幂等）**，未登录调用也不会得到 401（例外 E1）。

    有会话时仍然要带正确的 ``X-CSRF-Token``（否则 403）——
    否则第三方站点可以诱导浏览器把用户"强制登出"。
    """
    raw_token = request.cookies.get(SESSION_COOKIE)
    if raw_token:
        row = session.exec(
            select(UserSession).where(UserSession.token_hash == hash_session_token(raw_token))
        ).first()
        if row is not None and row.revoked_at is None:
            provided = request.headers.get(CSRF_HEADER)
            if not provided or not constant_time_equals(provided, row.csrf_token):
                raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF 校验失败")
            revoke_sessions(session, session_rows=[row], reason="logout")
    clear_session_cookies(response)
    response.status_code = status.HTTP_204_NO_CONTENT
    return None


@auth_router.get("/me", response_model=UserRead)
def read_me(user: CurrentUserDep):
    """当前登录用户（前端据此渲染角色化 UI）。"""
    return user


@auth_router.post(
    "/password",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
    dependencies=[Depends(require(Permission.SESSION_SELF))],
)
def change_password(
    payload: PasswordChangeRequest,
    request: Request,
    response: Response,
    session: SessionDep,
    user: CurrentUserDep,
):
    """修改**自己**的密码；成功后全部会话失效（含当前），前端应跳登录页。

    返回 204（无响应体）：前端只需要"成功/失败"这一个信号，
    详细的下一步动作（跳登录页）是固定的。
    """
    old_password = payload.old_password.get_secret_value()
    new_password = payload.new_password.get_secret_value()
    if _password_too_long(new_password) or _password_too_long(old_password):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, f"密码过长：最多 {MAX_PASSWORD_LENGTH} 位"
        )
    change_own_password(session, user, old_password, new_password)
    clear_session_cookies(response)
    response.status_code = status.HTTP_204_NO_CONTENT
    return None
