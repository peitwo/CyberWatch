"""认证、会话、CSRF、口令策略的测试（V0.5.1 / R1-8、R1-6）。

覆盖设计文档 §6.1 中与认证相关的全部用例，以及 §5.1 威胁模型里
T1–T9、T13、T15–T19、T21 的自动化验证。

纪律：

- 所有登录都走**真实** ``POST /auth/login``，不使用 ``dependency_overrides``
  绕过认证（见 conftest 顶部说明）；
- 时间相关用例一律**注入时间戳**（monkeypatch ``app.auth.utcnow``），
  绝不 ``sleep``；
- 每个用例都在自己的临时库里跑，永远不碰真实 ``cyberwatch.db``。
"""
from __future__ import annotations

import hashlib
from contextlib import closing
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

import app.auth as auth_module
from app.auth import (
    AUTH_SETTINGS,
    CSRF_COOKIE,
    CSRF_HEADER,
    LOGIN_FAILED_DETAIL,
    LOGIN_LOCKOUT_THRESHOLD,
    SESSION_COOKIE,
    safe_next_path,
)
from app.main import app
from app.models import User, UserSession
from app.security import (
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    PasswordPolicyError,
    describe_duration,
    hash_password,
    hash_session_token,
    normalize_utc,
    password_needs_rehash,
    seconds_since,
    utcnow,
    validate_password_strength,
    verify_password,
)

from conftest import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    ANALYST_PASSWORD,
    ANALYST_USERNAME,
    DISABLED_PASSWORD,
    DISABLED_USERNAME,
    VIEWER_USERNAME,
)

NEW_ADMIN_PASSWORD = "a-brand-new-Passphrase-2026"


# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------
def shift_time(monkeypatch, seconds: int) -> None:
    """把 app.auth 里的 ``utcnow`` 往前推 ``seconds`` 秒（时间戳注入，不用 sleep）。"""
    base = utcnow()

    def fake_utcnow():
        return base + timedelta(seconds=seconds)

    monkeypatch.setattr(auth_module, "utcnow", fake_utcnow)


def sessions_of(engine, username: str) -> list[UserSession]:
    with Session(engine) as session:
        user = session.exec(select(User).where(User.username == username)).first()
        assert user is not None
        return list(
            session.exec(select(UserSession).where(UserSession.user_id == user.id)).all()
        )


def user_row(engine, username: str) -> User:
    with Session(engine) as session:
        row = session.exec(select(User).where(User.username == username)).first()
        assert row is not None, f"测试账号 {username} 不存在"
        return row


def cookie_value(response, name: str) -> str | None:
    """从响应的 ``Set-Cookie`` 头里取某个 Cookie 的值（不碰客户端的 Cookie 罐）。

    为什么不直接读 ``client.cookies[name]``：TestClient 的 Cookie 罐会同时留下
    「测试里手工塞的」和「服务端下发的」同名 Cookie（domain 不同），
    httpx 遇到同名会抛 ``CookieConflict``。响应头是唯一无歧义的来源。
    """
    for header in response.headers.get_list("set-cookie"):
        if header.startswith(f"{name}="):
            return header.split(";", 1)[0].split("=", 1)[1]
    return None


# ===========================================================================
# 一、登录
# ===========================================================================
def test_login_success_sets_session_and_csrf_cookies(anon_client):
    response = anon_client.post(
        "/auth/login", json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["username"] == ADMIN_USERNAME
    assert body["role"] == "admin"
    assert body["is_active"] is True
    assert body["last_login_at"] is not None

    cookies = anon_client.cookies
    assert SESSION_COOKIE in cookies and CSRF_COOKIE in cookies
    # CSRF 令牌必须是 32 字节 → 64 个 hex 字符（正好填满 VARCHAR(64)）
    assert len(cookies[CSRF_COOKIE]) == 64


def test_session_cookie_attributes(anon_client):
    """会话 Cookie 必须 HttpOnly；CSRF Cookie 必须可被 JS 读到；两者都 SameSite=Lax。"""
    response = anon_client.post(
        "/auth/login", json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}
    )
    raw_headers = response.headers.get_list("set-cookie")
    session_header = next(h for h in raw_headers if h.startswith(SESSION_COOKIE + "="))
    csrf_header = next(h for h in raw_headers if h.startswith(CSRF_COOKIE + "="))

    assert "HttpOnly" in session_header
    assert "HttpOnly" not in csrf_header
    for header in (session_header, csrf_header):
        # 属性名大小写由 Starlette 决定，统一小写后比较，避免脆弱的拼写耦合
        lowered = header.lower()
        assert "samesite=lax" in lowered
        assert "path=/" in lowered
        # 刻意不设 Domain：绑定当前主机，天然排除子域共享
        assert "domain=" not in lowered
    # 开发环境不设 Secure（本机 http 可预测）；生产由配置强制为 true
    assert ("Secure" in session_header) is AUTH_SETTINGS.cookie_secure
    assert ("Secure" in csrf_header) is AUTH_SETTINGS.cookie_secure


def test_login_wrong_password_returns_401_with_generic_message(anon_client):
    response = anon_client.post(
        "/auth/login", json={"username": ADMIN_USERNAME, "password": "definitely-wrong-pass"}
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "用户名或密码错误"}
    assert SESSION_COOKIE not in anon_client.cookies


def test_login_unknown_user_is_indistinguishable(anon_client, monkeypatch):
    """T3/T4：用户不存在与密码错误必须**状态码、文案、调用路径**完全一致。"""
    calls: list[str] = []
    real_dummy = auth_module.run_dummy_verify

    def spy_dummy(*args, **kwargs):
        calls.append("dummy")
        return real_dummy(*args, **kwargs)

    monkeypatch.setattr(auth_module, "run_dummy_verify", spy_dummy)

    wrong = anon_client.post(
        "/auth/login", json={"username": ADMIN_USERNAME, "password": "wrong-but-long-enough"}
    )
    unknown = anon_client.post(
        "/auth/login", json={"username": "no-such-account", "password": "wrong-but-long-enough"}
    )

    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json() == {"detail": "用户名或密码错误"}
    assert len(calls) == 1, "未知用户路径必须也跑一次 Argon2 校验（时间对齐）"


def test_login_locks_account_after_five_failures(anon_client):
    """T2：连续 5 次失败后，**即使密码正确**也必须被拒。"""
    for _ in range(auth_module.LOGIN_LOCKOUT_THRESHOLD):
        response = anon_client.post(
            "/auth/login", json={"username": ADMIN_USERNAME, "password": "wrong-but-long-enough"}
        )
        assert response.status_code == 401

    locked = anon_client.post(
        "/auth/login", json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}
    )
    assert locked.status_code == 401, "锁定期间即便密码正确也不得放行"
    assert locked.json() == {"detail": LOGIN_FAILED_DETAIL}
    assert SESSION_COOKIE not in anon_client.cookies


def test_locked_account_is_indistinguishable_from_unknown_account(make_client):
    """锁定状态**不得**在响应里留下任何痕迹（否则又是一条枚举旁路）。

    这条测试的来历：V0.5.1 最初的实现给"已锁定"分支加了
    ``Retry-After`` 响应头。实测（对本机服务连打 6 次）结果：

    ===================  ================================================
    用户名                6 次 401 响应里 ``Retry-After`` 的出现情况
    ===================  ================================================
    ``admin``（存在）      第 6 次出现（``899``）
    ``ghost-account``（不存在） 全程 ``None``
    ===================  ================================================

    也就是说：只要求 5 次，就能靠"第 6 次有没有这个头"判断账号是否存在。
    前面辛苦做的统一文案 + Argon2 时间对齐，全被这一个头毁掉。

    修法是**把响应做得完全一致**，而不是"再补一个头让它也带上"——
    后者等于在普通失败响应里撒谎说账号已锁定。
    """
    engine = make_client.engine
    client = make_client("admin", csrf=False)
    unseen = "ghost-account-does-not-exist"

    # 把 admin 打到锁定
    for _ in range(auth_module.LOGIN_LOCKOUT_THRESHOLD):
        client.post(
            "/auth/login", json={"username": ADMIN_USERNAME, "password": "wrong-but-long-enough"}
        )

    locked = client.post(
        "/auth/login", json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}
    )
    unknown = client.post(
        "/auth/login", json={"username": unseen, "password": "wrong-but-long-enough"}
    )

    assert locked.status_code == unknown.status_code == 401
    assert locked.json() == unknown.json() == {"detail": LOGIN_FAILED_DETAIL}
    # 逐个头比对（忽略每次请求都会变的时间头）：两边必须完全一致
    volatile = {"date"}
    locked_headers = {k.lower(): v for k, v in locked.headers.items()}
    unknown_headers = {k.lower(): v for k, v in unknown.headers.items()}
    for name in volatile:
        locked_headers.pop(name, None)
        unknown_headers.pop(name, None)
    assert locked_headers == unknown_headers, (locked_headers, unknown_headers)
    # 点名钉住那个曾经泄露过的头
    assert "retry-after" not in locked_headers
    # 两边都不得下发会话 Cookie
    assert SESSION_COOKIE not in locked.cookies and SESSION_COOKIE not in unknown.cookies

    # 锁定的确发生了（只是不对外表现）：这条用例不是靠"没锁上"通过的
    assert user_row(engine, ADMIN_USERNAME).locked_until is not None


def test_failed_login_count_resets_after_success(make_client):
    engine = make_client.engine
    client = make_client("admin", csrf=False)

    for _ in range(2):
        assert (
            client.post(
                "/auth/login",
                json={"username": ADMIN_USERNAME, "password": "wrong-but-long-enough"},
            ).status_code
            == 401
        )
    assert user_row(engine, ADMIN_USERNAME).failed_login_count == 2

    assert (
        client.post(
            "/auth/login", json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}
        ).status_code
        == 200
    )
    row = user_row(engine, ADMIN_USERNAME)
    assert row.failed_login_count == 0
    assert row.locked_until is None


def test_deactivated_user_cannot_login(make_client):
    """停用账号**即使口令正确**也登录不了，且响应与「口令错误」逐字节一致。

    这是 req-5「停用即时生效」与 req-3「不泄露账号存在性」两条的联合验证：
    若两者响应有任何差异，攻击者就能靠对比响应枚举出哪些账号存在（T5）。
    """
    engine = make_client.engine
    with Session(engine) as session:
        user = session.exec(select(User).where(User.username == DISABLED_USERNAME)).first()
    assert user is not None and user.is_active is False, "夹具应播种一个已停用账号"

    # 新建一个干净的、没有任何 Cookie 的客户端（避免"已登录"状态干扰判定）
    with closing(TestClient(app)) as probe:
        deactivated = probe.post(
            "/auth/login",
            json={"username": DISABLED_USERNAME, "password": DISABLED_PASSWORD},
        )
    with closing(TestClient(app)) as probe:
        wrong_password = probe.post(
            "/auth/login",
            json={"username": ADMIN_USERNAME, "password": "definitely-not-the-password"},
        )

    assert deactivated.status_code == wrong_password.status_code == 401
    assert deactivated.json() == wrong_password.json() == {"detail": LOGIN_FAILED_DETAIL}
    # 停用分支绝不允许下发会话 Cookie（哪怕口令是对的）
    assert SESSION_COOKIE not in deactivated.cookies
    assert deactivated.headers.get("set-cookie") is None


def test_deactivated_user_keeps_failed_login_count_clean(make_client):
    """停用账号的失败**不应**累加到锁定计数（否则会把停用误判成"被爆破"）。"""
    engine = make_client.engine
    for _ in range(LOGIN_LOCKOUT_THRESHOLD + 1):
        with closing(TestClient(app)) as probe:
            probe.post(
                "/auth/login",
                json={"username": DISABLED_USERNAME, "password": DISABLED_PASSWORD},
            )
    with Session(engine) as session:
        row = session.exec(select(User).where(User.username == DISABLED_USERNAME)).first()
    assert row is not None
    assert row.failed_login_count == 0
    assert row.locked_until is None


@pytest.mark.parametrize(
    "payload",
    [
        {"username": "admin", "password": ""},
        {"username": "  ", "password": "some-long-password"},
        {"username": "admin", "password": "x" * (MAX_PASSWORD_LENGTH + 1)},
        {"username": "admin", "password": "ok-long-password", "extra": "typo"},
        {"username": "admin"},
    ],
)
def test_login_rejects_malformed_payload(anon_client, payload):
    """空用户名 / 空密码 / 超长密码 / 未知字段 / 缺字段：一律 4xx，且不建会话。"""
    response = anon_client.post("/auth/login", json=payload)
    assert 400 <= response.status_code < 500, response.text
    assert SESSION_COOKIE not in anon_client.cookies


def test_login_rejects_cross_site_origin(anon_client):
    """T7：登录接口的 Origin/Referer 同源校验。"""
    for origin in ("https://evil.example", "null"):
        response = anon_client.post(
            "/auth/login",
            json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
            headers={"Origin": origin},
        )
        assert response.status_code == 403, (origin, response.text)
        assert SESSION_COOKIE not in anon_client.cookies

    # 同源 Origin 正常放行
    ok = anon_client.post(
        "/auth/login",
        json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
        headers={"Origin": "http://testserver"},
    )
    assert ok.status_code == 200, ok.text


def test_login_response_never_contains_hash_or_password(anon_client):
    """T19：响应体不得包含密码或哈希（`SecretStr` 不得被序列化出去）。"""
    response = anon_client.post(
        "/auth/login", json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}
    )
    text = response.text.lower()
    assert "password" not in text
    assert "argon2" not in text
    assert ADMIN_PASSWORD not in response.text


# ===========================================================================
# 二、会话生命周期
# ===========================================================================
def test_unauthenticated_api_returns_401(anon_client):
    response = anon_client.get("/auth/me")
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Cookie"
    assert "未认证" in response.json()["detail"]


def test_dashboard_redirects_to_login_with_next(anon_client):
    response = anon_client.get("/dashboard", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"] == "/login?next=/dashboard"


def test_session_cookie_is_not_stored_in_plaintext(make_client):
    """T1：库里只能有 SHA-256 摘要，**绝不能**出现 Cookie 里的原始令牌。"""
    engine = make_client.engine
    client = make_client("admin")
    raw_token = client.cookies[SESSION_COOKIE]

    with Session(engine) as session:
        stored = [row.token_hash for row in session.exec(select(UserSession)).all()]
    assert raw_token not in stored
    assert hashlib.sha256(raw_token.encode()).hexdigest() in stored
    assert hash_session_token(raw_token) in stored


def test_garbage_session_cookie_is_rejected(anon_client):
    anon_client.cookies.set(SESSION_COOKIE, "not-a-real-token")
    response = anon_client.get("/auth/me")
    assert response.status_code == 401


def test_session_rejected_after_absolute_expiry(make_client, monkeypatch):
    """T6：绝对有效期一过，会话立刻无效，并把 revoked_reason 记为 expired。"""
    engine = make_client.engine
    client = make_client("admin")
    assert client.get("/auth/me").status_code == 200

    shift_time(monkeypatch, AUTH_SETTINGS.session_ttl_seconds + 60)

    response = client.get("/auth/me")
    assert response.status_code == 401
    assert "过期" in response.json()["detail"]

    rows = sessions_of(engine, ADMIN_USERNAME)
    assert len(rows) == 1
    assert rows[0].revoked_reason == "expired"
    assert normalize_utc(rows[0].revoked_at) is not None


def test_session_rejected_after_idle_timeout(make_client, monkeypatch):
    """T6：空闲超时必须**先于**绝对有效期生效。"""
    engine = make_client.engine
    client = make_client("admin")
    assert client.get("/auth/me").status_code == 200

    idle = AUTH_SETTINGS.session_idle_seconds
    assert idle < AUTH_SETTINGS.session_ttl_seconds, "默认配置下空闲超时应更早触发"
    shift_time(monkeypatch, idle + 60)

    response = client.get("/auth/me")
    assert response.status_code == 401
    assert sessions_of(engine, ADMIN_USERNAME)[0].revoked_reason == "expired"


def test_deactivating_user_kills_their_sessions_immediately(make_client):
    """T13：停用**立即生效**——下一次请求就 401，且全部会话被标记 deactivated。"""
    engine = make_client.engine
    client = make_client("analyst")
    assert client.get("/auth/me").json()["role"] == "analyst"

    with Session(engine) as session:
        user = session.exec(select(User).where(User.username == ANALYST_USERNAME)).first()
        user.is_active = False
        session.add(user)
        session.commit()

    assert client.get("/auth/me").status_code == 401
    assert client.get("/events").status_code == 401

    rows = sessions_of(engine, ANALYST_USERNAME)
    assert rows and all(row.revoked_reason == "deactivated" for row in rows)


def test_session_fixation_login_always_creates_a_new_session(anon_client, make_client):
    """T5：登录前塞进去的令牌，登录后必须彻底失效。"""
    engine = make_client.engine
    forged = "attacker-supplied-token-value"
    anon_client.cookies.set(SESSION_COOKIE, forged)

    response = anon_client.post(
        "/auth/login", json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}
    )
    assert response.status_code == 200
    issued = cookie_value(response, SESSION_COOKIE)
    assert issued is not None, "登录成功必须下发新的会话 Cookie"
    assert issued != forged, "登录必须新建会话，不能复用客户端带来的令牌"

    with Session(engine) as session:
        hashes = {row.token_hash for row in session.exec(select(UserSession)).all()}
    assert hash_session_token(forged) not in hashes


def test_logout_revokes_session_and_clears_cookies(make_client):
    engine = make_client.engine
    client = make_client("admin")
    assert client.get("/auth/me").status_code == 200

    response = client.post("/auth/logout")
    assert response.status_code == 204
    assert response.content == b""
    assert client.cookies.get(SESSION_COOKIE) is None

    assert client.get("/auth/me").status_code == 401
    rows = sessions_of(engine, ADMIN_USERNAME)
    assert rows[0].revoked_reason == "logout"


def test_logout_without_session_is_still_204(anon_client):
    """R1-5：统一约定 —— 未登录调用登出也返回 204（幂等），不是 401。"""
    first = anon_client.post("/auth/logout")
    second = anon_client.post("/auth/logout")
    assert first.status_code == second.status_code == 204


def test_change_password_revokes_every_session(make_client):
    """T6：改密后**全部**会话（含当前）失效，用户被迫重新登录。"""
    engine = make_client.engine
    first = make_client("admin")
    second = make_client("admin")  # 模拟"另一台设备"
    assert first.get("/auth/me").status_code == 200
    assert second.get("/auth/me").status_code == 200
    assert len(sessions_of(engine, ADMIN_USERNAME)) == 2

    response = first.post(
        "/auth/password",
        json={"old_password": ADMIN_PASSWORD, "new_password": NEW_ADMIN_PASSWORD},
    )
    assert response.status_code == 204, response.text
    assert first.cookies.get(SESSION_COOKIE) is None

    assert first.get("/auth/me").status_code == 401
    assert second.get("/auth/me").status_code == 401
    rows = sessions_of(engine, ADMIN_USERNAME)
    assert all(row.revoked_reason == "password_change" for row in rows)
    assert normalize_utc(user_row(engine, ADMIN_USERNAME).password_changed_at) >= normalize_utc(
        rows[0].created_at
    ) - timedelta(seconds=1)

    # 新密码可用、旧密码失效。
    # 注意：不能用 make_client 工厂 —— 它固定用账号的"初始口令"登录，
    # 而这里管理员口令已经被改掉了；直接开一台全新客户端更贴合真实场景。
    with closing(TestClient(app)) as fresh:
        assert (
            fresh.post(
                "/auth/login", json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}
            ).status_code
            == 401
        )
        assert (
            fresh.post(
                "/auth/login",
                json={"username": ADMIN_USERNAME, "password": NEW_ADMIN_PASSWORD},
            ).status_code
            == 200
        )
        assert fresh.get("/auth/me").status_code == 200


def test_change_password_requires_correct_old_password(make_client):
    client = make_client("admin")
    response = client.post(
        "/auth/password",
        json={"old_password": "not-the-old-password", "new_password": NEW_ADMIN_PASSWORD},
    )
    assert response.status_code == 403
    assert "原密码" in response.json()["detail"]
    assert client.get("/auth/me").status_code == 200  # 会话未被吊销


@pytest.mark.parametrize(
    "new_password",
    [
        "short",                      # 太短
        "cyberwatch-Admin-2026",      # 与原密码相同
        ADMIN_USERNAME + "",          # 与用户名相同
        "password1234",               # 命中弱口令表
        "x" * (MAX_PASSWORD_LENGTH + 1),  # 超长
    ],
)
def test_change_password_rejects_weak_or_invalid(make_client, new_password):
    client = make_client("admin")
    response = client.post(
        "/auth/password", json={"old_password": ADMIN_PASSWORD, "new_password": new_password}
    )
    assert response.status_code in (422,), response.text
    assert client.get("/auth/me").status_code == 200  # 口令未被改动，会话仍在


def test_expired_sessions_are_cleaned_opportunistically(make_client, monkeypatch):
    """T21：机会式清理会删掉 7 天前的失效会话行。"""
    engine = make_client.engine
    client = make_client("admin")
    client.post("/auth/logout")

    with Session(engine) as session:
        row = session.exec(select(UserSession)).first()
        row.revoked_at = utcnow() - timedelta(days=30)
        session.add(row)
        session.commit()

    auth_module._cleanup_state["last"] = 0.0  # 绕过"每小时最多一次"的节流
    shift_time(monkeypatch, 0)
    with Session(engine) as session:
        removed = auth_module.maybe_cleanup_sessions(session)
    assert removed == 1

    rows = sessions_of(engine, ADMIN_USERNAME)
    assert rows == []


# ===========================================================================
# 三、CSRF
# ===========================================================================
def test_csrf_missing_token_is_403(make_client):
    bare = make_client("admin", csrf=False)
    response = bare.post("/events", json={"title": "无 CSRF", "severity": "low"})
    assert response.status_code == 403
    assert response.json()["detail"] == "CSRF 校验失败"


def test_csrf_wrong_token_is_403(make_client):
    bare = make_client("admin", csrf=False)
    bare.headers[CSRF_HEADER] = "0" * 64
    assert bare.post("/events", json={"title": "错的 CSRF", "severity": "low"}).status_code == 403


def test_csrf_valid_token_passes(make_client):
    client = make_client("admin")
    response = client.post("/events", json={"title": "正确的 CSRF", "severity": "low"})
    assert response.status_code == 201, response.text


def test_get_does_not_require_csrf(make_client):
    bare = make_client("admin", csrf=False)
    assert bare.get("/events").status_code == 200
    assert bare.get("/auth/me").status_code == 200


def test_csrf_header_must_match_the_session_it_belongs_to(make_client):
    """两个客户端的 CSRF 令牌不能互换（服务端存的是**每个会话自己的**令牌）。"""
    first = make_client("admin")
    second = make_client("admin", csrf=False)
    stolen = first.cookies[CSRF_COOKIE]
    second.headers[CSRF_HEADER] = stolen
    assert second.post("/events", json={"title": "串令牌", "severity": "low"}).status_code == 403


# ===========================================================================
# 四、口令与哈希
# ===========================================================================
def test_password_hash_is_argon2id_and_salted():
    """T1：必须是 Argon2id，且同一口令两次哈希必须不同（随机盐）。"""
    first = hash_password(ADMIN_PASSWORD)
    second = hash_password(ADMIN_PASSWORD)
    assert first.startswith("$argon2id$v=19$m=65536,t=3,p=2$"), first
    assert first != second, "两次哈希相同说明没有随机盐"
    assert ADMIN_PASSWORD not in first
    assert verify_password(ADMIN_PASSWORD, first) is True
    assert verify_password(ADMIN_PASSWORD + "x", first) is False
    # 损坏的哈希不得抛异常，只返回 False（否则会变成 500 与信息泄露面）
    assert verify_password(ADMIN_PASSWORD, "not-a-hash") is False


def test_password_needs_rehash_detects_weaker_parameters():
    from argon2 import PasswordHasher, Type

    weak_hasher = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1, type=Type.ID)
    weak_hash = weak_hasher.hash(ADMIN_PASSWORD)
    assert password_needs_rehash(weak_hash) is True
    assert password_needs_rehash(hash_password(ADMIN_PASSWORD)) is False
    assert password_needs_rehash("garbage") is True


def test_login_silently_upgrades_outdated_hash(make_client):
    """登录成功时把低参数哈希静默升级（用户无感，且不吊销其它会话）。"""
    engine = make_client.engine
    from argon2 import PasswordHasher, Type

    weak_hash = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1, type=Type.ID).hash(
        ADMIN_PASSWORD
    )
    with Session(engine) as session:
        user = session.exec(select(User).where(User.username == ADMIN_USERNAME)).first()
        user.password_hash = weak_hash
        session.add(user)
        session.commit()

    client = make_client("admin", csrf=False)
    client.cookies.clear()
    assert client.post(
        "/auth/login", json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}
    ).status_code == 200

    upgraded_hash = user_row(engine, ADMIN_USERNAME).password_hash
    assert upgraded_hash != weak_hash
    assert password_needs_rehash(upgraded_hash) is False
    assert verify_password(ADMIN_PASSWORD, upgraded_hash) is True


@pytest.mark.parametrize(
    "password,username,ok",
    [
        ("x" * (MIN_PASSWORD_LENGTH - 1), "admin", False),
        ("x" * MIN_PASSWORD_LENGTH, "admin", True),
        ("admin", "admin", False),          # 等于用户名
        ("ADMIN", "admin", False),          # 忽略大小写后等于用户名
        ("password1234", "admin", False),   # 弱口令表
        ("x" * (MAX_PASSWORD_LENGTH + 1), "admin", False),
        ("", "admin", False),
    ],
)
def test_password_policy(password, username, ok):
    if ok:
        validate_password_strength(password, username)
    else:
        with pytest.raises(PasswordPolicyError):
            validate_password_strength(password, username)


# ===========================================================================
# 五、开放重定向与配置
# ===========================================================================
@pytest.mark.parametrize(
    "raw,expected",
    [
        (None, "/dashboard"),
        ("", "/dashboard"),
        ("/events", "/events"),
        ("/dashboard?x=1", "/dashboard?x=1"),
        ("//evil.example", "/dashboard"),
        ("https://evil.example", "/dashboard"),
        ("http://evil.example/x", "/dashboard"),
        ("/a\\b", "/dashboard"),
        ("javascript:alert(1)", "/dashboard"),
        ("/ok:1", "/dashboard"),
        ("\\\\evil", "/dashboard"),
    ],
)
def test_safe_next_path_blocks_open_redirect(raw, expected):
    """T15：只接受站内相对路径，其余一律回落 `/dashboard`。"""
    assert safe_next_path(raw) == expected


def test_dashboard_redirect_next_is_encoded(anon_client):
    response = anon_client.get(
        "/dashboard?a=1", follow_redirects=False, headers={"Accept": "text/html"}
    )
    assert response.status_code == 302
    assert response.headers["location"].startswith("/login?next=")


def test_auth_settings_are_loaded_without_warnings_in_development():
    """开发环境默认值：docs_mode=public、Cookie 非 Secure、无阻断性警告。"""
    assert AUTH_SETTINGS.environment == "development"
    assert AUTH_SETTINGS.docs_mode == "public"
    assert AUTH_SETTINGS.cookie_secure is False


# ===========================================================================
# 六、时间工具（会话过期判定依赖它们，所以要单独测）
# ===========================================================================
def test_seconds_since_handles_missing_and_naive_timestamps():
    """`seconds_since` 是会话闲置超时的唯一判据，边界必须先钉住。

    - ``None → +inf``：时间戳缺失时必须落进"已超时"，而不是被当成 0 秒
      （那等于"刚刚活动过"，会让失效的会话继续活着）；
    - naive 时间戳按 UTC 解释（SQLite 读回来的就是 naive）；
    - 未来时间戳返回负数、不做截断，调用方靠一次 `>` 比较即可，
      不需要再写分支（少一个分支就少一处不一致）。
    """
    now = utcnow()
    assert seconds_since(None, now=now) == float("inf")
    assert seconds_since(now, now=now) == pytest.approx(0, abs=0.01)

    naive_like_sqlite = (now - timedelta(seconds=90)).replace(tzinfo=None)
    assert seconds_since(naive_like_sqlite, now=now) == pytest.approx(90, abs=0.5)
    assert seconds_since(now + timedelta(seconds=30), now=now) < 0


@pytest.mark.parametrize(
    "seconds,expected",
    [
        (float("inf"), "未知（时间戳缺失）"),
        (0, "0 秒"),
        (-5, "0 秒"),
        (45, "45 秒"),
        (60, "1 分钟"),
        (125, "2 分钟 5 秒"),
        (3600, "1 小时"),
        (3900, "1 小时 5 分钟"),
    ],
)
def test_describe_duration_is_for_logs_only(seconds, expected):
    """`describe_duration` 只用于日志文本，**不参与任何 HTTP 响应**。

    它曾经被用在登录限流的 `Retry-After` 头里，那是一处账号枚举旁路，
    已经移除；这条用例顺带说明它现在的用途边界。
    """
    assert describe_duration(seconds) == expected
