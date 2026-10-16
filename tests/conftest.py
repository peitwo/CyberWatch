"""pytest 全局配置。

核心职责（按执行顺序）：

1. **在导入 ``app`` 之前**把数据库指向系统临时目录 —— 这是本阶段最重要的
   测试安全措施。pytest 收集测试模块之前会先导入同目录下的 ``conftest.py``，
   因此这里设置的 ``CYBERWATCH_DATABASE_URL`` 一定早于任何
   ``from app.main import ...`` 生效。效果：测试进程里 ``app.main`` 解析出的
   数据库 URL 永远指向系统临时目录，**任何自动化测试、探针或初始化流程都不可能
   连接真实的 cyberwatch.db**。
2. 提供共享的 ``client`` fixture（临时库 + 覆盖 ``get_session``），以及
   ``client_and_engine``（额外给出底层 engine，供直接查库断言持久化）。
   两个 fixture 都开启 ``PRAGMA foreign_keys=ON``，与生产行为一致。
3. **V0.5 起，``client`` / ``client_and_engine`` 默认「已以管理员登录」**，
   并自动为写方法带上 ``X-CSRF-Token``。这样 V0.4.2 的 141 条既有用例
   **一行都不用改**，同时它们顺带都在**真实认证链路**下运行。

关于 ``dependency_overrides`` 的纪律（V0.5 明确）：

    本文件覆盖的是 ``get_session`` —— **只把数据库指向临时库**，
    完全不触碰任何鉴权逻辑。**绝不**用它覆盖 ``get_current_user`` /
    ``require`` 之类的依赖去"绕过登录"制造测试通过的假象：
    那样得到的绿是假的，生产里认证一旦写错测试也发现不了。
    需要不同身份的客户端时，用 ``make_client("viewer")`` —— 它会走
    **真实的 ``POST /auth/login``** 拿到独立 Cookie 罐。

注意：``tests/test_events.py`` 自带一个同名的局部 ``client`` fixture，
按 pytest 的解析规则，模块内定义优先于 conftest。该文件已在 V0.5 同步改造
（R1-8 批准），给它自己的夹具补上了登录与 ``PRAGMA foreign_keys=ON``。
"""
from __future__ import annotations

import atexit
import os
import shutil
import tempfile
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# 1) 在任何 app 导入之前，把默认数据库重定向到系统临时目录
# ---------------------------------------------------------------------------
TEST_TEMP_ROOT = Path(tempfile.mkdtemp(prefix="cyberwatch-tests-"))
TEST_DATABASE_PATH = TEST_TEMP_ROOT / "cyberwatch-test.db"
os.environ["CYBERWATCH_DATABASE_URL"] = f"sqlite:///{TEST_DATABASE_PATH.as_posix()}"

atexit.register(lambda: shutil.rmtree(TEST_TEMP_ROOT, ignore_errors=True))

# ---------------------------------------------------------------------------
# 2) 环境变量就位之后，才允许导入 app
# ---------------------------------------------------------------------------
from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine  # noqa: E402

from app.auth import CSRF_COOKIE, CSRF_HEADER  # noqa: E402
from app.config import enable_sqlite_foreign_keys  # noqa: E402
from app.main import app, get_session  # noqa: E402
from app.models import Role, User  # noqa: E402
from app.security import hash_password  # noqa: E402

#: 测试账号（集中在这里定义，避免各测试文件各写一份口令）。
#: 口令都满足策略：>= 12 位、不是弱口令、不等于用户名。
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "cyberwatch-Admin-2026"
ANALYST_USERNAME = "analyst"
ANALYST_PASSWORD = "cyberwatch-Analyst-2026"
VIEWER_USERNAME = "viewer"
VIEWER_PASSWORD = "cyberwatch-Viewer-2026"
DISABLED_USERNAME = "retired"
DISABLED_PASSWORD = "cyberwatch-Retired-2026"

ACCOUNTS: dict[str, tuple[str, Role, bool]] = {
    ADMIN_USERNAME: (ADMIN_PASSWORD, Role.admin, True),
    ANALYST_USERNAME: (ANALYST_PASSWORD, Role.analyst, True),
    VIEWER_USERNAME: (VIEWER_PASSWORD, Role.viewer, True),
    # 一个"已停用"的账号，用于验证停用即时生效
    DISABLED_USERNAME: (DISABLED_PASSWORD, Role.viewer, False),
}

#: 全部账号（`make_client` 需要任意角色时用）
ALL_USERNAMES = tuple(ACCOUNTS)

#: 口令哈希缓存。
#: 单个 Argon2id 哈希实测约 66 ms；每个用例都要新建临时库（＝要重新播种账号），
#: 若不缓存，160 多个用例会白花几十秒在重复计算同一个口令的哈希上。
#: **只缓存测试账号**，不影响生产路径，也不影响 `test_auth.py` 里
#: "同一口令两次哈希结果不同"这类断言（那些用例直接调 `hash_password`）。
_HASH_CACHE: dict[tuple[str, str], str] = {}


def _cached_hash(username: str, password: str) -> str:
    key = (username, password)
    if key not in _HASH_CACHE:
        _HASH_CACHE[key] = hash_password(password)
    return _HASH_CACHE[key]


def is_within_tempdir(path: os.PathLike[str] | str) -> bool:
    """判断路径是否位于系统临时目录内（Windows 路径大小写不敏感）。"""
    resolved = Path(path).resolve()
    temp_root = Path(tempfile.gettempdir()).resolve()
    return os.path.normcase(str(resolved)).startswith(os.path.normcase(str(temp_root)))


def seed_accounts(engine, usernames=ALL_USERNAMES) -> dict[str, User]:
    """在临时库里建出测试账号（用真实哈希，走真实模型）。"""
    created: dict[str, User] = {}
    with Session(engine) as session:
        for username in usernames:
            password, role, is_active = ACCOUNTS[username]
            user = User(
                username=username,
                password_hash=_cached_hash(username, password),
                role=role,
                is_active=is_active,
                display_name=None,
            )
            session.add(user)
        session.commit()
        for username in usernames:
            row = session.exec(
                __import__("sqlmodel").select(User).where(User.username == username)
            ).first()
            if row is not None:
                session.refresh(row)
                created[username] = row
    return created


def login(
    client: TestClient,
    username: str = ADMIN_USERNAME,
    password: str | None = None,
    *,
    with_csrf: bool = True,
):
    """走**真实** ``POST /auth/login`` 建立会话。

    ``with_csrf=True``（默认）顺便把 ``X-CSRF-Token`` 设为该客户端的默认请求头，
    这样调用方写 ``client.post(...)`` 时不必每次手动带头。
    """
    secret = password if password is not None else ACCOUNTS[username][0]
    response = client.post("/auth/login", json={"username": username, "password": secret})
    assert response.status_code == 200, f"测试登录失败：{response.status_code} {response.text}"
    if with_csrf:
        client.headers[CSRF_HEADER] = client.cookies.get(CSRF_COOKIE, "")
    return response


@contextmanager
def _temporary_app(seed: tuple[str, ...] = (ADMIN_USERNAME,)):
    """建一个「临时库支撑的 TestClient + 底层 engine」的上下文。

    - 数据库文件永远落在系统临时目录，不会碰到真实 ``cyberwatch.db``；
    - 与生产一致地开启 ``PRAGMA foreign_keys=ON``，保证外键约束在测试里也真实生效；
    - 默认只播种管理员（既省时间，也符合"V0.5.1 库里只有管理员"的现实）；
      需要其它角色时传 ``seed=ALL_USERNAMES``；
    - 不进入 TestClient 的上下文管理器（那会运行应用 lifespan）。
    """
    with tempfile.TemporaryDirectory(prefix="cyberwatch-client-") as temp:
        db = Path(temp) / "test.db"
        test_engine = create_engine(
            f"sqlite:///{db}", connect_args={"check_same_thread": False}
        )
        enable_sqlite_foreign_keys(test_engine)
        SQLModel.metadata.create_all(test_engine)
        seed_accounts(test_engine, seed)

        def override_session():
            with Session(test_engine) as session:
                yield session

        app.dependency_overrides[get_session] = override_session
        try:
            with closing(TestClient(app)) as test_client:
                yield test_client, test_engine
        finally:
            app.dependency_overrides.pop(get_session, None)
            # 必须在 TemporaryDirectory 删除 test.db *之前* 释放连接池，
            # 否则 Windows 会抛 WinError 32。
            test_engine.dispose()


@pytest.fixture(scope="session")
def test_temp_root() -> Path:
    """本轮所有测试用的临时目录根。"""
    return TEST_TEMP_ROOT


@dataclass
class AppStack:
    """一个测试用例的「临时库支撑的客户端 + 它背后的 engine」。"""

    client: TestClient
    engine: object  # sqlalchemy Engine；避免为了一个类型注解多引一个 import


@pytest.fixture(scope="session")
def in_tempdir():
    """返回「路径是否位于系统临时目录内」的判断函数，供迁移/隔离断言复用。"""
    return is_within_tempdir


@pytest.fixture
def app_stack():
    """一个**每用例唯一**的「临时库 + 已登录客户端 + engine」三元组。

    为什么需要它（V0.5 引入鉴权后暴露出来的夹具耦合）：

    V0.4.2 时 ``client`` 与 ``client_and_engine`` 各自 ``_temporary_app()``，
    也就是**两个独立的临时库**。当时没有任何鉴权，测试把请求发给哪个库都能跑通，
    而且断言只看"同一个库里的数据是否一致"，所以一直没暴露问题。

    V0.5 加上服务端会话后，这条隐式耦合变成了硬错误：``client`` 在库 A 上登录，
    而 ``client_and_engine`` 一执行就把 ``app.dependency_overrides[get_session]``
    换成了库 B —— 于是 ``client`` 后续请求带着库 A 的会话令牌去查库 B，
    必然 401（实测：``test_status_history.py`` / ``test_restore.py`` 共 17 条用例）。

    修法不是给测试打补丁，而是让这两个 fixture **共享同一个栈**：
    同一个临时库、同一个 ``TestClient``、同一套 Cookie。
    这样 141 条既有断言一行都不用改，而且"两个夹具指向同一份数据"本来就
    是它们被写出来时想要的语义。
    """
    with _temporary_app() as (test_client, engine):
        login(test_client)
        yield AppStack(test_client, engine)


@pytest.fixture
def anon_client():
    """**未登录**的裸客户端：用于验证 401 / 302 / CSRF 等"没有会话"的行为。"""
    with _temporary_app() as (test_client, _engine):
        yield test_client


@pytest.fixture
def client(app_stack):
    """一个由临时数据库支撑、**已以管理员登录**的测试客户端。

    变化说明（V0.5）：V0.4.2 时它是个没有身份的裸客户端；现在它走真实登录。
    这样既有的 141 条用例无需改动，却又全部运行在真实认证链路上。
    """
    return app_stack.client


@pytest.fixture
def client_and_engine(app_stack):
    """同时给出（已登录管理员的）TestClient 与它背后的 engine。

    供「先用 API 改数据、再直接查库断言持久化结果」的用例使用 ——
    直接查库比只看响应更能证明数据真的落盘（例如软删除后行仍在、
    以及审计记录确实写进去了）。

    **与 ``client`` 共享同一个临时库**（见 ``app_stack``），
    否则"通过 API 写入、直接查库读出"会读到两个不同的库。
    """
    return app_stack.client, app_stack.engine


@pytest.fixture
def make_client():
    """工厂：``make_client("viewer")`` → 一个**独立 Cookie 罐**的已登录客户端。

    - 会先播种全部测试账号（admin / analyst / viewer / retired）；
    - 登录走真实 ``/auth/login``，**不经过任何 dependency_overrides**；
    - ``csrf=False`` 返回"已登录但不带 CSRF 头"的客户端，用于验证写方法必须带 CSRF。

    用完记得让 fixture 收尾关闭客户端，避免连接泄漏。
    """
    created: list[TestClient] = []
    with _temporary_app(seed=ALL_USERNAMES) as (_default_client, engine):
        def factory(role: str = "admin", *, csrf: bool = True) -> TestClient:
            username = _username_for(role)
            client = TestClient(app)
            created.append(client)
            login(client, username, with_csrf=csrf)
            return client

        #: 暴露底层 engine，便于少数用例直接改库
        #: （例如"把账号停用后旧会话必须立刻失效"）。
        factory.engine = engine  # type: ignore[attr-defined]
        try:
            yield factory
        finally:
            for client in created:
                client.close()


def _username_for(role: str) -> str:
    """把 ``"admin"`` / ``"analyst"`` / ``"viewer"`` / ``"retired"`` 映射到测试账号名。"""
    if role == "retired":
        return DISABLED_USERNAME
    if role in ACCOUNTS:
        return role
    raise KeyError(
        f"未知的测试角色 {role!r}；可用：admin / analyst / viewer / retired，或直接写用户名"
    )


@pytest.fixture
def seeded_users():
    """建出全部测试账号并返回 ``username -> User`` 映射（供直接查库断言）。"""
    with _temporary_app(seed=ALL_USERNAMES) as (_client, engine):
        with Session(engine) as session:
            rows = session.exec(__import__("sqlmodel").select(User)).all()
            yield {row.username: row for row in rows}


def pytest_report_header(config: object) -> str:
    return f"CyberWatch 测试数据库（系统临时目录）: {TEST_DATABASE_PATH}"
