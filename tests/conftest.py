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

注意：``tests/test_events.py`` 自带一个同名的局部 ``client`` fixture，
按 pytest 的解析规则，模块内定义优先于 conftest，所以那个文件保持原样即可。
"""
from __future__ import annotations

import atexit
import os
import shutil
import tempfile
from contextlib import closing, contextmanager
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

from app.config import enable_sqlite_foreign_keys  # noqa: E402
from app.main import app, get_session  # noqa: E402


def is_within_tempdir(path: os.PathLike[str] | str) -> bool:
    """判断路径是否位于系统临时目录内（Windows 路径大小写不敏感）。"""
    resolved = Path(path).resolve()
    temp_root = Path(tempfile.gettempdir()).resolve()
    return os.path.normcase(str(resolved)).startswith(os.path.normcase(str(temp_root)))


@contextmanager
def _temporary_app():
    """建一个「临时库支撑的 TestClient + 底层 engine」的上下文。

    - 数据库文件永远落在系统临时目录，不会碰到真实 ``cyberwatch.db``；
    - 与生产一致地开启 ``PRAGMA foreign_keys=ON``，保证外键约束在测试里也真实生效；
    - 不进入 TestClient 的上下文管理器（那会运行应用 lifespan）。
    """
    with tempfile.TemporaryDirectory(prefix="cyberwatch-client-") as temp:
        db = Path(temp) / "test.db"
        test_engine = create_engine(
            f"sqlite:///{db}", connect_args={"check_same_thread": False}
        )
        enable_sqlite_foreign_keys(test_engine)
        SQLModel.metadata.create_all(test_engine)

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


@pytest.fixture(scope="session")
def in_tempdir():
    """返回「路径是否位于系统临时目录内」的判断函数，供迁移/隔离断言复用。"""
    return is_within_tempdir


@pytest.fixture
def client():
    """一个由临时数据库支撑的测试客户端，永远不连应用的真实数据库。"""
    with _temporary_app() as (test_client, _engine):
        yield test_client


@pytest.fixture
def client_and_engine():
    """同时给出 TestClient 与它背后的 engine。

    供「先用 API 改数据、再直接查库断言持久化结果」的用例使用 ——
    直接查库比只看响应更能证明数据真的落盘（例如软删除后行仍在、
    以及审计记录确实写进去了）。
    """
    with _temporary_app() as (test_client, test_engine):
        yield test_client, test_engine


def pytest_report_header(config: object) -> str:
    return f"CyberWatch 测试数据库（系统临时目录）: {TEST_DATABASE_PATH}"
