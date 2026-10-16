"""`python -m app.cli create-admin` 的测试（V0.5.1 / 评审意见 R1-6）。

为什么用**子进程**而不是在进程内调 `main()`：

1. CLI 的价值在于"从零到能登录"这条**完整链路** —— 建库 → 迁移 → 建号 →
   用建出来的号登录。只有真起一个进程，才能证明 `alembic`、`app.cli`、
   `app.security` 三者用的确实是同一个 ``CYBERWATCH_DATABASE_URL``；
2. 退出码是 CLI 的对外契约（脚本要靠它判断），进程内调用很容易漏掉
   `sys.exit` 路径；
3. 顺带验证"绝不打印密码"这一条 —— 捕获真实的 stdout/stderr 才算数。

安全约定：
- 每个用例的库都在 ``tmp_path``（系统临时目录）里，**绝不碰真实 cyberwatch.db**；
- 子进程环境里显式覆盖 ``CYBERWATCH_DATABASE_URL``，不继承外层的测试库，
  这样 CLI 用例彼此之间也不会互相干扰。
"""
from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from app.config import ADMIN_PASSWORD_ENV, BASE_DIR, DATABASE_URL_ENV
from app.security import verify_password

CLI_TIMEOUT = 120
ADMIN_NAME = "cli-admin"
ADMIN_SECRET = "cli-Admin-Secret-2026"


# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------
def run_python(args: list[str], db: Path, extra_env: dict[str, str | None] | None = None):
    """在仓库根目录下跑一个子进程，库指向 ``db``。"""
    env = os.environ.copy()
    env[DATABASE_URL_ENV] = f"sqlite:///{db.as_posix()}"
    env.pop(ADMIN_PASSWORD_ENV, None)
    for key, value in (extra_env or {}).items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    return subprocess.run(
        [sys.executable, *args],
        cwd=str(BASE_DIR),
        env=env,
        capture_output=True,
        text=True,
        timeout=CLI_TIMEOUT,
    )


def migrate(db: Path) -> subprocess.CompletedProcess:
    return run_python(["-m", "alembic", "upgrade", "head"], db)


def create_admin(
    db: Path, *, username: str = ADMIN_NAME, secret: str | None = ADMIN_SECRET,
    password_env: str | None = ADMIN_PASSWORD_ENV, display_name: str | None = None,
):
    args = ["-m", "app.cli", "create-admin", "--username", username]
    if display_name:
        args += ["--display-name", display_name]
    if password_env:
        args += ["--password-env", password_env]
    return run_python(
        args, db, extra_env={password_env: secret} if password_env and secret else None
    )


def user_rows(db: Path) -> list[tuple]:
    con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
    try:
        return list(
            con.execute(
                "select username, password_hash, role, is_active, display_name from app_user"
            )
        )
    finally:
        con.close()


def assert_in_tempdir(db: Path, in_tempdir) -> None:
    assert in_tempdir(db), f"CLI 测试用到了非临时目录：{db}"
    assert db.resolve() != (BASE_DIR / "cyberwatch.db").resolve()


@pytest.fixture
def migrated_db(tmp_path, in_tempdir) -> Path:
    """一个已经跑到 head 的空库（每个用例独立）。"""
    db = tmp_path / "cli.db"
    assert_in_tempdir(db, in_tempdir)
    result = migrate(db)
    assert result.returncode == 0, f"迁移失败：{result.stdout}\n{result.stderr}"
    return db


# ---------------------------------------------------------------------------
# 1) 成功路径：从空库到「能登录的账号」
# ---------------------------------------------------------------------------
def test_create_admin_succeeds_and_reports_identity_only(migrated_db):
    result = create_admin(migrated_db, display_name="命令行管理员")

    assert result.returncode == 0, f"{result.stdout}\n{result.stderr}"
    output = result.stdout + result.stderr

    # 只报身份，不报秘密
    assert ADMIN_NAME in output
    assert ADMIN_SECRET not in output, "CLI 把密码打印出来了"
    assert "$argon2" not in output, "CLI 把哈希打印出来了"

    rows = user_rows(migrated_db)
    assert len(rows) == 1
    username, password_hash, role, is_active, display_name = rows[0]
    assert username == ADMIN_NAME
    assert role == "admin"
    assert is_active == 1
    assert display_name == "命令行管理员"

    # 存的必须是**可校验的 Argon2id 哈希**，不是明文、也不是别的算法
    assert password_hash.startswith("$argon2id$")
    assert verify_password(ADMIN_SECRET, password_hash)
    assert not verify_password(ADMIN_SECRET + "x", password_hash)


def test_create_admin_normalizes_username_to_lowercase(migrated_db):
    result = create_admin(migrated_db, username="  CLI-Admin  ")
    assert result.returncode == 0, result.stderr
    assert [row[0] for row in user_rows(migrated_db)] == ["cli-admin"]


def test_create_admin_created_account_can_actually_log_in(migrated_db):
    """真正的验收动作：用 CLI 建的号，走真实 ``POST /auth/login``。

    这是需求 6「初始化管理员 + 首次启动完整流程」的自动化版本 ——
    "能建出来"不是终点，"建出来的号能登录进 dashboard"才是。
    """
    from contextlib import closing

    from fastapi.testclient import TestClient
    from sqlmodel import Session, create_engine

    from app.config import enable_sqlite_foreign_keys
    from app.main import app, get_session

    assert create_admin(migrated_db).returncode == 0

    engine = create_engine(
        f"sqlite:///{migrated_db.as_posix()}", connect_args={"check_same_thread": False}
    )
    enable_sqlite_foreign_keys(engine)

    def override_session():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = override_session
    try:
        with closing(TestClient(app)) as client:
            response = client.post(
                "/auth/login", json={"username": ADMIN_NAME, "password": ADMIN_SECRET}
            )
            assert response.status_code == 200, response.text
            assert response.json()["role"] == "admin"
            assert client.get("/dashboard", follow_redirects=False).status_code == 200
    finally:
        app.dependency_overrides.pop(get_session, None)
        engine.dispose()


# ---------------------------------------------------------------------------
# 2) 业务失败：退出码 1
# ---------------------------------------------------------------------------
def test_duplicate_username_is_rejected_without_touching_the_account(migrated_db):
    assert create_admin(migrated_db).returncode == 0

    second = create_admin(migrated_db, secret="another-Strong-Secret-2026")
    assert second.returncode == 1, f"{second.stdout}\n{second.stderr}"
    assert "已存在" in (second.stdout + second.stderr)
    assert ADMIN_SECRET not in (second.stdout + second.stderr)

    # 关键：既有账号的密码**没有被覆盖**（否则 CLI 就成了后门）
    rows = user_rows(migrated_db)
    assert len(rows) == 1
    assert verify_password(ADMIN_SECRET, rows[0][1]), "重复创建时把原密码改掉了"
    assert not verify_password("another-Strong-Secret-2026", rows[0][1])


@pytest.mark.parametrize(
    "secret",
    [
        "short",                 # 太短
        ADMIN_NAME,              # 与用户名相同
        "password1234",          # 命中弱口令表
    ],
)
def test_weak_password_is_rejected(migrated_db, secret):
    result = create_admin(migrated_db, secret=secret)
    assert result.returncode == 1, f"{result.stdout}\n{result.stderr}"
    assert user_rows(migrated_db) == [], "口令不合规却仍然建了账号"


def test_missing_password_env_is_a_business_error(migrated_db):
    result = run_python(
        ["-m", "app.cli", "create-admin", "--username", ADMIN_NAME,
         "--password-env", ADMIN_PASSWORD_ENV],
        migrated_db,
        extra_env={ADMIN_PASSWORD_ENV: None},
    )
    assert result.returncode == 1
    assert ADMIN_PASSWORD_ENV in (result.stdout + result.stderr)
    assert user_rows(migrated_db) == []


def test_username_too_long_is_rejected(migrated_db):
    result = create_admin(migrated_db, username="u" * 33)
    assert result.returncode == 1
    assert "过长" in (result.stdout + result.stderr)
    assert user_rows(migrated_db) == []


# ---------------------------------------------------------------------------
# 3) 环境未就绪：退出码 2（且绝不"顺手建表"）
# ---------------------------------------------------------------------------
def test_unmigrated_database_exits_with_code_2(tmp_path, in_tempdir):
    db = tmp_path / "not-migrated.db"
    assert_in_tempdir(db, in_tempdir)
    sqlite3.connect(str(db)).close()  # 空库：连表都没有

    result = create_admin(db)

    assert result.returncode == 2, f"退出码应为 2，实际 {result.returncode}"
    output = result.stdout + result.stderr
    assert "app_user" in output and "alembic" in output.lower()
    # 只读检查：不得因为缺表就自己 create_all
    con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
    try:
        tables = [row[0] for row in con.execute("select name from sqlite_master where type='table'")]
    finally:
        con.close()
    assert tables == [], f"CLI 在未迁移的库上建了表：{tables}"


def test_partially_migrated_database_exits_with_code_2(tmp_path, in_tempdir):
    """只跑到 0004（没有 app_user / user_session）→ 同样必须拒绝。"""
    db = tmp_path / "old-head.db"
    assert_in_tempdir(db, in_tempdir)
    assert run_python(["-m", "alembic", "upgrade", "0004"], db).returncode == 0

    result = create_admin(db)

    assert result.returncode == 2, f"{result.stdout}\n{result.stderr}"
    output = result.stdout + result.stderr
    assert "app_user" in output and "user_session" in output
