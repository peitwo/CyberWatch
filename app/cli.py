"""命令行工具：首位管理员引导与账号救援（V0.5 新增）。

用法::

    python -m app.cli create-admin --username admin --display-name 管理员

**为什么管理员只能由 CLI 创建，而不是"首次启动自动建号"**：

1. 启动自动建号会**写库**，与项目"启动只做只读结构检查"的既有铁律冲突；
2. 会把密码塞进环境变量 / 默认值，容易在生产里留下弱口令；
3. CLI 是显式的、可审计的一次性动作，操作者必须主动敲命令。

退出码约定（可被脚本判断）：

======  ============================================
退出码  含义
======  ============================================
0       成功
1       业务失败（用户名已存在 / 密码不合规 / 参数非法）
2       环境未就绪（数据库缺表，需要先跑 alembic upgrade head）
======  ============================================

依赖方向：本模块只使用 `models` / `security` / `database` / `config`，
**不 import `app.auth` / `app.main`**，因此不会拉起 FastAPI 与路由。
"""
from __future__ import annotations

import argparse
import os
import sys

from sqlmodel import Session, select

from app.config import ADMIN_PASSWORD_ENV, DATABASE_URL_ENV, sqlite_file_path
from app.database import DATABASE_URL, engine
from app.models import Role, User, utcnow
from app.security import (
    MIN_PASSWORD_LENGTH,
    PasswordPolicyError,
    hash_password,
    validate_password_strength,
)

EXIT_OK = 0
EXIT_BUSINESS_ERROR = 1
EXIT_NOT_READY = 2

#: 本 CLI 依赖的表（缺任何一个都说明迁移没跑完）
REQUIRED_TABLES = ("event", "status_history", "app_user", "user_session")


class CliError(Exception):
    """带退出码的业务错误。"""

    def __init__(self, message: str, exit_code: int = EXIT_BUSINESS_ERROR) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def missing_schema(session: Session) -> list[str]:
    """只读地列出缺失的表（**绝不建表、绝不改库**）。"""
    rows = session.connection().exec_driver_sql(
        "select name from sqlite_master where type='table'"
    ).fetchall()
    existing = {row[0] for row in rows}
    return [name for name in REQUIRED_TABLES if name not in existing]


def _schema_guard(session: Session) -> None:
    missing = missing_schema(session)
    if not missing:
        return
    target = sqlite_file_path(DATABASE_URL)
    raise CliError(
        "数据库结构不是最新，缺少：" + "、".join(missing) + "\n"
        f"当前数据库：{target or DATABASE_URL}\n"
        "请先执行迁移，再重试本命令：\n"
        "    python -m alembic upgrade head\n"
        f"（如需改用其它数据库位置，请设置环境变量 {DATABASE_URL_ENV}）",
        EXIT_NOT_READY,
    )


def normalize_username(raw: str) -> str:
    """用户名统一小写存储与比较（避免 Admin / admin 被当成两个账号）。"""
    return raw.strip().lower()


def read_password(username: str, *, password_env: str | None) -> str:
    """取得管理员密码：优先环境变量（非交互），否则两次交互输入。

    无论哪条路径，都**不把密码写进任何日志或输出**。
    """
    from_env = False
    if password_env:
        candidate = os.environ.get(password_env)
        if candidate is None or candidate == "":
            raise CliError(f"环境变量 {password_env} 未设置或为空")
        password = candidate
        from_env = True
    else:
        import getpass

        password = getpass.getpass(f"请输入 {username} 的密码（至少 {MIN_PASSWORD_LENGTH} 位）：")
        again = getpass.getpass("请再输入一次以确认：")
        if password != again:
            raise CliError("两次输入的密码不一致")

    try:
        validate_password_strength(password, username)
    except PasswordPolicyError as exc:
        raise CliError(str(exc)) from exc
    if from_env:
        print(f"（密码来自环境变量 {password_env}，请在使用后立即清除该变量）")
    return password


def create_admin(
    session: Session,
    *,
    username: str,
    display_name: str | None,
    password: str,
    role: Role = Role.admin,
) -> User:
    """创建管理员账号并返回它。

    幂等性边界：**用户名已存在即拒绝**，绝不覆盖既有账号的密码 ——
    覆盖会变成一个危险的"后门"（拿到机器的人可以直接改掉管理员密码）。
    """
    normalized = normalize_username(username)
    if not normalized:
        raise CliError("用户名不能为空")
    if len(normalized) > 32:
        raise CliError("用户名过长：最多 32 位")

    existing = session.exec(select(User).where(User.username == normalized)).first()
    if existing is not None:
        raise CliError(f"用户名 {normalized} 已存在（id={existing.id}），未做任何修改")

    now = utcnow()
    user = User(
        username=normalized,
        password_hash=hash_password(password),
        role=role,
        is_active=True,
        created_at=now,
        password_changed_at=now,
        display_name=display_name,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def command_create_admin(args: argparse.Namespace) -> int:
    with Session(engine) as session:
        _schema_guard(session)
        password = read_password(args.username, password_env=args.password_env)
        user = create_admin(
            session,
            username=args.username,
            display_name=args.display_name,
            password=password,
        )
    # 只打印身份，**绝不打印密码或哈希**
    print(f"已创建管理员 {user.username}（id={user.id}）")
    print("提示：现在可以用它登录 /login ，或继续用本命令创建更多管理员。")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.cli",
        description="CyberWatch 命令行工具（账号引导与救援）",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create-admin", help="创建一位管理员账号")
    create.add_argument("--username", required=True, help="用户名（统一按小写存储）")
    create.add_argument("--display-name", default=None, help="界面显示名（可选，不参与鉴权）")
    create.add_argument(
        "--password-env",
        default=None,
        metavar="VAR",
        help=f"从环境变量读取密码（非交互；常用值 {ADMIN_PASSWORD_ENV}）",
    )
    create.set_defaults(func=command_create_admin)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except CliError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        print("\n已取消。", file=sys.stderr)
        return EXIT_BUSINESS_ERROR


if __name__ == "__main__":  # pragma: no cover - 由测试直接调用 main()
    sys.exit(main())
