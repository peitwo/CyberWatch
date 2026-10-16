"""数据库引擎与会话依赖（V0.5 新增）。

**为什么要把 engine 从 `app/main.py` 挪到这里**：
`app/auth.py` 的 `require()` / `get_current_user` 依赖需要 ``get_session``，
而 `app/main.py` 又需要 `app.auth` 里的认证路由与依赖。若 ``get_session``
仍留在 `main.py`，两边就会互相 import，形成循环导入（`ImportError`）。
把「引擎 + 会话」下沉到本模块，依赖方向变成单向：

    config → database → models → permissions → auth → main

本模块是**唯一**创建数据库引擎的地方。`app/main.py` 继续 re-export 这里的
``engine`` / ``get_session`` / ``SessionDep``，因此既有测试与
``migrations/env.py`` 的 ``from app.main import engine`` 无需改动。
"""
from __future__ import annotations

from typing import Annotated

from fastapi import Depends
from sqlmodel import Session, create_engine

from app.config import (
    enable_sqlite_foreign_keys,
    resolve_database_url,
)

#: 数据库 URL 由 app/config.py 统一解析（优先级：显式参数 > 环境变量 > 项目根绝对路径）。
#: 这样做的目的：让「应用连接的库」与「Alembic 迁移的库」永远是同一个，
#: 且默认路径基于项目根目录、不再随进程 cwd 漂移。
DATABASE_URL = resolve_database_url()

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
# 让 status_history.event_id → event.id 的外键**真实生效**（SQLite 默认不校验外键）
enable_sqlite_foreign_keys(engine)


def get_session():
    """每次请求一个独立会话；请求结束自动关闭。"""
    with Session(engine) as session:
        yield session


#: 路由里写 ``session: SessionDep`` 即可拿到会话（与 V0.4.2 用法完全一致）。
SessionDep = Annotated[Session, Depends(get_session)]
