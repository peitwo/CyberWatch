"""数据库 URL 解析与测试隔离的回归测试（需求：统一解析逻辑 + 明确优先级）。

本文件先于实现存在（TDD 红灯）：它描述的是「修复后应该成立的行为」。
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from app import config
from app.main import DATABASE_URL, engine


# ---------------------------------------------------------------------------
# 1) 默认路径：项目根目录下的绝对路径，且与进程 cwd 无关
# ---------------------------------------------------------------------------
def test_default_database_url_is_project_root_absolute(monkeypatch):
    """默认库 = <项目根>/cyberwatch.db 的绝对路径，不再是相对 cwd 的 ./xxx.db。"""
    monkeypatch.delenv(config.DATABASE_URL_ENV, raising=False)
    url = config.resolve_database_url()

    assert url.startswith("sqlite:///"), url
    path = Path(url[len("sqlite:///"):])
    assert path.is_absolute(), f"默认路径必须绝对：{path}"
    assert path == config.BASE_DIR / "cyberwatch.db"


def test_default_database_url_does_not_depend_on_cwd(monkeypatch, tmp_path):
    """切换 cwd 后默认路径必须完全不变（这是修复前会失败的场景）。"""
    monkeypatch.delenv(config.DATABASE_URL_ENV, raising=False)
    before = config.resolve_database_url()
    monkeypatch.chdir(tmp_path)
    after = config.resolve_database_url()
    assert before == after


def test_cwd_never_produces_a_second_database_file(monkeypatch, tmp_path):
    """在别的目录下解析，也不能冒出第二个 cyberwatch.db（避免双库分叉）。"""
    monkeypatch.delenv(config.DATABASE_URL_ENV, raising=False)
    monkeypatch.chdir(tmp_path)
    path = Path(config.resolve_database_url()[len("sqlite:///"):])
    assert path.parent == config.BASE_DIR
    assert path.exists() or path == config.BASE_DIR / "cyberwatch.db"


# ---------------------------------------------------------------------------
# 2) 优先级：显式参数 > 环境变量 > 项目默认
# ---------------------------------------------------------------------------
def test_env_var_overrides_default(monkeypatch, tmp_path):
    override = tmp_path / "override.db"
    monkeypatch.setenv(config.DATABASE_URL_ENV, f"sqlite:///{override.as_posix()}")
    assert config.resolve_database_url() == f"sqlite:///{override.as_posix()}"


def test_explicit_argument_beats_env_var(monkeypatch, tmp_path):
    """显式传入的 URL 优先级最高，绝不能被环境变量覆盖（Alembic 覆盖事故的根因）。"""
    env_db = tmp_path / "from-env.db"
    explicit_db = tmp_path / "from-caller.db"
    monkeypatch.setenv(config.DATABASE_URL_ENV, f"sqlite:///{env_db.as_posix()}")

    resolved = config.resolve_database_url(explicit=f"sqlite:///{explicit_db.as_posix()}")
    assert resolved == f"sqlite:///{explicit_db.as_posix()}"
    assert "from-env" not in resolved


def test_blank_values_fall_through(monkeypatch, tmp_path):
    """空白字符串视为「未设置」，继续走下一优先级。"""
    monkeypatch.setenv(config.DATABASE_URL_ENV, "   ")
    monkeypatch.chdir(tmp_path)
    assert config.resolve_database_url() == config.default_database_url()
    monkeypatch.setenv(config.DATABASE_URL_ENV, f"sqlite:///{(tmp_path / 'x.db').as_posix()}")
    assert config.resolve_database_url(explicit="  ") == f"sqlite:///{(tmp_path / 'x.db').as_posix()}"


# ---------------------------------------------------------------------------
# 3) 测试隔离：导入 app 的默认引擎必须落在系统临时目录
# ---------------------------------------------------------------------------
def test_app_database_url_points_into_system_tempdir(in_tempdir):
    """conftest 已把 URL 指向临时目录，应用默认引擎绝不能指向真实库。"""
    path = Path(DATABASE_URL[len("sqlite:///"):])
    assert in_tempdir(path), f"默认引擎指向了非临时目录：{path}"
    assert path != config.BASE_DIR / "cyberwatch.db"


def test_app_engine_url_points_into_system_tempdir(in_tempdir):
    assert engine.url.get_backend_name() == "sqlite"
    assert in_tempdir(str(engine.url.database))


def test_real_database_file_is_never_the_default_target(in_tempdir):
    """真实库路径必须与测试进程使用的默认库路径不同。"""
    real = (config.BASE_DIR / "cyberwatch.db").resolve()
    used = Path(str(engine.url.database)).resolve()
    assert real != used
    assert in_tempdir(used)
