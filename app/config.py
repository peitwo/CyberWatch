"""项目路径与数据库 URL 的集中解析（单一真相来源）。

本模块被 ``app/main.py``（应用运行时）与 ``migrations/env.py``（Alembic 迁移）
**共同导入**，从而保证「应用连接的库」和「迁移改动的库」永远是同一个，
杜绝「服务连 A 库、迁移改 B 库」这类最难排查的事故。

V0.5 追加：认证相关配置（``AuthSettings``）。它同样遵守「单一真相来源」——
所有认证行为的**取值**只能从这里来，业务模块不得自己读 ``os.environ``。
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import Engine, event

# app/config.py -> app/ -> cyberwatch-starter/
BASE_DIR = Path(__file__).resolve().parent.parent

#: 显式覆盖数据库位置的环境变量（供测试与未来部署使用）
DATABASE_URL_ENV = "CYBERWATCH_DATABASE_URL"

#: 默认数据库文件：项目根目录下的绝对路径，与进程当前工作目录无关
DEFAULT_DATABASE_PATH = BASE_DIR / "cyberwatch.db"


def default_database_url() -> str:
    """默认数据库 URL（`<项目根>/cyberwatch.db` 的绝对路径）。"""
    return f"sqlite:///{DEFAULT_DATABASE_PATH.as_posix()}"


def resolve_database_url(explicit: str | None = None) -> str:
    """按**明确优先级**解析数据库 URL。

    优先级（高 → 低）：

    1. ``explicit`` —— 调用方显式传入的 URL。测试与程序化调用（如 Alembic 的
       ``Config``）用它指向临时库；**它绝不允许被下面的环境变量或默认值覆盖**。
    2. 环境变量 ``CYBERWATCH_DATABASE_URL`` —— 供测试与未来部署覆盖数据库位置。
    3. 项目根目录下的 ``cyberwatch.db``（绝对路径）。

    空白字符串视为「未设置」，继续向下传递。
    """
    if explicit is not None and explicit.strip():
        return explicit.strip()
    override = os.environ.get(DATABASE_URL_ENV)
    if override is not None and override.strip():
        return override.strip()
    return default_database_url()


def sqlite_file_path(url: str) -> Path | None:
    """从 SQLite URL 中取出文件路径；非 SQLite 或内存库返回 ``None``。"""
    prefix = "sqlite:///"
    if not url.startswith(prefix):
        return None
    raw = url[len(prefix):]
    if not raw or raw.startswith(":memory:"):
        return None
    return Path(raw)


def enable_sqlite_foreign_keys(engine: Engine) -> None:
    """让 SQLite 引擎**真正强制**外键约束。

    背景：SQLite 出于向后兼容，默认 **不** 校验外键。``PRAGMA foreign_keys``
    是「按连接」生效的开关，因此必须在**每次新建连接**时打开，
    而不是在引擎上设置一次。

    做法：给引擎挂一个 ``connect`` 事件监听器，SQLAlchemy 每次从连接池
    新建底层连接时都会执行 ``PRAGMA foreign_keys=ON``。

    这样 ``status_history.event_id`` 对 ``event.id`` 的外键才是**真实生效**的约束，
    而不是只写在 DDL 里的装饰。非 SQLite 后端直接跳过（PostgreSQL 等默认就强制）。
    """
    if engine.url.get_backend_name() != "sqlite":
        return

    @event.listens_for(engine, "connect")
    def _set_sqlite_foreign_keys(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()


# ---------------------------------------------------------------------------
# V0.5：认证与部署配置（AuthSettings）
# ---------------------------------------------------------------------------
ENV_VAR = "CYBERWATCH_ENV"
COOKIE_SECURE_ENV = "CYBERWATCH_COOKIE_SECURE"
SESSION_TTL_ENV = "CYBERWATCH_SESSION_TTL_HOURS"
SESSION_IDLE_ENV = "CYBERWATCH_SESSION_IDLE_MINUTES"
COOKIE_NAME_ENV = "CYBERWATCH_COOKIE_NAME"
DOCS_MODE_ENV = "CYBERWATCH_DOCS_MODE"
ALLOW_PUBLIC_DOCS_ENV = "CYBERWATCH_ALLOW_PUBLIC_DOCS"
TRUST_PROXY_ENV = "CYBERWATCH_TRUST_PROXY"
TRUSTED_PROXY_CIDRS_ENV = "CYBERWATCH_TRUSTED_PROXY_CIDRS"
ADMIN_PASSWORD_ENV = "CYBERWATCH_ADMIN_PASSWORD"

#: 合法环境名
ENVIRONMENTS = ("development", "production")
#: 合法 docs 模式
DOCS_MODES = ("admin", "public", "disabled")


class ConfigError(RuntimeError):
    """配置非法。**启动阶段**抛出即为「拒绝启动」，避免带病运行。"""


def _read_bool(raw: str | None) -> bool | None:
    """把 ``1/true/yes/on`` 解析为 True，``0/false/no/off`` 解析为 False。

    返回 ``None`` 表示「未设置」。非法值抛 :class:`ConfigError`
    （宁可启动失败，也不要静默按 False 处理 —— 那可能让生产跑出明文会话）。
    """
    if raw is None:
        return None
    value = raw.strip().lower()
    if value == "":
        return None
    if value in ("1", "true", "yes", "on"):
        return True
    if value in ("0", "false", "no", "off"):
        return False
    raise ConfigError(
        f"布尔配置值无法识别：{raw!r}（可用 1/0、true/false、yes/no、on/off）"
    )


def _read_positive_int(raw: str | None, *, name: str, default: int) -> int:
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw.strip())
    except ValueError as exc:
        raise ConfigError(f"{name} 必须是整数，收到 {raw!r}") from exc
    if value <= 0:
        raise ConfigError(f"{name} 必须大于 0，收到 {value}")
    return value


@dataclass(frozen=True)
class AuthSettings:
    """认证与部署配置的**不可变快照**。

    取值规则：调用方传入的 ``env`` 优先，其次读 ``os.environ``（便于测试注入），
    最后回落默认值。所有校验在构造时一次性完成 —— 生产配置错误会在
    **导入 `app.main` 时**就以中文消息拒绝启动，而不是等第一个请求进来才炸。
    """

    environment: str
    cookie_secure: bool
    cookie_name: str
    session_ttl_hours: int
    session_idle_minutes: int
    docs_mode: str
    trust_proxy: bool
    trusted_proxy_cidrs: tuple[str, ...]
    warnings: tuple[str, ...] = ()

    # -- 便捷属性 -----------------------------------------------------------
    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def session_ttl_seconds(self) -> int:
        return self.session_ttl_hours * 3600

    @property
    def session_idle_seconds(self) -> int:
        return self.session_idle_minutes * 60

    def describe(self) -> str:
        """打印用摘要。**绝不含任何密钥或密码。**"""
        return (
            f"environment={self.environment} "
            f"docs_mode={self.docs_mode} "
            f"cookie_name={self.cookie_name} "
            f"cookie_secure={self.cookie_secure} "
            f"session_ttl={self.session_ttl_hours}h "
            f"session_idle={self.session_idle_minutes}m "
            f"trust_proxy={self.trust_proxy}"
            + (f" trusted_proxy_cidrs={','.join(self.trusted_proxy_cidrs)}"
               if self.trusted_proxy_cidrs else "")
        )


def load_auth_settings(environ: dict[str, str] | None = None) -> AuthSettings:
    """解析并校验认证配置。

    ``environ`` 为 ``None`` 时读真实环境变量；测试可传入字典做纯函数式校验。

    校验规则（「拒绝启动」清单，见设计文档 §2.9）：

    1. ``CYBERWATCH_ENV`` 只接受 ``development`` / ``production``
    2. ``production`` 下 ``cookie_secure=false`` → 拒绝（明文网络传会话）
    3. ``production`` 下 ``docs_mode=public`` 必须附带 ``ALLOW_PUBLIC_DOCS=1`` → 否则拒绝
    4. ``session_ttl_hours`` / ``session_idle_minutes`` 必须是正整数
    5. ``trust_proxy=true`` 必须同时给出非空 ``trusted_proxy_cidrs`` → 否则拒绝
    6. 其余情况只产生 ``warnings``（不阻断启动）
    """
    env = os.environ if environ is None else environ
    warnings: list[str] = []

    environment = (env.get(ENV_VAR) or "development").strip().lower()
    if environment not in ENVIRONMENTS:
        raise ConfigError(
            f"{ENV_VAR} 只能是 {' 或 '.join(ENVIRONMENTS)}，收到 {environment!r}"
        )
    production = environment == "production"

    cookie_secure_explicit = _read_bool(env.get(COOKIE_SECURE_ENV))
    if production and cookie_secure_explicit is False:
        raise ConfigError(
            f"{ENV_VAR}=production 时不允许把 {COOKIE_SECURE_ENV} 显式设为 false："
            "会话 Cookie 必须只在 HTTPS 上传输。\n"
            "修正：删掉该变量（生产默认即为 true），或设为 true。"
        )
    cookie_secure = cookie_secure_explicit if cookie_secure_explicit is not None else production

    docs_mode = (env.get(DOCS_MODE_ENV) or ("admin" if production else "public")).strip().lower()
    if docs_mode not in DOCS_MODES:
        raise ConfigError(
            f"{DOCS_MODE_ENV} 只能是 {' / '.join(DOCS_MODES)}，收到 {docs_mode!r}"
        )
    allow_public_docs = bool(_read_bool(env.get(ALLOW_PUBLIC_DOCS_ENV)))
    if production and docs_mode == "public" and not allow_public_docs:
        raise ConfigError(
            f"{ENV_VAR}=production 且 {DOCS_MODE_ENV}=public："
            f"这会把完整接口清单暴露给任何人。若确实需要，请显式设置 {ALLOW_PUBLIC_DOCS_ENV}=1。"
        )
    if not production and docs_mode == "public":
        warnings.append(
            "DOCS 公开模式：仅限本机隔离环境；请勿用于任何可被他人访问的部署。"
        )

    session_ttl_hours = _read_positive_int(
        env.get(SESSION_TTL_ENV), name=SESSION_TTL_ENV, default=168
    )
    session_idle_minutes = _read_positive_int(
        env.get(SESSION_IDLE_ENV), name=SESSION_IDLE_ENV, default=720
    )
    if session_idle_minutes > session_ttl_hours * 60:
        warnings.append(
            f"{SESSION_IDLE_ENV}（{session_idle_minutes}m）大于绝对有效期"
            f"（{session_ttl_hours}h），空闲超时将永远不会先生效。"
        )

    trust_proxy = bool(_read_bool(env.get(TRUST_PROXY_ENV)))
    raw_cidrs = (env.get(TRUSTED_PROXY_CIDRS_ENV) or "").strip()
    trusted_proxy_cidrs = tuple(c.strip() for c in raw_cidrs.split(",") if c.strip())
    if trust_proxy and not trusted_proxy_cidrs:
        raise ConfigError(
            f"{TRUST_PROXY_ENV}=true 但 {TRUSTED_PROXY_CIDRS_ENV} 为空："
            "信任转发头却不限定来源，等于把日志与限流键交给攻击者。\n"
            f"修正：设置 {TRUSTED_PROXY_CIDRS_ENV}=127.0.0.1/32（或你的反代网段），"
            f"或把 {TRUST_PROXY_ENV} 设为 false。"
        )

    cookie_name = (env.get(COOKIE_NAME_ENV) or "cw_session").strip() or "cw_session"

    if production and not env.get(DATABASE_URL_ENV, "").strip():
        warnings.append(
            f"{ENV_VAR}=production 但未显式设置 {DATABASE_URL_ENV}："
            "当前使用的是项目根目录下的默认库文件，生产环境建议显式指定。"
        )

    return AuthSettings(
        environment=environment,
        cookie_secure=cookie_secure,
        cookie_name=cookie_name,
        session_ttl_hours=session_ttl_hours,
        session_idle_minutes=session_idle_minutes,
        docs_mode=docs_mode,
        trust_proxy=trust_proxy,
        trusted_proxy_cidrs=trusted_proxy_cidrs,
        warnings=tuple(warnings),
    )
