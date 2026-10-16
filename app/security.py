"""密码哈希、会话令牌、时间工具（V0.5 新增）。

本模块是**纯函数层**：不碰数据库、不 import `app.auth` / `app.main`，
唯一的 `app.*` 依赖是 `app.models`（只为复用 `utcnow`，
依赖方向 `models → security` 与分层一致，见设计文档 §2.0）。
这样它既能被 `app/auth.py` 使用，也能被 `app/cli.py` 与单测直接使用，
而且永远不会参与循环导入。

职责边界：

- **密码**：Argon2id 哈希 / 校验 / 参数升级判定 / 口令强度策略
- **令牌**：随机会话令牌生成 + SHA-256 摘要（**库里永不存明文令牌**）
- **恒定时间比较**：CSRF 令牌比对
- **时间**：统一 UTC（SQLite 的 DATETIME 不保存 tzinfo，必须显式归一化）
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

#: ``utcnow`` 的**唯一定义**在 ``app/models.py``（那一层需要它做 ``default_factory``）。
#: 这里刻意**重新导出**而不是再写一份实现：两份实现即使此刻完全一样，
#: 也迟早会漂移（例如一边改成返回 naive 时间），而"现在几点"一旦有两个答案，
#: 会话过期判定就会变成极难排查的偶发问题。
from app.models import utcnow

# ---------------------------------------------------------------------------
# 1) 口令策略常量
# ---------------------------------------------------------------------------
#: 最小长度。NIST SP 800-63B 的立场是「长度优先、不强制字符组合」。
MIN_PASSWORD_LENGTH = 12
#: 最大长度。上限是**防 DoS**：Argon2 会把整个口令读进内存再处理。
MAX_PASSWORD_LENGTH = 128

#: 一串常见的弱口令。只做「命中即拒绝」的黑名单，不做复杂度打分。
#: 刻意保持精简（约 60 条最容易在公开字典里排在前面的几个），
#: 目的是拦住「Password123!」这类"看起来合规"的默认口令。
WEAK_PASSWORDS = frozenset(
    {
        "password", "password1", "password123", "password1234", "password12345",
        "passw0rd", "p@ssw0rd", "p@ssword123", "password!",
        "123456", "1234567", "12345678", "123456789", "1234567890",
        "12345678901", "123456789012", "111111111111", "000000000000",
        "qwerty", "qwerty123", "qwertyuiop", "qwertyuiop123",
        "abc123456789", "abcd1234", "abcdefghijkl", "letmein", "letmein123",
        "iloveyou", "iloveyou123", "welcome", "welcome123", "welcome1",
        "admin", "admin123", "administrator", "root123456", "toor123456",
        "changeme", "changeme123", "secret", "secret123", "default",
        "cyberwatch", "cyberwatch123", "cyberwatch2026",
        "monkey123456", "dragon123456", "sunshine123", "princess123",
        "football123", "baseball123", "master123456", "shadow123456",
        "trustno1", "starwars123", "whatever123", "nothing123",
        "aaaaaaaaaaaa", "zzzzzzzzzzzz", "asdfghjkl", "asdfghjkl123",
        "1qaz2wsx3edc", "zaq12wsxcde3", "!@#$%^&*()_+",
    }
)

# ---------------------------------------------------------------------------
# 2) Argon2id
# ---------------------------------------------------------------------------
#: 交互式登录档位（OWASP 建议之上）。实测：hash/verify 各约 66 ms、64 MiB 内存。
#: 参数写死在这里，**不允许**从环境变量改 —— 否则会出现「同一套密码用不同
#: 成本参数校验」的运维黑洞。调参的正确方式是改这里 + 靠 needs_rehash 平滑升级。
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # KiB = 64 MiB
ARGON2_PARALLELISM = 2
ARGON2_HASH_LEN = 32
ARGON2_SALT_LEN = 16

_password_hasher = PasswordHasher(
    time_cost=ARGON2_TIME_COST,
    memory_cost=ARGON2_MEMORY_COST,
    parallelism=ARGON2_PARALLELISM,
    hash_len=ARGON2_HASH_LEN,
    salt_len=ARGON2_SALT_LEN,
    type=Type.ID,  # Argon2id：抗 GPU 且抗侧信道
)

#: 用于**用户不存在时**照样跑一次校验，让耗时与「密码错误」一致，
#: 从而堵住「按响应时间判断账号是否存在」的侧信道。
#: 这是一个用相同参数生成的普通 Argon2id 哈希，明文无关紧要。
DUMMY_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=2$GxhPraQmfPWT3AhO5Qb9mw$"
    "u3y3hqXpH25lCtBnJj6idJUJ0UzvS0lhDrkori/w6yM"
)


def hash_password(password: str) -> str:
    """生成 Argon2id 编码串（每次调用都用新的随机盐）。"""
    return _password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """校验口令。**不抛异常**：任何不匹配/损坏的哈希都返回 ``False``。

    调用方（登录流程）只关心"过 / 不过"，不应该区分"哈希串坏了"和"密码错了" ——
    区分了就会变成信息泄露面。
    """
    try:
        return _password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def run_dummy_verify(password: str = "dummy") -> None:
    """对 :data:`DUMMY_HASH` 跑一次真实校验，纯粹为了**消耗相同的时间**。"""
    verify_password(password, DUMMY_HASH)


def password_needs_rehash(password_hash: str) -> bool:
    """判断已有哈希是否落后于当前参数（登录成功时用它做静默升级）。"""
    try:
        return _password_hasher.check_needs_rehash(password_hash)
    except (InvalidHashError, VerificationError):
        return True  # 无法解析的历史哈希 → 一律要求重建


class PasswordPolicyError(ValueError):
    """口令不符合策略（消息为面向用户的中文）。"""


def validate_password_strength(password: str, username: str = "") -> None:
    """校验口令强度，不合规抛 :class:`PasswordPolicyError`。

    只做三件事（与设计文档 §2.2 一致）：

    1. 长度在 ``[MIN, MAX]`` 区间内；
    2. 不（忽略大小写）等于用户名；
    3. 不在 :data:`WEAK_PASSWORDS` 里。

    **刻意不要求**大小写/数字/符号组合：那类规则会让用户写出
    ``Password1!`` 这种"合规但很弱"的口令，NIST SP 800-63B 已明确不建议。
    """
    if not isinstance(password, str) or password == "":
        raise PasswordPolicyError("密码不能为空")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(f"密码强度不足：至少 {MIN_PASSWORD_LENGTH} 位")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise PasswordPolicyError(f"密码过长：最多 {MAX_PASSWORD_LENGTH} 位")
    normalized = password.strip().lower()
    if username and normalized == username.strip().lower():
        raise PasswordPolicyError("密码强度不足：不能与用户名相同")
    if normalized in WEAK_PASSWORDS:
        raise PasswordPolicyError("密码强度不足：这是常见弱口令，请换一个")


# ---------------------------------------------------------------------------
# 3) 会话令牌与 CSRF 令牌
# ---------------------------------------------------------------------------
#: 会话令牌的原始字节数（32 字节 = 256 bit 熵）。仅存在于 Cookie 中。
SESSION_TOKEN_BYTES = 32
#: CSRF 令牌的原始字节数（32 字节 → 64 个 hex 字符，正好填满 VARCHAR(64)）。
CSRF_TOKEN_BYTES = 32


def generate_session_token() -> str:
    """生成新的会话令牌（明文只应写进 Cookie，**绝不入库**）。"""
    return secrets.token_urlsafe(SESSION_TOKEN_BYTES)


def hash_session_token(raw_token: str) -> str:
    """令牌 → 64 字符 SHA-256 十六进制摘要（这是入库的形式）。

    为什么用 SHA-256 而不是 Argon2：
    令牌本身是 256 bit 的高熵随机串，不存在"被字典猜中"的问题，
    因此不需要慢哈希；用快哈希才能在每次请求的鉴权路径上承受得住。
    """
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def generate_csrf_token() -> str:
    """生成 CSRF 令牌（64 字符 hex）。前端可从非 HttpOnly 的 Cookie 读到它。"""
    return secrets.token_hex(CSRF_TOKEN_BYTES)


def constant_time_equals(left: str | None, right: str | None) -> bool:
    """恒定时间字符串比较（防「逐字符试探 CSRF 令牌」的时序攻击）。

    两个入参都可能来自攻击者（请求头 vs 库中值），所以必须：
    1. 先把两者都规范化成 ``bytes``（``None`` → 空串）；
    2. 用 :func:`hmac.compare_digest` 比较 —— 它在长度不等时也保持恒定时间。
    """
    left_bytes = ("" if left is None else str(left)).encode("utf-8")
    right_bytes = ("" if right is None else str(right)).encode("utf-8")
    return hmac.compare_digest(left_bytes, right_bytes)


# ---------------------------------------------------------------------------
# 4) 时间工具
# ---------------------------------------------------------------------------
def normalize_utc(value: datetime | None) -> datetime | None:
    """把从 SQLite 读回的时间统一成 aware UTC。

    **为什么必须要它**：SQLite 的 ``DATETIME`` 不保存时区，写进去的 aware
    datetime 读回来是 naive 的。若拿 naive 与 aware 直接比较，Python 会抛
    ``TypeError``；若误按本地时区解释，会话过期判定就会整体偏移。
    因此规定：**所有时间比较前必须先过这个函数**。

    - ``None`` → ``None``
    - naive → 视为 UTC，补上 ``tzinfo``
    - aware → 转换成 UTC
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def seconds_since(moment: datetime | None, *, now: datetime | None = None) -> float:
    """``now - moment`` 的秒数（两侧都先归一化到 UTC）。"""
    normalized = normalize_utc(moment)
    if normalized is None:
        return float("inf")
    reference = utcnow() if now is None else normalize_utc(now)
    return (reference - normalized).total_seconds()


def describe_duration(seconds: float) -> str:
    """把秒数变成中文可读文本（写日志用；**不用于 HTTP 响应**）。

    之所以特意写"不用于 HTTP 响应"：V0.5.1 一度把它用在登录限流的
    ``Retry-After`` 头里，后来实测发现那个头本身就是一条账号枚举旁路
    （不存在的用户名永远不会带 `Retry-After`），已经移除，详见
    ``docs/V0.5-需求与架构设计.md`` §2.6 注。剩余时间现在只进服务端日志。

    ``float`` 入参是为了能直接吃 ``seconds_since`` 的返回值（可能是 ``inf``）。
    """
    if seconds == float("inf"):
        return "未知（时间戳缺失）"
    whole = int(seconds)
    if whole <= 0:
        return "0 秒"
    if whole < 60:
        return f"{whole} 秒"
    minutes, rest = divmod(whole, 60)
    if minutes < 60:
        return f"{minutes} 分钟" + (f" {rest} 秒" if rest else "")
    hours, minutes = divmod(minutes, 60)
    return f"{hours} 小时" + (f" {minutes} 分钟" if minutes else "")


def add_seconds(moment: datetime, seconds: int) -> datetime:
    """在 aware UTC 时间上加秒数（用于算过期时间）。"""
    return normalize_utc(moment) + timedelta(seconds=seconds)
