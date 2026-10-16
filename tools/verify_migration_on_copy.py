"""生产迁移演练：**在真实库的副本上**跑一遍 0004 → 0005，并逐步核对。

为什么要有这个脚本

设计文档 §9.6 规定生产迁移必须"先备份 → 核对目标路径 → 迁移 → 验证完整性"。
人工敲这几步很容易漏掉其中一步（尤其是"我到底改的是哪个文件"）。
本脚本把这套规程固化成一条命令，且**只读源库**：

- 源库全程以只读方式打开，脚本开始与结束时各算一次 SHA-256 对比；
- 真正的迁移只发生在 ``%TEMP%`` 下的副本上；
- 迁移后又用 `alembic downgrade` 把副本退回原版本，证明回退路径同样可用。

用法::

    python tools/verify_migration_on_copy.py                      # 演练 cyberwatch.db
    python tools/verify_migration_on_copy.py --source path/to.db  # 演练指定库
    python tools/verify_migration_on_copy.py --keep               # 保留副本目录，便于人工查看

退出码：0 全部核对通过；1 有核对失败；2 环境问题（源库不存在 / 迁移命令跑不起来）。
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from app.config import DATABASE_URL_ENV  # noqa: E402

AUTH_TABLES = ("app_user", "user_session")
EXPECTED_HEAD = "0005"
EXPECTED_FORKS = [("app_user", "user_id", "id")]


class CheckFailed(Exception):
    pass


def snapshot(db: Path) -> dict:
    """只读取一份库的完整快照：字节摘要 + 表清单 + 每张表的全部行。"""
    payload = db.read_bytes()
    con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
    try:
        tables = sorted(
            row[0]
            for row in con.execute("select name from sqlite_master where type='table'")
        )
        data = {
            table: list(con.execute(f"select * from {table}"))
            for table in tables
            if table != "sqlite_sequence"
        }
        version = (
            [row[0] for row in con.execute("select version_num from alembic_version")]
            if "alembic_version" in tables
            else []
        )
    finally:
        con.close()
    return {
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "tables": tables,
        "rows": data,
        "version": version,
    }


def run_alembic(db: Path, *args: str) -> None:
    env = os.environ.copy()
    env[DATABASE_URL_ENV] = f"sqlite:///{db.as_posix()}"
    command = [sys.executable, "-m", "alembic", *args]
    printable = f"{DATABASE_URL_ENV}=sqlite:///{db.name} " + " ".join(command[1:])
    print(f"    $ {printable}")
    result = subprocess.run(
        command, cwd=str(BASE_DIR), env=env, capture_output=True, text=True, timeout=300
    )
    if result.returncode != 0:
        raise CheckFailed(f"alembic {' '.join(args)} 失败：\n{result.stdout}\n{result.stderr}")


def check(condition: bool, message: str) -> None:
    mark = "OK  " if condition else "FAIL"
    print(f"    [{mark}] {message}")
    if not condition:
        raise CheckFailed(message)


def forks_of(db: Path, table: str) -> list[tuple[str, str, str]]:
    con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
    try:
        return [row[2:5] for row in con.execute(f"PRAGMA foreign_key_list({table})")]
    finally:
        con.close()


def unique_indexes(db: Path, table: str) -> list[tuple[str, ...]]:
    con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
    try:
        result = []
        for row in con.execute(f"PRAGMA index_list({table})"):
            if row[2]:
                result.append(tuple(r[2] for r in con.execute(f"PRAGMA index_info({row[1]})")))
        return result
    finally:
        con.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="在真实库副本上演练 0004 → 0005 迁移")
    parser.add_argument("--source", default=str(BASE_DIR / "cyberwatch.db"))
    parser.add_argument("--keep", action="store_true", help="保留副本目录")
    args = parser.parse_args(argv)

    source = Path(args.source).resolve()
    print(f"源库：{source}")
    if not source.exists():
        print("源库不存在，无法演练。", file=sys.stderr)
        return 2
    if source.name == "cyberwatch.db" and source.parent != BASE_DIR:
        print("警告：--source 指向了项目之外的同名文件，请确认路径。", file=sys.stderr)

    workdir = Path(tempfile.mkdtemp(prefix="cyberwatch-rehearsal-"))
    copy = workdir / "rehearsal.db"
    print(f"副本：{copy}")

    try:
        print("\n[1/5] 备份：把源库复制到临时目录（源库只读）")
        before = snapshot(source)
        shutil.copy2(source, copy)
        check(copy.stat().st_size == before["size"], f"副本大小与源库一致（{before['size']} 字节）")
        check(
            hashlib.sha256(copy.read_bytes()).hexdigest() == before["sha256"],
            "副本 SHA-256 与源库一致",
        )
        print(f"    迁移前版本：{before['version']}，表：{before['tables']}")
        print(
            "    迁移前行数："
            + ", ".join(f"{t}={len(rows)}" for t, rows in before["rows"].items())
        )

        print("\n[2/5] 核对目标：确认 alembic 确实作用于副本")
        check(copy != source, "副本不是源库本身")
        check(
            str(copy).lower().startswith(str(Path(tempfile.gettempdir())).lower()),
            "副本位于系统临时目录",
        )

        print("\n[3/5] 迁移：upgrade head（只在副本上执行）")
        run_alembic(copy, "upgrade", "head")
        after = snapshot(copy)

        print("\n[4/5] 完整性核对")
        check(after["version"] == [EXPECTED_HEAD], f"版本推进到 {EXPECTED_HEAD}（实际 {after['version']}）")
        for table in AUTH_TABLES:
            check(table in after["tables"], f"新表 {table} 已创建")
        check(len(after["rows"]["app_user"]) == 0, "app_user 未被迁移写入数据")
        check(len(after["rows"]["user_session"]) == 0, "user_session 未被迁移写入数据")
        check(
            forks_of(copy, "user_session") == EXPECTED_FORKS,
            f"user_session 的真实外键 = {EXPECTED_FORKS}",
        )
        check(("username",) in unique_indexes(copy, "app_user"), "app_user.username 唯一索引存在")
        check(
            ("token_hash",) in unique_indexes(copy, "user_session"),
            "user_session.token_hash 唯一索引存在",
        )

        for table in ("event", "status_history"):
            check(
                after["rows"][table] == before["rows"][table],
                f"{table} 的全部 {len(before['rows'][table])} 行逐字段零损失",
            )
        check(after["tables"] == sorted(before["tables"] + list(AUTH_TABLES)),
              f"表集合 = 原表 + {AUTH_TABLES}，没有表被删除")

        print("\n[5/5] 回退演练：downgrade 0004，确认可原路退回")
        run_alembic(copy, "downgrade", "0004")
        rolled = snapshot(copy)
        check(rolled["version"] == ["0004"], f"版本退回 0004（实际 {rolled['version']}）")
        check(rolled["tables"] == before["tables"], "表集合回到迁移前")
        for table in ("event", "status_history"):
            check(rolled["rows"][table] == before["rows"][table], f"{table} 回退后数据仍完好")

        print("\n最终确认：源库在整个演练期间未被改动")
        final = snapshot(source)
        check(final["sha256"] == before["sha256"], f"源库 SHA-256 不变（{before['sha256'][:16]}…）")
        check(final["size"] == before["size"], "源库大小不变")

        print("\n=== 演练全部通过 ===")
        return 0

    except CheckFailed as exc:
        print(f"\n=== 演练失败 ===\n{exc}", file=sys.stderr)
        return 1
    finally:
        if args.keep:
            print(f"（副本已保留：{workdir}）")
        else:
            shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
