"""SQLite 受信 root 存储 + 跨进程并发控制。

设计要点：
* 受信 root 以“整行替换”方式保存在 SQLite，WAL 模式支持两个 uvicorn 工作进程并发读；
* 所有“读取最新受信 root → 验证整链 → 替换提交”的事务在 POSIX 文件锁
  （flock，跨进程互斥）内完成，保证并发提交都以当前最新受信 root 为起点，
  不会覆盖另一个请求已经提交的更新；
* 仅在数据库首次初始化、其中不存在受信 root 时，才从启动文件载入引导 root；
  重启后数据库已有受信 root，启动文件不会再次生效；
* 每次提交（成功/失败）写入审计表 root_audit，重启后结果保留。
"""

from __future__ import annotations

import fcntl
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .root_verify import (
    ChainError,
    ParsedRoot,
    RootFormatError,
    parse_root,
    verify_chain,
)
from .settings import BOOTSTRAP_ROOT_PATH, DB_PATH


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class StoreError(RuntimeError):
    """存储层不可恢复错误（如引导文件缺失/非法）。"""


class RootStore:
    def __init__(self, db_path: Path | str = DB_PATH,
                 bootstrap_path: Path | str = BOOTSTRAP_ROOT_PATH):
        self.db_path = Path(db_path)
        self.bootstrap_path = Path(bootstrap_path)
        self.lock_path = self.db_path.with_name(self.db_path.name + ".lock")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # lock 文件需可被两个工作进程（容器内同一用户）打开
        self._lock_fd = self.lock_path.open("a+")
        self._initialized = False
        self.initialize()

    # ------------------------------------------------------------------ #
    # 初始化与引导
    # ------------------------------------------------------------------ #
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self.db_path, timeout=30, isolation_level=None, check_same_thread=False
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def initialize(self) -> None:
        """幂等初始化；跨进程加锁，保证引导 root 只在首个进程首次启动时载入。"""
        if self._initialized:
            return
        with self._exclusive_lock():
            conn = self._connect()
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS trusted_root (
                        id INTEGER PRIMARY KEY CHECK (id = 1),
                        version INTEGER NOT NULL,
                        spec_version TEXT NOT NULL,
                        expires TEXT NOT NULL,
                        envelope_json TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS root_audit (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts TEXT NOT NULL,
                        result TEXT NOT NULL,
                        from_version INTEGER,
                        to_version INTEGER,
                        file_count INTEGER,
                        failed_version INTEGER,
                        reason TEXT
                    )
                    """
                )
                row = conn.execute(
                    "SELECT COUNT(*) AS n FROM trusted_root"
                ).fetchone()
                if row["n"] == 0:
                    self._bootstrap(conn)
            finally:
                conn.close()
        self._initialized = True

    def _bootstrap(self, conn: sqlite3.Connection) -> None:
        """首次启动：从启动文件载入受信 root（仅此一次）。"""
        if not self.bootstrap_path.is_file():
            raise StoreError(
                f"首次启动需要引导 root 文件，但 {self.bootstrap_path} 不存在"
            )
        raw = self.bootstrap_path.read_bytes()
        try:
            envelope = json.loads(raw.decode("utf-8"))
            parsed = parse_root(envelope, raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StoreError(f"引导 root 不是合法 JSON: {exc}") from exc
        except RootFormatError as exc:
            raise StoreError(f"引导 root 格式非法: {exc.message}") from exc
        conn.execute(
            "INSERT INTO trusted_root (id, version, spec_version, expires, "
            "envelope_json, updated_at) VALUES (1, ?, ?, ?, ?, ?)",
            (
                parsed.version,
                parsed.spec_version,
                parsed.expires.isoformat(),
                parsed.raw_bytes.decode("utf-8"),
                _utc_now().isoformat(),
            ),
        )
        conn.execute(
            "INSERT INTO root_audit (ts, result, from_version, to_version, "
            "file_count, failed_version, reason) VALUES (?, 'bootstrap', ?, ?, 1, NULL, ?)",
            (
                _utc_now().isoformat(),
                parsed.version,
                parsed.version,
                f"首次启动从 {self.bootstrap_path.name} 载入受信 root",
            ),
        )

    # ------------------------------------------------------------------ #
    # 锁
    # ------------------------------------------------------------------ #
    class _Lock:
        def __init__(self, fd):
            self.fd = fd

        def __enter__(self):
            fcntl.flock(self.fd.fileno(), fcntl.LOCK_EX)
            return self

        def __exit__(self, exc_type, exc, tb):
            fcntl.flock(self.fd.fileno(), fcntl.LOCK_UN)
            return False

    def _exclusive_lock(self) -> "RootStore._Lock":
        return RootStore._Lock(self._lock_fd)

    # ------------------------------------------------------------------ #
    # 读取
    # ------------------------------------------------------------------ #
    def get_trusted(self) -> ParsedRoot:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT envelope_json FROM trusted_root WHERE id = 1"
            ).fetchone()
            if row is None:  # 理论上 initialize 已保证存在
                raise StoreError("受信 root 尚未初始化")
            raw = row["envelope_json"].encode("utf-8")
            return parse_root(json.loads(raw.decode("utf-8")), raw)
        finally:
            conn.close()

    def get_trusted_info(self) -> dict[str, Any]:
        parsed = self.get_trusted()
        return {
            "version": parsed.version,
            "spec_version": parsed.spec_version,
            "expires": parsed.expires.isoformat().replace("+00:00", "Z"),
            "key_count": len(parsed.keys),
            "root_keyids": parsed.role_keyids.get("root", []),
            "root_threshold": parsed.role_thresholds.get("root"),
        }

    # ------------------------------------------------------------------ #
    # 轮换提交
    # ------------------------------------------------------------------ #
    def submit_chain(
        self, raw_files: list[bytes], update_started_at: datetime
    ) -> dict[str, Any]:
        """在排他锁内以“当前最新受信 root”为起点验证并原子替换。

        成功：整链验证通过后替换受信 root，写审计，返回结果；
        失败：不修改受信 root，写审计并抛出 ChainError / RootFormatError。
        """
        # 上传文件的 JSON 解析在锁外即可完成（不触碰共享状态）
        candidates: list[ParsedRoot] = []
        for index, raw in enumerate(raw_files):
            try:
                envelope = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                err = RootFormatError(f"第 {index + 1} 份文件不是合法 JSON: {exc}")
                self._audit_failure(len(raw_files), None, err.message)
                raise err from exc
            try:
                candidates.append(parse_root(envelope, raw))
            except RootFormatError as exc:
                self._audit_failure(len(raw_files), exc.version, exc.message)
                raise

        # 按版本排列；重复版本在此直接判失败
        versions = [c.version for c in candidates]
        if len(set(versions)) != len(versions):
            dup = sorted({v for v in versions if versions.count(v) > 1})
            reason = f"上传的 root 存在重复版本: {dup}，版本必须逐次加 1"
            self._audit_failure(len(raw_files), dup[0], reason)
            raise ChainError(dup[0], reason)
        candidates.sort(key=lambda c: c.version)

        with self._exclusive_lock():
            # 锁内重新读取最新受信 root：并发请求不会基于过期信任锚验证
            trusted = self.get_trusted()
            try:
                reports = verify_chain(trusted, candidates, update_started_at)
            except ChainError as exc:
                self._audit_failure(
                    len(raw_files), exc.version, exc.reason,
                    from_version=trusted.version,
                )
                raise
            final = candidates[-1]
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                # 二次确认受信 root 未被改动（锁保护下的防御性校验）
                row = conn.execute(
                    "SELECT version FROM trusted_root WHERE id = 1"
                ).fetchone()
                if row is None or row["version"] != trusted.version:
                    conn.rollback()
                    reason = "受信 root 在验证期间已被其他请求更新，请基于最新受信 root 重新提交"
                    self._audit_failure(
                        len(raw_files), None, reason, from_version=trusted.version
                    )
                    raise ChainError(None, reason)
                conn.execute(
                    "UPDATE trusted_root SET version = ?, spec_version = ?, "
                    "expires = ?, envelope_json = ?, updated_at = ? WHERE id = 1",
                    (
                        final.version,
                        final.spec_version,
                        final.expires.isoformat(),
                        final.raw_bytes.decode("utf-8"),
                        _utc_now().isoformat(),
                    ),
                )
                conn.execute(
                    "INSERT INTO root_audit (ts, result, from_version, to_version, "
                    "file_count, failed_version, reason) "
                    "VALUES (?, 'success', ?, ?, ?, NULL, ?)",
                    (
                        _utc_now().isoformat(),
                        trusted.version,
                        final.version,
                        len(raw_files),
                        f"整链 {len(raw_files)} 份 root 验证通过并替换受信 root",
                    ),
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

        return {
            "ok": True,
            "previous_version": trusted.version,
            "current_version": final.version,
            "file_count": len(raw_files),
            "reports": reports,
        }

    # ------------------------------------------------------------------ #
    # 审计
    # ------------------------------------------------------------------ #
    def _audit_failure(
        self,
        file_count: int,
        failed_version: Optional[int],
        reason: str,
        *,
        from_version: Optional[int] = None,
    ) -> None:
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO root_audit (ts, result, from_version, to_version, "
                "file_count, failed_version, reason) "
                "VALUES (?, 'failure', ?, NULL, ?, ?, ?)",
                (
                    _utc_now().isoformat(),
                    from_version,
                    file_count,
                    failed_version,
                    reason,
                ),
            )
        finally:
            conn.close()

    def list_audit(self, limit: int = 20) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT id, ts, result, from_version, to_version, file_count, "
                "failed_version, reason FROM root_audit ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()
