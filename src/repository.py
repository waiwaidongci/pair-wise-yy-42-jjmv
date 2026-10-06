from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from .audit import make_entry, utc_now
from .domain import ConflictError, NotFoundError
from .rules import DERIVED_KINDS, RECORD_STATUSES, STATES


class Repository:
    def __init__(self, db_path: str):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self._create_schema()
        self._migrate_records()

    def _create_schema(self) -> None:
        statuses = ",".join("'" + s.replace("'", "''") + "'" for s in STATES)
        record_statuses = ",".join("'" + s.replace("'", "''") + "'" for s in RECORD_STATUSES)
        with self.conn:
            self.conn.executescript(f"""
                CREATE TABLE IF NOT EXISTS items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    quantity REAL NOT NULL DEFAULT 0,
                    threshold REAL NOT NULL DEFAULT 1,
                    status TEXT NOT NULL CHECK(status IN ({statuses})),
                    version INTEGER NOT NULL DEFAULT 1,
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ux_items_external_ref
                    ON items(external_ref) WHERE external_ref IS NOT NULL;
                CREATE TABLE IF NOT EXISTS records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open'
                        CHECK(status IN ({record_statuses})),
                    external_ref TEXT,
                    version INTEGER NOT NULL DEFAULT 1,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(item_id, external_ref)
                );
                CREATE TABLE IF NOT EXISTS rollback_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_no TEXT NOT NULL UNIQUE,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    expected_version INTEGER NOT NULL,
                    target_status TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending'
                        CHECK(status IN ('pending','committed','aborted')),
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    committed_at TEXT,
                    result_version INTEGER
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );
            """)

    def _migrate_records(self) -> None:
        """旧记录没有版本号时迁移成首版，并放开 voided 状态约束。"""
        with self._lock, self.conn:
            cols = self.conn.execute("PRAGMA table_info(records)").fetchall()
            col_names = [c[1] for c in cols]
            if "version" in col_names:
                return
            # 旧表缺少 version 列，且 CHECK 未包含 voided；整表重建以迁移
            self.conn.execute("ALTER TABLE records RENAME TO records_old")
            self.conn.execute(f"""
                CREATE TABLE records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open'
                        CHECK(status IN ({','.join("'" + s.replace("'", "''") + "'" for s in RECORD_STATUSES)})),
                    external_ref TEXT,
                    version INTEGER NOT NULL DEFAULT 1,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(item_id, external_ref)
                )
            """)
            self.conn.execute(
                """INSERT INTO records(id, item_id, kind, detail, status, external_ref,
                   version, created_by, created_at)
                   SELECT id, item_id, kind, detail, status, external_ref, 1,
                          created_by, created_at FROM records_old"""
            )
            self.conn.execute("DROP TABLE records_old")

    @staticmethod
    def _item(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    def create_item(self, title: str, description: str, severity: str,
                    quantity: float, threshold: float, external_ref: Optional[str],
                    actor: str) -> Dict[str, Any]:
        now = utc_now()
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO items(title, description, severity, quantity, threshold,
                       status, version, external_ref, created_by, created_at, updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (title, description, severity, quantity, threshold, STATES[0], 1,
                     external_ref, actor, now, now),
                )
                item_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("external_ref已存在") from exc
        return self.get_item(item_id)

    def get_item(self, item_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if row is None:
            raise NotFoundError("项目不存在")
        return self._item(row)

    def list_items(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM items"
        params: tuple = ()
        if status:
            sql += " WHERE status=?"
            params = (status,)
        sql += " ORDER BY id DESC"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [self._item(row) for row in rows]

    def transition_item(self, item_id: int, target: str, expected_version: int,
                        actor: str) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                """UPDATE items SET status=?, version=version+1, updated_at=?
                   WHERE id=? AND version=?""",
                (target, now, item_id, expected_version),
            )
            if cur.rowcount == 0:
                exists = self.conn.execute("SELECT 1 FROM items WHERE id=?", (item_id,)).fetchone()
                if exists is None:
                    raise NotFoundError("项目不存在")
                row = self.conn.execute(
                    "SELECT version FROM items WHERE id=?", (item_id,)
                ).fetchone()
                raise ConflictError(
                    f"版本冲突，当前版本为{row['version']}，请刷新后重试")
        return self.get_item(item_id)

    def create_rollback_request(self, request_no: str, item_id: int,
                                 expected_version: int, target: str, reason: str,
                                 actor: str) -> None:
        """建立检查点（pending）。请求编号唯一，重复提交不重复落账。"""
        now = utc_now()
        with self._lock, self.conn:
            self.conn.execute(
                """INSERT OR IGNORE INTO rollback_requests
                   (request_no, item_id, expected_version, target_status, reason,
                    status, created_by, created_at)
                   VALUES(?,?,?,?,?, 'pending', ?, ?)""",
                (request_no, item_id, expected_version, target, reason, actor, now),
            )

    def get_rollback_request(self, request_no: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM rollback_requests WHERE request_no=?", (request_no,)
            ).fetchone()
        return dict(row) if row else None

    def update_rollback_request(self, request_no: str, expected_version: Optional[int] = None,
                                 status: Optional[str] = None) -> None:
        now = utc_now()
        fields: List[str] = []
        params: List[Any] = []
        if expected_version is not None:
            fields.append("expected_version=?"); params.append(expected_version)
        if status is not None:
            fields.append("status=?"); params.append(status)
            if status == "committed":
                fields.append("committed_at=?"); params.append(now)
        if not fields:
            return
        params.append(request_no)
        with self._lock, self.conn:
            self.conn.execute(
                f"UPDATE rollback_requests SET {', '.join(fields)} WHERE request_no=?",
                params,
            )

    def apply_rollback(self, item_id: int, target: str, expected_version: int,
                       request_no: str) -> tuple:
        """原子完成：版本核对、作废派生记录、生成新版本、标记请求已提交。

        任一环节失败则整体回滚，请求保持 pending 以便从检查点恢复。
        返回 (更新后的item, 本次作废的派生记录列表)。
        """
        now = utc_now()
        placeholders = ",".join("?" for _ in DERIVED_KINDS)
        with self._lock, self.conn:
            cur = self.conn.execute(
                """UPDATE items SET status=?, version=version+1, updated_at=?
                   WHERE id=? AND version=?""",
                (target, now, item_id, expected_version),
            )
            if cur.rowcount == 0:
                exists = self.conn.execute("SELECT 1 FROM items WHERE id=?", (item_id,)).fetchone()
                if exists is None:
                    raise NotFoundError("项目不存在")
                row = self.conn.execute(
                    "SELECT version FROM items WHERE id=?", (item_id,)
                ).fetchone()
                raise ConflictError(
                    f"版本冲突，当前版本为{row['version']}，请刷新后重试")
            # 作废派生记录（关闭签认、资源释放），并生成记录新版本
            self.conn.execute(
                f"""UPDATE records SET status='voided', version=version+1
                    WHERE item_id=? AND kind IN ({placeholders})
                      AND status != 'voided'""",
                (item_id, *DERIVED_KINDS),
            )
            voided = self.conn.execute(
                f"""SELECT * FROM records
                    WHERE item_id=? AND kind IN ({placeholders}) AND status='voided'
                    ORDER BY id""",
                (item_id, *DERIVED_KINDS),
            ).fetchall()
            item_row = self.conn.execute(
                "SELECT * FROM items WHERE id=?", (item_id,)
            ).fetchone()
            result_version = item_row["version"]
            self.conn.execute(
                """UPDATE rollback_requests
                   SET status='committed', committed_at=?, result_version=?
                   WHERE request_no=?""",
                (now, result_version, request_no),
            )
        return dict(item_row), [dict(r) for r in voided]

    def add_record(self, item_id: int, kind: str, detail: str, status: str,
                   external_ref: Optional[str], actor: str) -> Dict[str, Any]:
        now = utc_now()
        self.get_item(item_id)
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO records(item_id, kind, detail, status, external_ref,
                       created_by, created_at) VALUES(?,?,?,?,?,?,?)""",
                    (item_id, kind, detail, status, external_ref, actor, now),
                )
                record_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("记录唯一标识已存在") from exc
        with self._lock:
            row = self.conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        return dict(row)

    def list_records(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM records WHERE item_id=? ORDER BY id", (item_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    def open_record_count(self, item_id: int) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM records WHERE item_id=? AND status='open'",
                (item_id,),
            ).fetchone()
        return int(row["n"])

    def append_audit(self, action: str, entity_type: str, entity_id: int,
                     actor: str, detail: dict) -> Dict[str, Any]:
        with self._lock, self.conn:
            row = self.conn.execute(
                "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            previous = row["entry_hash"] if row else "GENESIS"
            event = make_entry(action, entity_type, entity_id, actor, detail, previous)
            cur = self.conn.execute(
                """INSERT INTO audit_events(action, entity_type, entity_id, actor, detail,
                   previous_hash, entry_hash, created_at) VALUES(?,?,?,?,?,?,?,?)""",
                (event["action"], event["entity_type"], event["entity_id"], event["actor"],
                 json.dumps(event["detail"], ensure_ascii=False, sort_keys=True),
                 event["previous_hash"], event["entry_hash"], event["created_at"]),
            )
            event_id = int(cur.lastrowid)
        event["id"] = event_id
        return event

    def list_audit(self, entity_id: Optional[int] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM audit_events"
        params: tuple = ()
        if entity_id is not None:
            sql += " WHERE entity_id=?"
            params = (entity_id,)
        sql += " ORDER BY id"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["detail"] = json.loads(item["detail"])
            result.append(item)
        return result

    def verify_audit_chain(self) -> bool:
        from .audit import calculate_hash
        with self._lock:
            rows = self.conn.execute("SELECT * FROM audit_events ORDER BY id").fetchall()
        previous = "GENESIS"
        for row in rows:
            if row["previous_hash"] != previous:
                return False
            payload = {
                "action": row["action"], "entity_type": row["entity_type"],
                "entity_id": row["entity_id"], "actor": row["actor"],
                "detail": json.loads(row["detail"]), "created_at": row["created_at"],
            }
            if calculate_hash(previous, payload) != row["entry_hash"]:
                return False
            previous = row["entry_hash"]
        return True

    def close(self) -> None:
        with self._lock:
            self.conn.close()
