from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from .audit import make_entry, utc_now
from .domain import ConflictError, NotFoundError
from .rules import ID_PREFIX, STATES


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
        self._migrate()

    def _migrate(self) -> None:
        """旧库结构升级：没有版本号的旧记录迁移成首版，记录表补作废列。"""
        with self._lock, self.conn:
            item_cols = {row[1] for row in self.conn.execute("PRAGMA table_info(items)")}
            if item_cols and "version" not in item_cols:
                self.conn.execute(
                    "ALTER TABLE items ADD COLUMN version INTEGER NOT NULL DEFAULT 1")
            if item_cols:
                self.conn.execute("UPDATE items SET version=1 WHERE version IS NULL")
            record_cols = {row[1] for row in self.conn.execute("PRAGMA table_info(records)")}
            if record_cols:
                for col in ("voided_at", "voided_by", "void_reason"):
                    if col not in record_cols:
                        self.conn.execute(f"ALTER TABLE records ADD COLUMN {col} TEXT")

    def _create_schema(self) -> None:
        statuses = ",".join("'" + s.replace("'", "''") + "'" for s in STATES)
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
                        CHECK(status IN ('open','closed')),
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    voided_at TEXT,
                    voided_by TEXT,
                    void_reason TEXT,
                    UNIQUE(item_id, external_ref)
                );
                CREATE TABLE IF NOT EXISTS rollback_requests (
                    request_id TEXT PRIMARY KEY,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    reason TEXT NOT NULL,
                    expected_version INTEGER NOT NULL,
                    target_status TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending'
                        CHECK(status IN ('pending','completed','failed')),
                    checkpoint TEXT NOT NULL DEFAULT '{{}}',
                    result TEXT,
                    error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
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
                raise ConflictError("版本冲突，请刷新后重试")
        return self.get_item(item_id)

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
                """SELECT COUNT(*) AS n FROM records
                   WHERE item_id=? AND status='open' AND voided_at IS NULL""",
                (item_id,),
            ).fetchone()
        return int(row["n"])

    def _insert_audit_event(self, action: str, entity_type: str, entity_id: int,
                            actor: str, detail: dict) -> Dict[str, Any]:
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
        event["id"] = int(cur.lastrowid)
        return event

    def append_audit(self, action: str, entity_type: str, entity_id: int,
                     actor: str, detail: dict) -> Dict[str, Any]:
        with self._lock, self.conn:
            return self._insert_audit_event(action, entity_type, entity_id, actor, detail)

    @staticmethod
    def _request(row: sqlite3.Row) -> Dict[str, Any]:
        req = dict(row)
        req["checkpoint"] = json.loads(req["checkpoint"])
        req["result"] = json.loads(req["result"]) if req["result"] else None
        return req

    def create_rollback_request(self, request_id: str, item_id: int, reason: str,
                                expected_version: int, target_status: str,
                                actor: str) -> Dict[str, Any]:
        now = utc_now()
        try:
            with self._lock, self.conn:
                self.conn.execute(
                    """INSERT INTO rollback_requests(request_id, item_id, reason,
                       expected_version, target_status, actor, status, checkpoint,
                       created_at, updated_at) VALUES(?,?,?,?,?,?,'pending','{}',?,?)""",
                    (request_id, item_id, reason, expected_version, target_status,
                     actor, now, now),
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("请求编号已存在") from exc
        return self.get_rollback_request(request_id)

    def get_rollback_request(self, request_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM rollback_requests WHERE request_id=?", (request_id,)
            ).fetchone()
        return self._request(row) if row else None

    def save_checkpoint(self, request_id: str, checkpoint: Dict[str, Any]) -> None:
        with self._lock, self.conn:
            self.conn.execute(
                "UPDATE rollback_requests SET checkpoint=?, updated_at=? WHERE request_id=?",
                (json.dumps(checkpoint, ensure_ascii=False, sort_keys=True),
                 utc_now(), request_id),
            )

    def reopen_rollback_request(self, request_id: str, reason: str,
                                expected_version: int, target_status: str) -> Dict[str, Any]:
        """失败后拿着新版本重办：保留检查点，更新期望版本后回到待执行。"""
        with self._lock, self.conn:
            self.conn.execute(
                """UPDATE rollback_requests SET status='pending', reason=?,
                   expected_version=?, target_status=?, error=NULL, updated_at=?
                   WHERE request_id=? AND status='failed'""",
                (reason, expected_version, target_status, utc_now(), request_id),
            )
        return self.get_rollback_request(request_id)

    def fail_rollback_request(self, request_id: str, error: str) -> None:
        with self._lock, self.conn:
            self.conn.execute(
                """UPDATE rollback_requests SET status='failed', error=?, updated_at=?
                   WHERE request_id=? AND status='pending'""",
                (error, utc_now(), request_id),
            )

    def complete_rollback_request(self, request_id: str, result: Dict[str, Any]) -> None:
        with self._lock, self.conn:
            self.conn.execute(
                """UPDATE rollback_requests SET status='completed', result=?, updated_at=?
                   WHERE request_id=? AND status='pending'""",
                (json.dumps(result, ensure_ascii=False, sort_keys=True),
                 utc_now(), request_id),
            )

    def apply_rollback(self, request_id: str, item_id: int, target: str,
                       expected_version: int, void_ids: List[int], reason: str,
                       checkpoint: Dict[str, Any]) -> Dict[str, Any]:
        """补偿落账：派生记录作废与版本推进同一事务，检查点随事务保存。"""
        now = utc_now()
        with self._lock, self.conn:
            for record_id in void_ids:
                self.conn.execute(
                    """UPDATE records SET voided_at=?, voided_by=?, void_reason=?
                       WHERE id=? AND item_id=? AND voided_at IS NULL""",
                    (now, request_id, reason, record_id, item_id),
                )
            cur = self.conn.execute(
                """UPDATE items SET status=?, version=version+1, updated_at=?
                   WHERE id=? AND version=?""",
                (target, now, item_id, expected_version),
            )
            if cur.rowcount == 0:
                exists = self.conn.execute(
                    "SELECT 1 FROM items WHERE id=?", (item_id,)).fetchone()
                if exists is None:
                    raise NotFoundError("项目不存在")
                raise ConflictError("版本冲突，请刷新后重试")
            self.conn.execute(
                "UPDATE rollback_requests SET checkpoint=?, updated_at=? WHERE request_id=?",
                (json.dumps(checkpoint, ensure_ascii=False, sort_keys=True),
                 now, request_id),
            )
        return self.get_item(item_id)

    def append_rollback_audit(self, request_id: str, entity_type: str, entity_id: int,
                              actor: str, detail: dict,
                              checkpoint: Dict[str, Any]) -> Dict[str, Any]:
        """审计事件与检查点同一事务，写入失败可从检查点重试。"""
        with self._lock, self.conn:
            event = self._insert_audit_event("rollback", entity_type, entity_id,
                                             actor, detail)
            self.conn.execute(
                "UPDATE rollback_requests SET checkpoint=?, updated_at=? WHERE request_id=?",
                (json.dumps(checkpoint, ensure_ascii=False, sort_keys=True),
                 utc_now(), request_id),
            )
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
