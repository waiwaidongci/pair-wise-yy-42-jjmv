import tempfile, unittest
from pathlib import Path
from src.domain import ConflictError, PermissionDenied, ValidationError
from src.repository import Repository
from src.rules import (CLOSURE_SIGNOFF_KIND, RESOURCE_RELEASE_KIND, STATES,
                       TRANSITION_ROLES)
from src.service import Service


class RollbackTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)
        self.item = self.service.create_item(
            {"title": "rollback item", "description": "night shift misjudged",
             "severity": "high", "quantity": 5, "threshold": 10,
             "external_ref": "RB-1"},
            "creator", "field_commander")
        # advance to controlled
        current = self.item
        for target in STATES[1:-1]:
            current = self.service.transition(
                current["id"], target, current["version"],
                "reviewer", TRANSITION_ROLES[target][0])
        self.controlled = current
        # derived records: closure signoff + resource release + open matter
        self.service.add_record(
            self.item["id"],
            {"kind": CLOSURE_SIGNOFF_KIND, "detail": "signed off",
             "status": "closed", "external_ref": "CS-1"},
            "recorder", "field_commander")
        self.service.add_record(
            self.item["id"],
            {"kind": RESOURCE_RELEASE_KIND, "detail": "released engine",
             "status": "closed", "external_ref": "RR-1"},
            "recorder", "logistics")
        self.service.add_record(
            self.item["id"],
            {"kind": "evidence", "detail": "still open",
             "status": "open", "external_ref": "EV-1"},
            "recorder", "field_commander")

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def _payload(self, request_no="RB-REQ-1", target="contained",
                 expected_version=None, reason="夜间误判已控，现场要求退回"):
        return {
            "request_no": request_no,
            "reason": reason,
            "target": target,
            "expected_version": expected_version or self.controlled["version"],
        }

    def test_rollback_marks_derived_void_and_new_version(self):
        result = self.service.rollback(
            self.item["id"], self._payload(), "commander", "incident_commander")
        self.assertEqual(result["status"], "contained")
        self.assertEqual(result["version"], self.controlled["version"] + 1)
        rb = result["rollback"]
        self.assertEqual(rb["from"], "controlled")
        self.assertEqual(rb["to"], "contained")
        self.assertFalse(rb["replayed"])
        # 派生记录作废
        for rec in rb["closure_signoffs"]:
            self.assertEqual(rec["status"], "voided")
        for rec in rb["resource_releases"]:
            self.assertEqual(rec["status"], "voided")
        # 未结事项保留
        self.assertEqual(len(rb["open_matters"]), 1)
        self.assertEqual(rb["open_matters"][0]["status"], "open")
        # 原流转与审计事件继续可查
        events = self.service.audit("viewer", self.item["id"])
        actions = [e["action"] for e in events]
        self.assertIn("rollback", actions)
        self.assertIn("transition", actions)
        self.assertTrue(self.repo.verify_audit_chain())

    def test_rollback_requires_commander_role(self):
        with self.assertRaises(PermissionDenied):
            self.service.rollback(
                self.item["id"], self._payload(), "attacker", "viewer")
        with self.assertRaises(PermissionDenied):
            self.service.rollback(
                self.item["id"], self._payload(), "clerk", "logistics")

    def test_rollback_version_conflict_loser_retries_with_new_version(self):
        # 关闭未结事项，使推进到closed的不变量满足
        with self.repo._lock, self.repo.conn:
            self.repo.conn.execute(
                "UPDATE records SET status='closed' WHERE external_ref='EV-1'")
        # 终端A推进到closed（先落账）
        first = self.service.transition(
            self.item["id"], "closed", self.controlled["version"],
            "commander", "incident_commander")
        self.assertEqual(first["version"], self.controlled["version"] + 1)
        # 终端B回退到contained，拿着旧版本 -> 版本冲突
        with self.assertRaises(ConflictError) as ctx:
            self.service.rollback(
                self.item["id"], self._payload(request_no="RB-REQ-B"),
                "commander", "incident_commander")
        self.assertIn(str(first["version"]), str(ctx.exception))
        # B拿着新版本重办回退成功
        retry = self.service.rollback(
            self.item["id"],
            self._payload(request_no="RB-REQ-B", expected_version=first["version"]),
            "commander", "incident_commander")
        self.assertEqual(retry["status"], "contained")
        self.assertEqual(retry["version"], first["version"] + 1)

    def test_rollback_idempotent_replay_no_double_void(self):
        first = self.service.rollback(
            self.item["id"], self._payload(), "commander", "incident_commander")
        # 重复提交同一请求编号 -> 幂等回放
        second = self.service.rollback(
            self.item["id"], self._payload(), "commander", "incident_commander")
        self.assertTrue(second["rollback"]["replayed"])
        self.assertEqual(second["version"], first["version"])
        # 派生记录只作废一次
        voided = [r for r in second["rollback"]["closure_signoffs"] +
                  second["rollback"]["resource_releases"]
                  if r["status"] == "voided"]
        self.assertEqual(len(voided), 2)
        # 审计事件只记录一次回退
        events = self.service.audit("viewer", self.item["id"])
        rb_events = [e for e in events if e["action"] == "rollback"]
        self.assertEqual(len(rb_events), 1)

    def test_rollback_checkpoint_recovery(self):
        # 模拟写入失败：先建立 pending 检查点
        self.repo.create_rollback_request(
            "RB-REQ-CP", self.item["id"], self.controlled["version"],
            "contained", "checkpoint", "commander")
        # 重试同一请求编号 -> 从检查点恢复并落账
        result = self.service.rollback(
            self.item["id"], self._payload(request_no="RB-REQ-CP"),
            "commander", "incident_commander")
        self.assertFalse(result["rollback"]["replayed"])
        self.assertEqual(result["version"], self.controlled["version"] + 1)
        req = self.repo.get_rollback_request("RB-REQ-CP")
        self.assertEqual(req["status"], "committed")

    def test_rollback_missing_fields_rejected(self):
        with self.assertRaises(ValidationError):
            self.service.rollback(
                self.item["id"], {"request_no": "RB-X", "reason": "r",
                                  "expected_version": 1},
                "commander", "incident_commander")
        with self.assertRaises(ValidationError):
            self.service.rollback(
                self.item["id"], {"request_no": "RB-X", "target": "contained",
                                  "expected_version": 1},
                "commander", "incident_commander")
        with self.assertRaises(ValidationError):
            self.service.rollback(
                self.item["id"], {"request_no": "RB-X", "reason": "r",
                                  "target": "contained", "expected_version": 0},
                "commander", "incident_commander")

    def test_rollback_target_must_be_earlier(self):
        with self.assertRaises(ConflictError):
            self.service.rollback(
                self.item["id"], self._payload(target="closed"),
                "commander", "incident_commander")
        with self.assertRaises(ConflictError):
            self.service.rollback(
                self.item["id"], self._payload(target="controlled"),
                "commander", "incident_commander")


class RollbackMigrationTest(unittest.TestCase):
    def test_old_records_migrated_to_version_one(self):
        tmp = tempfile.TemporaryDirectory()
        db_path = str(Path(tmp.name) / "legacy.db")
        # 构造旧库：records 无 version 列，CHECK 不含 voided
        import sqlite3
        conn = sqlite3.connect(db_path)
        conn.executescript("""
            CREATE TABLE items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL, description TEXT NOT NULL,
                severity TEXT NOT NULL, quantity REAL NOT NULL DEFAULT 0,
                threshold REAL NOT NULL DEFAULT 1,
                status TEXT NOT NULL CHECK(status IN ('reported','active','contained','controlled','closed')),
                version INTEGER NOT NULL DEFAULT 1,
                external_ref TEXT, created_by TEXT NOT NULL,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                kind TEXT NOT NULL, detail TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','closed')),
                external_ref TEXT, created_by TEXT NOT NULL, created_at TEXT NOT NULL,
                UNIQUE(item_id, external_ref)
            );
            INSERT INTO items(title,description,severity,quantity,threshold,status,version,created_by,created_at,updated_at)
                VALUES('legacy','legacy desc','high',5,10,'controlled',3,'creator','2026-01-01T00:00:00','2026-01-01T00:00:00');
            INSERT INTO records(item_id,kind,detail,status,external_ref,created_by,created_at)
                VALUES(1,'closure_signoff','old signoff','closed','CS-OLD','recorder','2026-01-01T00:00:00');
        """)
        conn.commit()
        conn.close()
        # 重新打开 -> 触发迁移
        repo = Repository(db_path)
        service = Service(repo)
        recs = service.list_records(1, "viewer")
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["version"], 1)
        # 迁移后回退可正常作废
        result = service.rollback(
            1, {"request_no": "RB-MIG", "reason": "migrated",
                "target": "contained", "expected_version": 3},
            "commander", "incident_commander")
        self.assertEqual(result["status"], "contained")
        self.assertEqual(result["version"], 4)
        self.assertEqual(result["rollback"]["closure_signoffs"][0]["status"], "voided")
        repo.close()
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
