import sqlite3
import tempfile
import unittest
from pathlib import Path

from src.domain import ConflictError, PermissionDenied, ValidationError
from src.repository import Repository
from src.service import Service
from src.rules import STATES, TRANSITION_ROLES


class RollbackTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)
        self.item = self.service.create_item(
            {"title": "night shift fire", "description": "misjudged scene",
             "severity": "high", "quantity": 12, "threshold": 6,
             "external_ref": "RB-ITEM-1"}, "creator", "field_commander")

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def _advance(self, item, up_to):
        current = item
        for target in STATES[1:STATES.index(up_to) + 1]:
            current = self.service.transition(
                current["id"], target, current["version"], "commander",
                TRANSITION_ROLES[target][0])
        return current

    def _prepare(self, up_to):
        signoff = self.service.add_record(
            self.item["id"], {"kind": "closure_signoff", "detail": "关闭签认已发",
                              "status": "closed", "external_ref": "RB-SIGN-1"},
            "recorder", "field_commander")
        release = self.service.add_record(
            self.item["id"], {"kind": "resource_release", "detail": "资源释放已发",
                              "status": "closed", "external_ref": "RB-REL-1"},
            "recorder", "logistics")
        open_note = self.service.add_record(
            self.item["id"], {"kind": "note", "detail": "未结事项",
                              "status": "open", "external_ref": "RB-NOTE-1"},
            "recorder", "field_commander")
        current = self._advance(self.item, up_to)
        return current, signoff, release, open_note

    def _prepare_controlled(self):
        return self._prepare("controlled")

    def _rollback_payload(self, version, request_id="RB-REQ-1"):
        return {"request_id": request_id,
                "reason": "夜间红外误读，火线实际未受控",
                "expected_version": version,
                "target_status": "active"}

    def test_rollback_voids_derived_records_and_keeps_trail(self):
        current, signoff, release, open_note = self._prepare_controlled()
        result = self.service.rollback(
            current["id"], self._rollback_payload(current["version"]),
            "commander", "incident_commander")
        self.assertEqual(result["from_status"], "controlled")
        self.assertEqual(result["to_status"], "active")
        self.assertEqual(result["new_version"], current["version"] + 1)
        self.assertEqual(result["checks"]["closure_signoffs"], [signoff["id"]])
        self.assertEqual(result["checks"]["resource_releases"], [release["id"]])
        self.assertEqual(result["checks"]["open_items"], [open_note["id"]])
        self.assertEqual(sorted(result["voided_records"]),
                         sorted([signoff["id"], release["id"]]))
        item = self.service.get_item(current["id"], "viewer")
        self.assertEqual(item["status"], "active")
        self.assertEqual(item["version"], current["version"] + 1)
        records = {r["id"]: r for r in
                   self.service.list_records(current["id"], "viewer")}
        self.assertEqual(len(records), 3)
        for voided_id in (signoff["id"], release["id"]):
            self.assertIsNotNone(records[voided_id]["voided_at"])
            self.assertEqual(records[voided_id]["voided_by"], "RB-REQ-1")
            self.assertEqual(records[voided_id]["void_reason"],
                             "夜间红外误读，火线实际未受控")
        self.assertIsNone(records[open_note["id"]]["voided_at"])
        events = self.service.audit("viewer", current["id"])
        actions = [e["action"] for e in events]
        self.assertIn("create", actions)
        self.assertIn("transition", actions)
        self.assertEqual(actions.count("rollback"), 1)
        rollback_event = events[actions.index("rollback")]
        self.assertEqual(rollback_event["detail"]["request_id"], "RB-REQ-1")
        self.assertEqual(rollback_event["detail"]["reason"], "夜间红外误读，火线实际未受控")
        self.assertTrue(self.repo.verify_audit_chain())

    def test_rollback_requires_command_role(self):
        current, _, _, _ = self._prepare_controlled()
        for role in ("logistics", "viewer"):
            with self.assertRaises(PermissionDenied):
                self.service.rollback(current["id"],
                                      self._rollback_payload(current["version"]),
                                      "intruder", role)
        result = self.service.rollback(
            current["id"], self._rollback_payload(current["version"]),
            "field-lead", "field_commander")
        self.assertEqual(result["to_status"], "active")

    def test_rollback_validates_target_and_payload(self):
        current, _, _, _ = self._prepare_controlled()
        with self.assertRaises(ConflictError):
            self.service.rollback(current["id"],
                                  self._rollback_payload(current["version"],
                                                         "RB-REQ-BAD-TARGET")
                                  | {"target_status": "reported"},
                                  "commander", "incident_commander")
        with self.assertRaises(ValidationError):
            self.service.rollback(current["id"],
                                  self._rollback_payload(current["version"],
                                                         "RB-REQ-BAD-VER")
                                  | {"expected_version": 0},
                                  "commander", "incident_commander")
        with self.assertRaises(ValidationError):
            self.service.rollback(current["id"],
                                  self._rollback_payload(current["version"],
                                                         "RB-REQ-NO-REASON")
                                  | {"reason": "  "},
                                  "commander", "incident_commander")

    def test_first_commit_wins_and_loser_retries_with_new_version(self):
        current, _, _, _ = self._prepare("contained")
        stale_version = current["version"]
        # 终端B的回退请求先登记（期望版本为当前版本），但尚未落账。
        self.repo.create_rollback_request(
            "RB-REQ-RACE", current["id"], "夜间误推已控", stale_version,
            "active", "commander")
        # 终端A推进 contained -> controlled 先落账，版本推进。
        winner = self.service.transition(
            current["id"], "controlled", stale_version, "commander",
            TRANSITION_ROLES["controlled"][0])
        self.assertEqual(winner["version"], stale_version + 1)
        # 终端B的回退落账时期望版本已过期，先到者生效。
        with self.assertRaises(ConflictError):
            self.service.rollback(
                current["id"], self._rollback_payload(stale_version, "RB-REQ-RACE"),
                "commander", "incident_commander")
        req = self.repo.get_rollback_request("RB-REQ-RACE")
        self.assertEqual(req["status"], "failed")
        # 后到者拿着新版本重办，同一请求编号。
        fresh = self.service.get_item(current["id"], "viewer")
        self.assertEqual(fresh["status"], "controlled")
        result = self.service.rollback(
            current["id"], self._rollback_payload(fresh["version"], "RB-REQ-RACE"),
            "commander", "incident_commander")
        self.assertEqual(result["from_status"], "controlled")
        self.assertEqual(result["new_version"], fresh["version"] + 1)
        final = self.service.get_item(current["id"], "viewer")
        self.assertEqual(final["status"], "active")
        actions = [e["action"] for e in self.service.audit("viewer", current["id"])]
        self.assertIn("transition", actions)
        self.assertEqual(actions.count("rollback"), 1)
        self.assertTrue(self.repo.verify_audit_chain())

    def test_duplicate_request_id_replays_result_once(self):
        current, _, _, _ = self._prepare_controlled()
        payload = self._rollback_payload(current["version"])
        first = self.service.rollback(current["id"], payload, "commander",
                                      "incident_commander")
        version_after = self.service.get_item(current["id"], "viewer")["version"]
        audit_count = len(self.service.audit("viewer", current["id"]))
        replay = self.service.rollback(current["id"], payload, "commander",
                                       "incident_commander")
        self.assertEqual(replay, first)
        self.assertEqual(self.service.get_item(current["id"], "viewer")["version"],
                         version_after)
        self.assertEqual(len(self.service.audit("viewer", current["id"])),
                         audit_count)
        other = self.service.create_item(
            {"title": "other fire", "description": "another scene",
             "severity": "low", "quantity": 1, "threshold": 10,
             "external_ref": "RB-ITEM-2"}, "creator", "field_commander")
        with self.assertRaises(ConflictError):
            self.service.rollback(other["id"], payload, "commander",
                                  "incident_commander")

    def test_resume_from_checkpoint_after_write_failure(self):
        current, signoff, release, _ = self._prepare_controlled()
        payload = self._rollback_payload(current["version"])
        original = self.repo.append_rollback_audit
        calls = {"n": 0}

        def failing_audit(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                raise sqlite3.OperationalError("simulated write failure")
            return original(*args, **kwargs)

        self.repo.append_rollback_audit = failing_audit
        with self.assertRaises(sqlite3.OperationalError):
            self.service.rollback(current["id"], payload, "commander",
                                  "incident_commander")
        self.repo.append_rollback_audit = original
        req = self.repo.get_rollback_request("RB-REQ-1")
        self.assertEqual(req["status"], "pending")
        self.assertTrue(req["checkpoint"]["compensation_done"])
        mid = self.service.get_item(current["id"], "viewer")
        self.assertEqual(mid["status"], "active")
        self.assertEqual(mid["version"], current["version"] + 1)
        result = self.service.rollback(current["id"], payload, "commander",
                                       "incident_commander")
        self.assertEqual(result["new_version"], current["version"] + 1)
        final = self.service.get_item(current["id"], "viewer")
        self.assertEqual(final["version"], current["version"] + 1)
        records = self.service.list_records(current["id"], "viewer")
        voided = [r for r in records if r["voided_at"]]
        self.assertEqual(sorted(r["id"] for r in voided),
                         sorted([signoff["id"], release["id"]]))
        actions = [e["action"] for e in self.service.audit("viewer", current["id"])]
        self.assertEqual(actions.count("rollback"), 1)
        self.assertTrue(self.repo.verify_audit_chain())
        req = self.repo.get_rollback_request("RB-REQ-1")
        self.assertEqual(req["status"], "completed")


class LegacyMigrationTest(unittest.TestCase):
    def test_legacy_rows_without_version_migrate_to_first_version(self):
        tmp = tempfile.TemporaryDirectory()
        db_path = str(Path(tmp.name) / "legacy.db")
        conn = sqlite3.connect(db_path)
        conn.executescript("""
            CREATE TABLE items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT NOT NULL,
                quantity REAL NOT NULL DEFAULT 0,
                threshold REAL NOT NULL DEFAULT 1,
                status TEXT NOT NULL,
                external_ref TEXT,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_id INTEGER NOT NULL,
                kind TEXT NOT NULL,
                detail TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                external_ref TEXT,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
        """)
        conn.execute(
            """INSERT INTO items(title, description, severity, quantity, threshold,
               status, external_ref, created_by, created_at, updated_at)
               VALUES('legacy fire', 'no version column', 'high', 5, 5,
                      'controlled', 'LEG-1', 'old', '2026-10-05T00:00:00+00:00',
                      '2026-10-05T00:00:00+00:00')""")
        conn.execute(
            """INSERT INTO records(item_id, kind, detail, status, external_ref,
               created_by, created_at)
               VALUES(1, 'closure_signoff', '旧关闭签认', 'closed', 'LEG-SIGN-1',
                      'old', '2026-10-05T00:00:00+00:00')""")
        conn.commit()
        conn.close()
        repo = Repository(db_path)
        try:
            item = repo.get_item(1)
            self.assertEqual(item["version"], 1)
            service = Service(repo)
            result = service.rollback(
                1, {"request_id": "LEG-RB-1", "reason": "旧数据误推已控",
                    "expected_version": 1, "target_status": "active"},
                "commander", "incident_commander")
            self.assertEqual(result["new_version"], 2)
            self.assertEqual(result["checks"]["closure_signoffs"], [1])
            record = repo.list_records(1)[0]
            self.assertIsNotNone(record["voided_at"])
            self.assertTrue(repo.verify_audit_chain())
        finally:
            repo.close()
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
