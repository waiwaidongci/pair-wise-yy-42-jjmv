from __future__ import annotations

from typing import Any, Dict, Optional

from .domain import ensure_role, normalize_severity, require_number, require_text
from .repository import Repository
from .rules import (AUDIT_ROLES, CLOSURE_SIGNOFF_KIND, CREATE_ROLES,
                    DERIVED_KINDS, ENTITY, RECORD_ROLES, RESOURCE_RELEASE_KIND,
                    ROLLBACK_ROLES, TITLE, VIEW_ROLES, completion_blockers,
                    escalation_required, priority_score, response_deadline_hours,
                    role_for_transition, validate_rollback, validate_transition)


class Service:
    def __init__(self, repository: Repository):
        self.repository = repository

    def _view(self, role: str) -> None:
        ensure_role(role, VIEW_ROLES)

    def create_item(self, payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, CREATE_ROLES)
        actor = require_text(actor, "actor", 100)
        title = require_text(payload.get("title"), "title", 200)
        description = require_text(payload.get("description"), "description")
        severity = normalize_severity(payload.get("severity"))
        quantity = require_number(payload.get("quantity", 0), "quantity")
        threshold = require_number(payload.get("threshold", 1), "threshold", 0.000001)
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        item = self.repository.create_item(title, description, severity, quantity,
                                           threshold, external_ref, actor)
        self.repository.append_audit("create", ENTITY, item["id"], actor, {
            "title": title, "severity": severity, "quantity": quantity,
            "priority": priority_score(severity, quantity, threshold),
        })
        return self.enrich(item)

    def add_record(self, item_id: int, payload: Dict[str, Any], actor: str,
                   role: str) -> Dict[str, Any]:
        ensure_role(role, RECORD_ROLES)
        actor = require_text(actor, "actor", 100)
        kind = require_text(payload.get("kind"), "kind", 100)
        detail = require_text(payload.get("detail"), "detail")
        status = payload.get("status", "open")
        if status not in ("open", "closed"):
            raise ValueError("status必须是open或closed")
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        record = self.repository.add_record(item_id, kind, detail, status,
                                            external_ref, actor)
        self.repository.append_audit("record", ENTITY, item_id, actor, {
            "record_id": record["id"], "kind": kind, "status": status,
        })
        return record

    def transition(self, item_id: int, target: str, expected_version: int,
                   actor: str, role: str) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        validate_transition(item["status"], target)
        ensure_role(role, role_for_transition(target))
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValueError("expected_version必须是正整数")
        blockers = completion_blockers(target, self.repository.open_record_count(item_id))
        if blockers:
            from .domain import ConflictError
            raise ConflictError("；".join(blockers))
        updated = self.repository.transition_item(item_id, target, expected_version, actor)
        self.repository.append_audit("transition", ENTITY, item_id, actor, {
            "from": item["status"], "to": target,
            "escalation_required": escalation_required(
                item["severity"], item["quantity"], item["threshold"]),
        })
        return self.enrich(updated)

    def rollback(self, item_id: int, payload: Dict[str, Any], actor: str,
                 role: str) -> Dict[str, Any]:
        """补偿回退：误判依据 + 期望版本 + 目标状态。

        仅指挥角色可提交。系统先逐项核对关闭签认、未结事项、资源释放，
        再把派生记录标记作废并生成新版本；原流转与审计事件继续可查。
        写入失败后从检查点恢复，按请求编号重试且重复只算一次。
        """
        from .domain import ValidationError
        ensure_role(role, ROLLBACK_ROLES)
        actor = require_text(actor, "actor", 100)
        request_no = require_text(payload.get("request_no"), "request_no", 100)
        reason = require_text(payload.get("reason"), "reason")
        target = require_text(payload.get("target"), "target", 100)
        expected_version = payload.get("expected_version")
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValidationError("expected_version必须是正整数")

        existing = self.repository.get_rollback_request(request_no)
        replayed = False
        voided = []
        if existing is not None and existing["status"] == "committed":
            # 重复提交：幂等回放，不重复落账
            replayed = True
            updated = self.repository.get_item(item_id)
            rb_audit = self._rollback_audit(request_no)
            from_status = rb_audit["from"] if rb_audit else updated["status"]
            to_status = rb_audit["to"] if rb_audit else target
        else:
            item = self.repository.get_item(item_id)
            validate_rollback(item["status"], target)
            if existing is None:
                self.repository.create_rollback_request(
                    request_no, item_id, expected_version, target, reason, actor)
            else:
                # pending/aborted：从检查点恢复，携带新版本重办
                self.repository.update_rollback_request(
                    request_no, expected_version=expected_version, status="pending")
            updated, voided = self.repository.apply_rollback(
                item_id, target, expected_version, request_no)
            self.repository.append_audit("rollback", ENTITY, item_id, actor, {
                "request_no": request_no,
                "reason": reason,
                "from": item["status"],
                "to": target,
                "expected_version": expected_version,
                "closure_signoffs_voided": sum(
                    1 for r in voided if r["kind"] == CLOSURE_SIGNOFF_KIND),
                "resource_releases_voided": sum(
                    1 for r in voided if r["kind"] == RESOURCE_RELEASE_KIND),
            })
            from_status = item["status"]
            to_status = target

        # 逐项核对：关闭签认、资源释放（派生记录）与未结事项
        all_records = self.repository.list_records(item_id)
        closure_signoffs = [r for r in all_records if r["kind"] == CLOSURE_SIGNOFF_KIND]
        resource_releases = [r for r in all_records if r["kind"] == RESOURCE_RELEASE_KIND]
        open_matters = [r for r in all_records
                        if r["status"] == "open" and r["kind"] not in DERIVED_KINDS]

        result = self.enrich(updated)
        result["rollback"] = {
            "request_no": request_no,
            "from": from_status,
            "to": to_status,
            "closure_signoffs": closure_signoffs,
            "resource_releases": resource_releases,
            "open_matters": open_matters,
            "replayed": replayed,
        }
        return result

    def _rollback_audit(self, request_no: str) -> Optional[Dict[str, Any]]:
        events = self.repository.list_audit()
        for event in events:
            if event["action"] == "rollback" and event["detail"].get("request_no") == request_no:
                return event["detail"]
        return None

    def get_item(self, item_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        return self.enrich(self.repository.get_item(item_id))

    def list_items(self, role: str, status: Optional[str] = None) -> list:
        self._view(role)
        return [self.enrich(item) for item in self.repository.list_items(status)]

    def list_records(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_records(item_id)

    def audit(self, role: str, item_id: Optional[int] = None) -> list:
        ensure_role(role, AUDIT_ROLES)
        return self.repository.list_audit(item_id)

    @staticmethod
    def enrich(item: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(item)
        result["priority"] = priority_score(
            item["severity"], item["quantity"], item["threshold"])
        result["deadline_hours"] = response_deadline_hours(
            item["severity"], item["quantity"], item["threshold"])
        result["escalation_required"] = escalation_required(
            item["severity"], item["quantity"], item["threshold"])
        return result
