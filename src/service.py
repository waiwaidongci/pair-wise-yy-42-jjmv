from __future__ import annotations

from typing import Any, Dict, Optional

from .domain import (ConflictError, ValidationError, ensure_role,
                     normalize_severity, require_number, require_text)
from .repository import Repository
from .rules import (AUDIT_ROLES, CREATE_ROLES, DERIVED_RECORD_KINDS, ENTITY,
                    RECORD_ROLES, ROLLBACK_ROLES, STATES, TITLE, VIEW_ROLES,
                    completion_blockers, escalation_required, priority_score,
                    response_deadline_hours, role_for_transition,
                    validate_rollback, validate_transition)


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
        """回退补偿：带误判依据与期望版本提交，逐项核对后作废派生记录并生成新版本。

        按请求编号幂等：已完成的请求重放原结果，重复只算一次；失败请求
        保留检查点，拿着新版本重办。
        """
        ensure_role(role, ROLLBACK_ROLES)
        actor = require_text(actor, "actor", 100)
        request_id = require_text(payload.get("request_id"), "request_id", 100)
        reason = require_text(payload.get("reason"), "reason")
        target = payload.get("target_status")
        if target not in STATES:
            raise ValidationError("未知目标状态")
        expected_version = payload.get("expected_version")
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValidationError("expected_version必须是正整数")
        req = self.repository.get_rollback_request(request_id)
        if req is None:
            item = self.repository.get_item(item_id)
            validate_rollback(item["status"], target)
            try:
                req = self.repository.create_rollback_request(
                    request_id, item_id, reason, expected_version, target, actor)
            except ConflictError:
                req = self.repository.get_rollback_request(request_id)
        if req["item_id"] != item_id:
            raise ConflictError("请求编号已被其他事件使用")
        if req["status"] == "completed":
            return req["result"]
        if req["status"] == "failed":
            req = self.repository.reopen_rollback_request(
                request_id, reason, expected_version, target)
        return self._execute_rollback(req)

    def _execute_rollback(self, req: Dict[str, Any]) -> Dict[str, Any]:
        item_id = req["item_id"]
        request_id = req["request_id"]
        checkpoint = dict(req["checkpoint"])
        if not checkpoint.get("compensation_done"):
            item = self.repository.get_item(item_id)
            validate_rollback(item["status"], req["target_status"])
            checks = self._rollback_checks(item_id)
            void_ids = checks["closure_signoffs"] + checks["resource_releases"]
            checkpoint.update(from_status=item["status"], checks=checks,
                              voided_record_ids=void_ids)
            self.repository.save_checkpoint(request_id, checkpoint)
            done_checkpoint = dict(checkpoint, compensation_done=True,
                                   new_version=req["expected_version"] + 1)
            try:
                item = self.repository.apply_rollback(
                    request_id, item_id, req["target_status"],
                    req["expected_version"], void_ids, req["reason"],
                    done_checkpoint)
            except ConflictError as exc:
                self.repository.fail_rollback_request(request_id, str(exc))
                final = self.repository.get_rollback_request(request_id)
                if final["status"] == "completed":
                    return final["result"]
                raise
            checkpoint = done_checkpoint
        if not checkpoint.get("audit_done"):
            item = self.repository.get_item(item_id)
            self.repository.append_rollback_audit(request_id, ENTITY, item_id,
                                                  req["actor"], {
                "request_id": request_id,
                "reason": req["reason"],
                "from": checkpoint["from_status"],
                "to": req["target_status"],
                "expected_version": req["expected_version"],
                "new_version": checkpoint["new_version"],
                "checks": checkpoint["checks"],
                "voided_records": checkpoint["voided_record_ids"],
            }, dict(checkpoint, audit_done=True))
            checkpoint["audit_done"] = True
        item = self.repository.get_item(item_id)
        result = {
            "request_id": request_id,
            "item_id": item_id,
            "reason": req["reason"],
            "from_status": checkpoint["from_status"],
            "to_status": req["target_status"],
            "expected_version": req["expected_version"],
            "new_version": checkpoint["new_version"],
            "checks": checkpoint["checks"],
            "voided_records": checkpoint["voided_record_ids"],
            "item": self.enrich(item),
        }
        self.repository.complete_rollback_request(request_id, result)
        return result

    def _rollback_checks(self, item_id: int) -> Dict[str, Any]:
        """逐项核对关闭签认、未结事项和资源释放，作废前留痕。"""
        records = self.repository.list_records(item_id)
        live = [r for r in records if not r.get("voided_at")]
        return {
            "closure_signoffs": [r["id"] for r in live
                                 if r["kind"] == DERIVED_RECORD_KINDS[0]],
            "resource_releases": [r["id"] for r in live
                                  if r["kind"] == DERIVED_RECORD_KINDS[1]],
            "open_items": [r["id"] for r in live if r["status"] == "open"],
        }

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
