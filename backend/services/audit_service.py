"""Remediation audit trail."""

import re

from backend.core.database import get_db


SENSITIVE_KEY_RE = re.compile(
    r"(password|secret|token|credential|certificate|api.?key|private.?key|client.?certificate|client.?key|tls|ca\.crt|authorization)",
    re.IGNORECASE,
)


def redact(obj):
    """Recursively redact sensitive values without mutating the original."""
    if isinstance(obj, dict):
        result = {}
        for key, value in obj.items():
            # Special-case Secret resource data
            if obj.get("kind") == "Secret" and key == "data":
                result[key] = {k: "[REDACTED]" for k in value} if isinstance(value, dict) else "[REDACTED]"
            elif SENSITIVE_KEY_RE.search(str(key)):
                result[key] = "[REDACTED]"
            else:
                result[key] = redact(value)
        return result
    if isinstance(obj, list):
        return [redact(item) for item in obj]
    return obj


def _timestamp_for(timestamps, state):
    for t in reversed(timestamps):
        if t.get("state") == state:
            return t.get("at")
    return None


def _audit_doc(doc: dict, policy_decision=None) -> dict:
    plan = doc.get("plan") or {}
    target = plan.get("target") or {}
    diagnosis = doc.get("diagnosis") or {}
    timestamps = doc.get("timestamps") or []

    return {
        "remediation_id": str(doc["_id"]),
        "investigation_id": str(doc["investigation_id"]),
        "incident_id": str(doc["investigation_id"]),
        "timestamp": doc.get("updated_at"),
        "affected_cluster": doc.get("context"),
        "namespace": target.get("namespace"),
        "kind": target.get("kind"),
        "resource": target.get("name"),
        "diagnosis": redact({
            "root_cause": diagnosis.get("root_cause"),
            "explanation": diagnosis.get("explanation"),
            "incident_type": diagnosis.get("incident_type"),
            "confidence": diagnosis.get("confidence"),
            "affected_resources": diagnosis.get("affected_resources"),
            "status": diagnosis.get("status"),
            "evidence_references": [
                {"source": e.get("source"), "description": e.get("description")}
                for e in (diagnosis.get("evidence") or [])
            ],
        }),
        "confidence": diagnosis.get("confidence"),
        "proposed_operation": {
            "tool": plan.get("tool"),
            "arguments": redact(plan.get("arguments") or {}),
            "risk": plan.get("risk"),
            "summary": plan.get("summary"),
        },
        "previewed_changes": redact(plan.get("changes") or []),
        "policy_decision": redact(policy_decision or doc.get("policy_decision")),
        "approval_status": _approval_status(timestamps),
        "approval_timestamp": _timestamp_for(timestamps, "APPROVED"),
        "execution_start": _timestamp_for(timestamps, "EXECUTING"),
        "execution_end": _execution_end(timestamps),
        "execution_result": redact(doc.get("kubernetes_response")),
        "verification_result": redact(doc.get("verification_result")),
        "rollback_information": redact(doc.get("rollback_plan")),
        "rollback_result": redact(doc.get("rollback_response")),
        "pre_change_state": redact(doc.get("pre_change_state")),
        "status": doc.get("status"),
        "error": doc.get("error"),
    }


def _approval_status(timestamps):
    states = {t.get("state") for t in timestamps}
    if "ROLLED_BACK" in states:
        return "ROLLED_BACK"
    if "REJECTED" in states:
        return "REJECTED"
    if "APPROVED" in states:
        return "APPROVED"
    if "EXECUTING" in states:
        return "APPROVED"
    if "FAILED" in states and "APPROVED" not in states:
        return "REJECTED"
    return "PENDING"


def _execution_end(timestamps):
    for t in reversed(timestamps):
        if t.get("state") in ("RESOLVED", "FAILED", "NOT_RESOLVED", "ROLLED_BACK", "ROLLBACK_FAILED"):
            return t.get("at")
    return None


def create_or_update_audit(doc: dict, policy_decision=None) -> None:
    """Persist or refresh an audit record for a remediation document."""
    db = get_db()
    audit_doc = _audit_doc(doc, policy_decision)
    db.audit.update_one(
        {"remediation_id": audit_doc["remediation_id"]},
        {"$set": audit_doc},
        upsert=True,
    )


def get_audit(remediation_id: str) -> dict | None:
    db = get_db()
    return db.audit.find_one({"remediation_id": remediation_id})


def record_execution(doc: dict, policy_decision: dict) -> None:
    create_or_update_audit(doc, policy_decision)


def record_rollback(doc: dict) -> None:
    create_or_update_audit(doc)
