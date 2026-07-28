import time
from datetime import datetime, timezone, timedelta

from bson.objectid import ObjectId

from backend.ai.remediation_planner import RemediationPlanner
from backend.core.database import get_db
from backend.core.logging import logger
from backend.core.policy_engine import PolicyEngine
from backend.kubernetes.toolkit import K8sToolkit
from backend.services import audit_service
from backend.services.verification_service import verify_remediation

PREVIEW_STALE_MINUTES = 10


def _now():
    return datetime.now(timezone.utc)


def _plan_execution_status(plan: dict) -> str:
    status = plan.get("status")
    if status == "READY":
        return "AWAITING_APPROVAL"
    if status == "NEED_USER_INPUT":
        return "NEED_USER_INPUT"
    return status or "NO_SAFE_REMEDIATION"


def _timestamp(state: str) -> dict:
    return {"state": state, "at": _now()}


def _push_timestamp(doc: dict, state: str) -> None:
    doc["timestamps"] = doc.get("timestamps", []) + [_timestamp(state)]


def create_remediation(
    investigation_id: str,
    plan: dict,
    diagnosis: dict,
    context: str | None = None,
) -> str:
    """Create a remediation document after an investigation and return its id."""
    db = get_db()
    status = _plan_execution_status(plan)
    now = _now()
    doc = {
        "investigation_id": investigation_id,
        "plan": plan,
        "diagnosis": diagnosis,
        "context": context,
        "status": status,
        "execution_id": None,
        "pre_change_state": None,
        "rollback_plan": None,
        "kubernetes_response": None,
        "rollback_response": None,
        "verification_result": None,
        "policy_decision": None,
        "error": None,
        "timestamps": [
            _timestamp("CREATED"),
            _timestamp(status),
        ],
        "created_at": now,
        "updated_at": now,
    }
    result = db.remediations.insert_one(doc)
    remediation_id = str(result.inserted_id)
    doc["_id"] = result.inserted_id

    db.investigations.update_one(
        {"_id": ObjectId(investigation_id)},
        {
            "$set": {
                "remediation_id": remediation_id,
                "remediation_plan": plan,
                "remediation_status": status,
                "remediation_timeline": [],
                "remediation_error": None,
                "remediation_verification": None,
                "updated_at": now,
            }
        },
    )

    try:
        audit_service.create_or_update_audit(doc)
    except Exception:
        logger.exception("Failed to create initial audit record")

    return remediation_id


def preview_remediation(
    remediation_id: str,
    user_input: dict | None = None,
) -> dict:
    """Regenerate a remediation plan (preview) for a remediation document."""
    db = get_db()
    doc = db.remediations.find_one({"_id": ObjectId(remediation_id)})
    if not doc:
        raise ValueError("Remediation not found")

    if doc["status"] in (
        "EXECUTING",
        "VERIFYING",
        "RESOLVED",
        "FAILED",
        "ROLLING_BACK",
        "ROLLED_BACK",
        "ROLLBACK_FAILED",
    ):
        raise ValueError("Cannot preview a remediation that is already in progress or finished")

    plan = RemediationPlanner(context=doc.get("context")).plan(
        doc["diagnosis"], user_input=user_input
    )
    status = _plan_execution_status(plan)
    now = _now()

    # If the planner resolves a concrete target (e.g. the owning Deployment),
    # record it as an affected resource so execution policy validation passes.
    target = plan.get("target") or {}
    if target.get("kind") and target.get("name"):
        target_id = (
            f"{target['kind']}/{target.get('namespace') or 'default'}/{target['name']}"
        ).lower()
        for key in ("affected_resources", "affectedResources"):
            if key in doc["diagnosis"]:
                existing = doc["diagnosis"][key]
                if isinstance(existing, list) and target_id not in existing:
                    existing.append(target_id)
                break
        else:
            doc["diagnosis"]["affected_resources"] = [target_id]

    doc["plan"] = plan
    doc["status"] = status
    doc["updated_at"] = now
    _push_timestamp(doc, status)

    db.remediations.update_one(
        {"_id": ObjectId(remediation_id)},
        {
            "$set": {
                "plan": plan,
                "diagnosis": doc["diagnosis"],
                "status": status,
                "updated_at": now,
                "timestamps": doc["timestamps"],
            }
        },
    )

    db.investigations.update_one(
        {"_id": ObjectId(doc["investigation_id"])},
        {
            "$set": {
                "remediation_plan": plan,
                "remediation_status": status,
                "updated_at": now,
            }
        },
    )

    try:
        audit_service.create_or_update_audit(doc)
    except Exception:
        logger.exception("Failed to update audit record after preview")

    return {"remediation_status": status, "remediation_plan": plan}


def reject_remediation(remediation_id: str) -> dict:
    db = get_db()
    doc = db.remediations.find_one({"_id": ObjectId(remediation_id)})
    if not doc:
        raise ValueError("Remediation not found")
    if doc["status"] in (
        "EXECUTING",
        "VERIFYING",
        "RESOLVED",
        "FAILED",
        "ROLLING_BACK",
        "ROLLED_BACK",
        "ROLLBACK_FAILED",
    ):
        raise ValueError("Cannot reject a remediation that is already in progress or finished")
    now = _now()
    status = "REJECTED"
    _push_timestamp(doc, status)
    db.remediations.update_one(
        {"_id": ObjectId(remediation_id)},
        {"$set": {"status": status, "updated_at": now, "timestamps": doc["timestamps"]}},
    )
    db.investigations.update_one(
        {"_id": ObjectId(doc["investigation_id"])},
        {"$set": {"remediation_status": status, "updated_at": now}},
    )

    try:
        audit_service.create_or_update_audit(doc)
    except Exception:
        logger.exception("Failed to update audit record after reject")

    return {"remediation_status": status}


def execute_remediation(remediation_id: str) -> dict:
    """Execute an approved remediation plan using stored, immutable tool+arguments."""
    db = get_db()
    doc = db.remediations.find_one({"_id": ObjectId(remediation_id)})
    if not doc:
        raise ValueError("Remediation not found")

    if doc["status"] != "AWAITING_APPROVAL":
        raise ValueError(f"Remediation cannot be executed from status '{doc['status']}'")

    updated_at = doc["updated_at"]
    if getattr(updated_at, "tzinfo", None) is None:
        updated_at = updated_at.replace(tzinfo=timezone.utc)
    if _now() - updated_at > timedelta(minutes=PREVIEW_STALE_MINUTES):
        _fail(db, doc, "Preview is stale; regenerate the plan before executing")
        raise ValueError("Preview is stale; regenerate the plan before executing")

    plan = doc["plan"]
    tool_name = plan.get("tool")
    arguments = plan.get("arguments") or {}
    target = plan.get("target") or {}
    diagnosis = doc["diagnosis"]

    toolkit = K8sToolkit(context=doc.get("context"))
    engine = PolicyEngine()
    policy = engine.validate(plan, diagnosis=diagnosis, toolkit=toolkit)
    if not policy.get("allowed"):
        _fail(db, doc, "; ".join(str(v) for v in policy.get("violations", [])))
        raise ValueError("Policy validation failed")

    doc["policy_decision"] = policy

    # Capture pre-change state and rollback information BEFORE execution
    pre_change = None
    if target.get("kind") and target.get("name"):
        pre = toolkit.get_resource(
            target["kind"], target.get("namespace"), target["name"]
        )
        if pre.get("success"):
            pre_change = pre.get("data")

    rollback_plan = _build_rollback_plan(plan, pre_change)

    # Record approval and start execution
    execution_id = str(ObjectId())
    now = _now()
    doc["status"] = "EXECUTING"
    doc["execution_id"] = execution_id
    doc["pre_change_state"] = pre_change
    doc["rollback_plan"] = rollback_plan
    _push_timestamp(doc, "APPROVED")
    _push_timestamp(doc, "EXECUTING")
    _update_doc(db, doc)
    _update_investigation(db, doc)
    _update_audit(db, doc, policy)

    # Execute the stored tool using the stored arguments only
    tool = getattr(toolkit, tool_name, None)
    if tool is None:
        _fail(db, doc, f"Unknown tool '{tool_name}'")
        raise ValueError(f"Unknown tool '{tool_name}'")

    try:
        result = tool(**arguments)
    except Exception as exc:
        _fail(db, doc, str(exc))
        raise

    if not result.get("success"):
        _fail(db, doc, str(result.get("error")))
        raise ValueError(f"Kubernetes operation failed: {result.get('error')}")

    doc["kubernetes_response"] = result
    doc["status"] = "VERIFYING"
    _push_timestamp(doc, "VERIFYING")
    _update_doc(db, doc)
    _update_investigation(db, doc)
    _update_audit(db, doc, policy)

    # Verification: poll briefly to allow the cluster to converge before deciding
    verification: dict = {"status": "NOT_RESOLVED", "checks": []}
    deadline = _now() + timedelta(seconds=180)
    while _now() < deadline:
        try:
            verification = verify_remediation(target, plan, toolkit)
        except Exception as exc:
            verification = {
                "status": "NOT_RESOLVED",
                "checks": [{"name": "Verification", "status": "FAIL"}],
                "error": str(exc),
            }
        if verification.get("status") == "RESOLVED":
            break
        time.sleep(5)

    doc["verification_result"] = verification

    if verification.get("status") == "RESOLVED":
        _resolve(db, doc)
    else:
        _verification_failed(db, doc, verification)

    _update_audit(db, doc, policy)

    return {
        "remediation_status": doc["status"],
        "execution_id": doc["execution_id"],
        "verification_result": doc.get("verification_result"),
    }


def rollback_remediation(remediation_id: str) -> dict:
    """Rollback a remediation that has been executed and verified or failed."""
    db = get_db()
    doc = db.remediations.find_one({"_id": ObjectId(remediation_id)})
    if not doc:
        raise ValueError("Remediation not found")

    if doc["status"] not in ("FAILED", "NOT_RESOLVED", "ROLLED_BACK", "ROLLBACK_FAILED"):
        raise ValueError(f"Remediation cannot be rolled back from status '{doc['status']}'")

    target = doc["plan"].get("target") or {}
    diagnosis = doc["diagnosis"]
    rollback_plan = doc.get("rollback_plan")

    if not rollback_plan:
        _rollback_failed(db, doc, "No rollback plan was recorded")
        raise ValueError("No rollback plan was recorded")

    toolkit = K8sToolkit(context=doc.get("context"))

    # 1. validate target exists
    existing = toolkit.get_resource(target["kind"], target.get("namespace"), target["name"])
    if not existing.get("success"):
        _rollback_failed(db, doc, "Target does not exist")
        raise ValueError("Target does not exist")

    # 2. validate rollback policy
    engine = PolicyEngine()
    policy = engine.validate(rollback_plan, diagnosis=diagnosis, toolkit=toolkit)
    if not policy.get("allowed"):
        _rollback_failed(db, doc, "; ".join(str(v) for v in policy.get("violations", [])))
        raise ValueError("Rollback policy validation failed")

    # 3. record rollback action
    rollback_execution_id = str(ObjectId())
    doc["status"] = "ROLLING_BACK"
    doc["rollback_execution_id"] = rollback_execution_id
    _push_timestamp(doc, "ROLLING_BACK")
    _update_doc(db, doc)
    _update_investigation(db, doc)
    _update_audit(db, doc)

    # 4. execute rollback
    rollback_tool = getattr(toolkit, rollback_plan["tool"], None)
    if rollback_tool is None:
        _rollback_failed(db, doc, f"Unknown rollback tool '{rollback_plan['tool']}'")
        raise ValueError(f"Unknown rollback tool '{rollback_plan['tool']}'")

    try:
        rollback_result = rollback_tool(**rollback_plan["arguments"])
    except Exception as exc:
        _rollback_failed(db, doc, str(exc))
        raise

    if not rollback_result.get("success"):
        _rollback_failed(db, doc, str(rollback_result.get("error")))
        raise ValueError(f"Rollback operation failed: {rollback_result.get('error')}")

    doc["rollback_response"] = rollback_result

    # 5. verify rollback
    doc["status"] = "VERIFYING"
    _push_timestamp(doc, "VERIFYING")
    _update_doc(db, doc)
    _update_investigation(db, doc)
    _update_audit(db, doc)

    try:
        verification = verify_remediation(target, rollback_plan, toolkit)
    except Exception as exc:
        verification = {
            "status": "NOT_RESOLVED",
            "checks": [{"name": "Rollback verification", "status": "FAIL"}],
            "error": str(exc),
        }

    doc["verification_result"] = verification

    if verification.get("status") == "RESOLVED":
        _rolled_back(db, doc)
    else:
        _rollback_failed(db, doc, "Rollback did not restore the resource")

    _update_audit(db, doc)

    return {
        "remediation_status": doc["status"],
        "rollback_execution_id": doc.get("rollback_execution_id"),
        "verification_result": doc.get("verification_result"),
    }


def get_remediation(remediation_id: str) -> dict | None:
    db = get_db()
    return db.remediations.find_one({"_id": ObjectId(remediation_id)})


def _build_rollback_plan(plan: dict, pre_change_state: dict | None) -> dict | None:
    """Determine rollback information BEFORE execution."""
    if not pre_change_state:
        return None

    target = plan.get("target") or {}
    kind = (target.get("kind") or "").lower()
    namespace = target.get("namespace")
    name = target.get("name")
    tool = plan.get("tool")
    resource = pre_change_state.get("resource") or pre_change_state or {}

    # Prefer Deployment rollout revision/history for Deployment targets
    if kind == "deployment" and tool != "scale_workload":
        return {
            "tool": "rollback_workload",
            "arguments": {
                "kind": "deployment",
                "namespace": namespace,
                "name": name,
            },
            "reason": "rollout undo",
        }

    if tool == "scale_workload":
        old_replicas = resource.get("spec", {}).get("replicas")
        return {
            "tool": "scale_workload",
            "arguments": {
                "kind": kind,
                "namespace": namespace,
                "name": name,
                "replicas": old_replicas,
            },
            "reason": "restore replica count",
        }

    if tool == "apply_resource":
        return {
            "tool": "apply_resource",
            "arguments": {"manifest": resource},
            "reason": "re-apply original manifest",
        }

    if tool == "patch_resource":
        original_patch = plan.get("arguments", {}).get("patch", {})
        inverse = _inverse_patch(original_patch, resource)
        return {
            "tool": "patch_resource",
            "arguments": {
                "kind": kind,
                "namespace": namespace,
                "name": name,
                "patch": inverse,
            },
            "reason": "restore changed fields",
        }

    return None


def _inverse_patch(patch: dict, old_resource: dict) -> dict:
    """Build a patch that restores the top-level keys changed by the original patch."""
    inverse = {}
    for key in patch:
        if isinstance(old_resource, dict) and key in old_resource:
            inverse[key] = old_resource[key]
        else:
            inverse[key] = None
    return inverse


def _update_doc(db, doc: dict) -> None:
    db.remediations.update_one(
        {"_id": doc["_id"]},
        {
            "$set": {
                "status": doc["status"],
                "execution_id": doc.get("execution_id"),
                "rollback_execution_id": doc.get("rollback_execution_id"),
                "pre_change_state": doc.get("pre_change_state"),
                "rollback_plan": doc.get("rollback_plan"),
                "kubernetes_response": doc.get("kubernetes_response"),
                "rollback_response": doc.get("rollback_response"),
                "verification_result": doc.get("verification_result"),
                "policy_decision": doc.get("policy_decision"),
                "error": doc.get("error"),
                "timestamps": doc["timestamps"],
                "updated_at": _now(),
            }
        },
    )


def _update_investigation(db, doc: dict) -> None:
    db.investigations.update_one(
        {"_id": ObjectId(doc["investigation_id"])},
        {
            "$set": {
                "remediation_status": doc["status"],
                "remediation_error": doc.get("error"),
                "remediation_verification": doc.get("verification_result"),
                "updated_at": _now(),
            }
        },
    )


def _update_audit(db, doc: dict, policy_decision=None) -> None:
    try:
        audit_service.create_or_update_audit(doc, policy_decision)
    except Exception:
        logger.exception("Failed to update audit record")


def _fail(db, doc: dict, error: str) -> None:
    doc["status"] = "FAILED"
    doc["error"] = error
    _push_timestamp(doc, "FAILED")
    _update_doc(db, doc)
    _update_investigation(db, doc)
    logger.error(f"Remediation {doc.get('_id')} failed: {error}")


def _verification_failed(db, doc: dict, verification: dict) -> None:
    doc["status"] = "FAILED"
    doc["error"] = "Remediation did not resolve the incident"
    doc["verification_result"] = verification
    _push_timestamp(doc, "FAILED")
    _update_doc(db, doc)
    _update_investigation(db, doc)
    logger.warning(f"Remediation {doc.get('_id')} did not resolve: {verification}")


def _resolve(db, doc: dict) -> None:
    doc["status"] = "RESOLVED"
    _push_timestamp(doc, "RESOLVED")
    _update_doc(db, doc)
    _update_investigation(db, doc)


def _rolled_back(db, doc: dict) -> None:
    doc["status"] = "ROLLED_BACK"
    _push_timestamp(doc, "ROLLED_BACK")
    _update_doc(db, doc)
    _update_investigation(db, doc)


def _rollback_failed(db, doc: dict, error: str) -> None:
    doc["status"] = "ROLLBACK_FAILED"
    doc["error"] = error
    _push_timestamp(doc, "ROLLBACK_FAILED")
    _update_doc(db, doc)
    _update_investigation(db, doc)
    logger.error(f"Rollback {doc.get('_id')} failed: {error}")
