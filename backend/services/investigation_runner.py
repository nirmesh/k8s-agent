from datetime import datetime, timezone
from typing import Callable

from bson.objectid import ObjectId

from backend.core.database import get_db
from backend.core.logging import logger
from backend.evidence.security import SecurityEvidenceCollector
from backend.evidence.security.scoring import score_security_posture
from backend.kubernetes.executor import set_context
from backend.kubernetes.toolkit import K8sToolkit
from backend.services.investigation_service import run_investigation
from backend.services.security_evidence_store import persist_security_evidence


def create_investigation(user_id: str) -> str:
    db = get_db()
    doc = {
        "user_id": user_id,
        "status": "pending",
        "steps": [],
        "pods": {},
        "logs": {},
        "events": {},
        "deployments": {},
        "network": {},
        "diagnosis": None,
        "root_cause": "",
        "namespace": "",
        "confidence": 0,
        "remediation_plan": None,
        "correlated_incidents": [],
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    return str(db.investigations.insert_one(doc).inserted_id)


def _progress_callback(db, investigation_id: str):
    def callback(step: str, completed: bool = True, detail: str | None = None):
        now = datetime.now(timezone.utc)
        if completed:
            db.investigations.update_one(
                {"_id": ObjectId(investigation_id)},
                {
                    "$set": {"updated_at": now},
                    "$push": {"steps": {"name": step, "status": "completed", "completed": True, "detail": detail or "", "timestamp": now}},
                },
            )
        else:
            db.investigations.update_one(
                {"_id": ObjectId(investigation_id)},
                {
                    "$set": {"updated_at": now},
                    "$pull": {"steps": {"name": step}},
                },
            )
            db.investigations.update_one(
                {"_id": ObjectId(investigation_id)},
                {
                    "$set": {"updated_at": now},
                    "$push": {"steps": {"name": step, "status": "running", "completed": False, "detail": detail or "", "timestamp": now}},
                },
            )
    return callback


def run_and_save(investigation_id: str, context: str | None = None) -> None:
    set_context(context)
    db = get_db()
    db.investigations.update_one({"_id": ObjectId(investigation_id)}, {"$set": {"status": "running", "updated_at": datetime.now(timezone.utc)}})
    try:
        security_collection = SecurityEvidenceCollector(K8sToolkit(context=context)).collect()
        security_evidence = security_collection.get("evidence") or []
        security_summary = score_security_posture(security_collection.get("summary") or {})
        security_evidence_json = [e.model_dump(mode="json") for e in security_evidence]
        security_precomputed = {
            "security_evidence": security_evidence_json,
            "security_summary": security_summary,
        }
        security_evidence_count = persist_security_evidence(db, investigation_id, security_evidence)
        now = datetime.now(timezone.utc)
        db.investigations.update_one(
            {"_id": ObjectId(investigation_id)},
            {
                "$set": {
                    "security_evidence_count": security_evidence_count,
                    "security_summary": security_summary,
                    "security_scan_completed": True,
                    "updated_at": now,
                },
                "$push": {"steps": {"name": "Security Scan", "status": "completed", "completed": True, "detail": "Live provider evidence collected", "timestamp": now}},
            },
        )

        result = run_investigation(
            progress_callback=_progress_callback(db, investigation_id),
            context=context,
            security_precomputed=security_precomputed,
        )
        diagnosis = result.get("diagnosis", {})
        affected = diagnosis.get("affected_resources") or []
        namespace = ""
        if affected:
            parts = str(affected[0]).split("/")
            if len(parts) == 3:
                namespace = parts[1]

        security_evidence_count = persist_security_evidence(db, investigation_id, security_evidence)
        now = datetime.now(timezone.utc)
        db.investigations.update_one(
            {"_id": ObjectId(investigation_id)},
            {
                "$set": {
                    "status": "completed",
                    "pods": result.get("pods", {}),
                    "logs": result.get("logs", {}),
                    "events": result.get("events", {}),
                    "deployments": result.get("deployments", {}),
                    "network": result.get("network", {}),
                    "operational_evidence": result.get("operational_evidence", []),
                    "correlated_incidents": result.get("correlated_incidents", []),
                    "security_evidence_count": security_evidence_count,
                    "security_summary": result.get("security_summary", security_summary),
                    "diagnosis": diagnosis,
                    "remediation_plan": None,
                    "root_cause": diagnosis.get("root_cause", ""),
                    "namespace": namespace,
                    "confidence": diagnosis.get("confidence", 0),
                    "updated_at": now,
                },
            },
        )
    except Exception as exc:
        logger.error(f"Investigation {investigation_id} failed: {exc}")
        db.investigations.update_one(
            {"_id": ObjectId(investigation_id)},
            {"$set": {"status": "failed", "error": str(exc), "updated_at": datetime.now(timezone.utc)}},
        )
    finally:
        set_context(None)
