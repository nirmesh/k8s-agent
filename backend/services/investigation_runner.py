from datetime import datetime, timezone

from bson.objectid import ObjectId

from backend.core.database import get_db
from backend.core.logging import logger
from backend.kubernetes.executor import set_context
from backend.services.investigation_service import run_investigation


def create_investigation(user_id: str) -> str:
    """Create a pending investigation record and return its id."""
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
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    result = db.investigations.insert_one(doc)
    return str(result.inserted_id)


def _progress_callback(db, investigation_id: str):
    def callback(step: str):
        db.investigations.update_one(
            {"_id": ObjectId(investigation_id)},
            {
                "$push": {"steps": {"name": step, "completed": True, "timestamp": datetime.now(timezone.utc)}},
                "$set": {"updated_at": datetime.now(timezone.utc)},
            },
        )
    return callback


def run_and_save(investigation_id: str, context: str | None = None) -> None:
    """Run the read-only investigation and persist evidence and diagnosis."""
    set_context(context)
    db = get_db()
    db.investigations.update_one({"_id": ObjectId(investigation_id)}, {"$set": {"status": "running"}})
    try:
        result = run_investigation(progress_callback=_progress_callback(db, investigation_id), context=context)
        diagnosis = result.get("diagnosis", {})
        affected = diagnosis.get("affected_resources") or []
        namespace = ""
        if affected:
            parts = str(affected[0]).split("/")
            if len(parts) == 3:
                namespace = parts[1]

        db.investigations.update_one(
            {"_id": ObjectId(investigation_id)},
            {"$set": {
                "status": "completed",
                "pods": result.get("pods", {}),
                "logs": result.get("logs", {}),
                "events": result.get("events", {}),
                "deployments": result.get("deployments", {}),
                "network": result.get("network", {}),
                "operational_evidence": result.get("operational_evidence", []),
                "security_evidence": result.get("security_evidence", []),
                "security_summary": result.get("security_summary", {}),
                "diagnosis": diagnosis,
                "remediation_plan": None,
                "root_cause": diagnosis.get("root_cause", ""),
                "namespace": namespace,
                "confidence": diagnosis.get("confidence", 0),
                "updated_at": datetime.now(timezone.utc),
            }},
        )
    except Exception as exc:
        logger.error(f"Investigation {investigation_id} failed: {exc}")
        db.investigations.update_one(
            {"_id": ObjectId(investigation_id)},
            {"$set": {"status": "failed", "error": str(exc), "updated_at": datetime.now(timezone.utc)}},
        )
    finally:
        set_context(None)
