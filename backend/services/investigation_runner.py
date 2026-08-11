from datetime import datetime, timezone

from bson.objectid import ObjectId

from backend.core.database import get_db
from backend.core.logging import logger
from backend.kubernetes.executor import set_context
from backend.services.investigation_service import run_investigation
from backend.services.remediation_service import create_remediation


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
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    result = db.investigations.insert_one(doc)
    return str(result.inserted_id)


def _progress_callback(db, investigation_id: str):
    """Return a callback that writes a completed step to Mongo."""
    def callback(step: str):
        db.investigations.update_one(
            {"_id": ObjectId(investigation_id)},
            {
                "$push": {
                    "steps": {
                        "name": step,
                        "completed": True,
                        "timestamp": datetime.now(timezone.utc),
                    }
                },
                "$set": {"updated_at": datetime.now(timezone.utc)},
            },
        )

    return callback


def run_and_save(investigation_id: str, context: str | None = None) -> None:
    """Run a full investigation and persist evidence and diagnosis to Mongo."""
    set_context(context)
    db = get_db()
    db.investigations.update_one(
        {"_id": ObjectId(investigation_id)},
        {"$set": {"status": "running"}},
    )

    try:
        progress = _progress_callback(db, investigation_id)
        result = run_investigation(progress_callback=progress, context=context)

        namespace = ""
        problematic = result.get("pods", {}).get("problematic_pods", [])
        if problematic:
            namespace = problematic[0].get("namespace", "")

        diagnosis = result.get("diagnosis", {})
        remediation_id = create_remediation(
            investigation_id,
            result.get("remediation_plan", {}),
            diagnosis,
            context,
        )

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
                    "operational_evidence": result.get("operational_evidence", {}),
                    "security_evidence": result.get("security_evidence", []),
                    "security_summary": result.get("security_summary", {}),
                    "diagnosis": diagnosis,
                    "remediation_id": remediation_id,
                    "root_cause": diagnosis.get("root_cause", ""),
                    "namespace": namespace,
                    "confidence": diagnosis.get("confidence", 0),
                    "updated_at": datetime.now(timezone.utc),
                }
            },
        )
    except Exception as exc:
        logger.error(f"Investigation {investigation_id} failed: {exc}")
        db.investigations.update_one(
            {"_id": ObjectId(investigation_id)},
            {
                "$set": {
                    "status": "failed",
                    "error": str(exc),
                    "updated_at": datetime.now(timezone.utc),
                }
            },
        )
    finally:
        set_context(None)
