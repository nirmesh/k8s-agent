from datetime import datetime

from bson.objectid import ObjectId
from fastapi import APIRouter, BackgroundTasks, Body, Depends, HTTPException
from pydantic import BaseModel

from backend.api.dependencies import get_current_user
from backend.core.database import get_db
from backend.services import audit_service, remediation_service

router = APIRouter(prefix="/remediations", tags=["remediations"])


class PreviewRequest(BaseModel):
    user_input: dict | None = None


def _serialize_doc(doc: dict) -> dict:
    doc["id"] = str(doc.pop("_id"))
    for field in ("created_at", "updated_at"):
        value = doc.get(field)
        if isinstance(value, datetime):
            doc[field] = value.isoformat()
    for item in doc.get("timestamps", []):
        at = item.get("at")
        if isinstance(at, datetime):
            item["at"] = at.isoformat()
    return doc


def _serialize_audit(doc: dict | None) -> dict | None:
    if not doc:
        return doc
    doc = dict(doc)
    if "_id" in doc:
        doc["id"] = str(doc.pop("_id"))
    for field in ("timestamp", "approval_timestamp", "execution_start", "execution_end"):
        value = doc.get(field)
        if isinstance(value, datetime):
            doc[field] = value.isoformat()
    return doc


@router.post("/{remediation_id}/preview")
def preview_remediation(
    remediation_id: str,
    request: PreviewRequest = Body(default=PreviewRequest()),
    user: dict = Depends(get_current_user),
):
    """Regenerate the remediation preview, optionally including user-provided input."""
    try:
        result = remediation_service.preview_remediation(
            remediation_id,
            user_input=request.user_input,
        )
        return {"status": "success", **result}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/{remediation_id}/execute")
def execute_remediation(
    remediation_id: str,
    background_tasks: BackgroundTasks,
    user: dict = Depends(get_current_user),
):
    """Execute the stored, approved remediation plan."""
    doc = remediation_service.get_remediation(remediation_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Remediation not found")

    investigation = get_db().investigations.find_one(
        {"_id": ObjectId(doc["investigation_id"])}
    )
    if not investigation or str(investigation.get("user_id")) != str(user["_id"]):
        raise HTTPException(status_code=404, detail="Remediation not found")

    if doc["status"] != "AWAITING_APPROVAL":
        raise HTTPException(
            status_code=400,
            detail=f"Cannot execute remediation with status '{doc['status']}'",
        )

    background_tasks.add_task(
        remediation_service.execute_remediation,
        remediation_id,
    )
    return {"status": "success", "remediation_status": "EXECUTING"}


@router.post("/{remediation_id}/rollback")
def rollback_remediation(
    remediation_id: str,
    background_tasks: BackgroundTasks,
    user: dict = Depends(get_current_user),
):
    """Rollback a previously executed remediation."""
    doc = remediation_service.get_remediation(remediation_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Remediation not found")

    investigation = get_db().investigations.find_one(
        {"_id": ObjectId(doc["investigation_id"])}
    )
    if not investigation or str(investigation.get("user_id")) != str(user["_id"]):
        raise HTTPException(status_code=404, detail="Remediation not found")

    if doc["status"] not in ("FAILED", "NOT_RESOLVED", "ROLLBACK_FAILED"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot rollback remediation with status '{doc['status']}'",
        )

    background_tasks.add_task(
        remediation_service.rollback_remediation,
        remediation_id,
    )
    return {"status": "success", "remediation_status": "ROLLING_BACK"}


@router.post("/{remediation_id}/reject")
def reject_remediation(
    remediation_id: str,
    user: dict = Depends(get_current_user),
):
    """Reject the remediation plan."""
    doc = remediation_service.get_remediation(remediation_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Remediation not found")

    investigation = get_db().investigations.find_one(
        {"_id": ObjectId(doc["investigation_id"])}
    )
    if not investigation or str(investigation.get("user_id")) != str(user["_id"]):
        raise HTTPException(status_code=404, detail="Remediation not found")

    try:
        result = remediation_service.reject_remediation(remediation_id)
        return {"status": "success", **result}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/{remediation_id}")
def get_remediation(
    remediation_id: str,
    user: dict = Depends(get_current_user),
):
    """Retrieve the current remediation document and its audit record."""
    doc = remediation_service.get_remediation(remediation_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Remediation not found")

    investigation = get_db().investigations.find_one(
        {"_id": ObjectId(doc["investigation_id"])}
    )
    if not investigation or str(investigation.get("user_id")) != str(user["_id"]):
        raise HTTPException(status_code=404, detail="Remediation not found")

    audit = audit_service.get_audit(remediation_id)
    return {
        "status": "success",
        "remediation": _serialize_doc(doc),
        "audit": _serialize_audit(audit),
    }
