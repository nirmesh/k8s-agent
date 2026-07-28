from datetime import datetime, timezone

from bson.objectid import ObjectId
from fastapi import APIRouter, BackgroundTasks, Body, Depends, HTTPException
from pydantic import BaseModel

from backend.api.dependencies import get_current_user
from backend.core.database import get_db
from backend.services.cluster_service import list_clusters
from backend.services.investigation_runner import create_investigation, run_and_save

router = APIRouter(tags=["investigate"])


class InvestigateRequest(BaseModel):
    context: str | None = None


def _serialize(doc: dict) -> dict:
    doc["id"] = str(doc.pop("_id"))
    for field in ("created_at", "updated_at", "expires_at"):
        value = doc.get(field)
        if isinstance(value, datetime):
            doc[field] = value.isoformat()
    if isinstance(doc.get("remediation_timeline"), list):
        for item in doc["remediation_timeline"]:
            ts = item.get("timestamp")
            if isinstance(ts, datetime):
                item["timestamp"] = ts.isoformat()
    return doc


@router.get("/clusters")
def get_clusters(user: dict = Depends(get_current_user)):
    return {"status": "success", "clusters": list_clusters()}


@router.post("/investigate")
def investigate(
    background_tasks: BackgroundTasks,
    request: InvestigateRequest = Body(default=InvestigateRequest()),
    user: dict = Depends(get_current_user),
) -> dict:
    investigation_id = create_investigation(str(user["_id"]))
    background_tasks.add_task(run_and_save, investigation_id, request.context)
    return {"investigation_id": investigation_id, "status": "running"}


@router.get("/investigations/{investigation_id}")
def get_investigation(investigation_id: str, user: dict = Depends(get_current_user)):
    db = get_db()
    doc = db.investigations.find_one({"_id": ObjectId(investigation_id)})
    if not doc or str(doc.get("user_id")) != str(user["_id"]):
        raise HTTPException(status_code=404, detail="Investigation not found")
    return {"status": "success", "investigation": _serialize(doc)}


@router.get("/investigations")
def list_investigations(user: dict = Depends(get_current_user)):
    db = get_db()
    docs = (
        db.investigations.find({"user_id": str(user["_id"])})
        .sort("created_at", -1)
        .limit(20)
    )
    return {"status": "success", "investigations": [_serialize(d) for d in docs]}
