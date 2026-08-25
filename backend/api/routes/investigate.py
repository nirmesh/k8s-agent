from datetime import datetime, timezone

from bson.objectid import ObjectId
from fastapi import APIRouter, BackgroundTasks, Body, Depends, HTTPException
from pydantic import BaseModel

from backend.api.dependencies import get_current_user
from backend.core.database import get_db
from backend.kubernetes.toolkit import K8sToolkit
from backend.services.cluster_service import list_clusters
from backend.services.investigation_runner import create_investigation, run_and_save
from backend.evidence.security import SecurityEvidenceCollector
from backend.evidence.security.additional_sources import collect_additional_sources
from backend.evidence.security.scoring import score_security_posture

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


@router.post("/security-scan")
def security_scan(
    request: InvestigateRequest = Body(default=InvestigateRequest()),
    user: dict = Depends(get_current_user),
) -> dict:
    """Run the full bounded security evidence scan for the dashboard snapshot."""
    try:
        collection = SecurityEvidenceCollector(K8sToolkit(context=request.context)).collect()
        summary = score_security_posture(collection.get("summary") or {})
        return {
            "status": "success",
            "security_summary": summary,
            "diagnostics": collection.get("diagnostics") or {},
            "security_evidence": [e.model_dump(mode="json") for e in (collection.get("evidence") or [])],
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Security scan failed: {exc}") from exc


@router.post("/falco-live")
def falco_live(
    request: InvestigateRequest = Body(default=InvestigateRequest()),
    user: dict = Depends(get_current_user),
) -> dict:
    """Read only recent Falco runtime evidence; do not rerun Trivy or the full posture scan."""
    try:
        findings: list[dict] = []

        def add_finding(**finding):
            findings.append({
                "id": finding.get("issue_key") or f"falco-live-{len(findings) + 1}",
                "title": finding.get("title") or "Falco runtime alert",
                "severity": finding.get("severity") or "UNKNOWN",
                "score": 0,
                "category": finding.get("category") or "runtime_detection",
                "layer": finding.get("layer") or "RUNTIME",
                "source": "falco",
                "evidence": finding.get("proof") or "",
                "why": finding.get("why") or "",
                "fix": finding.get("fix") or "",
                "verify": finding.get("verify") or "",
                "occurrences": 1,
                "affected_count": 1,
                "affected_resources": [finding.get("resource")] if finding.get("resource") else [],
                "explanation_source": "provider",
            })

        source_status = collect_additional_sources(K8sToolkit(context=request.context), add_finding)
        falco = source_status.get("falco") or {}
        return {
            "status": "success",
            "falco": falco,
            "findings": findings,
            "observed_at": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Falco live evidence failed: {exc}") from exc


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
