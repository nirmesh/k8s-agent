from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request

from backend.core.logging import logger
from backend.observability.alertmanager import build_incident_description, parse_alerts
from backend.services.investigation_runner import create_investigation, run_and_save

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.post("")
async def receive_alert(request: Request, background_tasks: BackgroundTasks) -> dict[str, Any]:
    """Receive an Alertmanager webhook, create an incident, and start an investigation."""
    try:
        payload = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON payload") from exc

    alerts = parse_alerts(payload)
    if not alerts:
        raise HTTPException(status_code=400, detail="No alerts found in payload")

    alert = alerts[0]
    incident_description = build_incident_description(alert)
    investigation_id = create_investigation(user_id="alertmanager")

    logger.info(f"Starting investigation {investigation_id} from alertmanager alert")
    background_tasks.add_task(run_and_save, investigation_id)

    return {
        "status": "accepted",
        "investigation_id": investigation_id,
        "alert_count": len(alerts),
        "incident_description": incident_description,
    }
