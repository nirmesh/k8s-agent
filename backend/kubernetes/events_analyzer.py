from backend.kubernetes.executor import run_kubectl_json
from backend.core.logging import logger

INTERESTING_REASONS = {
    "FailedScheduling",
    "BackOff",
    "FailedMount",
    "FailedPull",
    "ErrImagePull",
    "Unhealthy",
    "FailedCreate",
    "FailedDelete",
}


def analyze_events() -> dict:
    """Analyze Kubernetes events for common failure reasons."""
    data = run_kubectl_json(["get", "events", "--all-namespaces"])
    if data is None:
        logger.error("Failed to retrieve events")
        return {"total": 0, "findings": [], "error": "kubectl failed"}

    findings = []
    for event in data.get("items", []):
        reason = event.get("reason", "")
        if reason in INTERESTING_REASONS:
            metadata = event.get("metadata", {})
            involved = event.get("involvedObject", {})
            findings.append({
                "namespace": metadata.get("namespace", "default"),
                "reason": reason,
                "message": event.get("message", ""),
                "type": event.get("type", ""),
                "object": f"{involved.get('kind', '')}/{involved.get('name', '')}",
                "count": event.get("count", 1),
            })

    return {
        "total": len(data.get("items", [])),
        "findings": findings,
    }
