from backend.kubernetes.executor import run_kubectl_json
from backend.core.logging import logger


def inspect_deployments() -> dict:
    """Inspect deployments and identify unhealthy rollouts."""
    data = run_kubectl_json(["get", "deployments", "--all-namespaces"])
    if data is None:
        logger.error("Failed to retrieve deployments")
        return {"total": 0, "unhealthy": [], "error": "kubectl failed"}

    unhealthy = []
    for deployment in data.get("items", []):
        metadata = deployment.get("metadata", {})
        spec = deployment.get("spec", {})
        status = deployment.get("status", {})

        desired = spec.get("replicas", 0)
        ready = status.get("readyReplicas", 0)
        available = status.get("availableReplicas", 0)
        unavailable = status.get("unavailableReplicas", 0) or 0

        conditions = status.get("conditions", [])
        summary = [
            {
                "type": c.get("type"),
                "status": c.get("status"),
                "reason": c.get("reason"),
                "message": c.get("message"),
            }
            for c in conditions
        ]

        is_unhealthy = ready != desired or unavailable > 0
        for condition in conditions:
            if condition.get("type") in {"Available", "Progressing"} and condition.get("status") != "True":
                is_unhealthy = True
                break

        if is_unhealthy:
            unhealthy.append({
                "name": metadata.get("name", "unknown"),
                "namespace": metadata.get("namespace", "default"),
                "desired": desired,
                "ready": ready,
                "available": available,
                "unavailable": unavailable,
                "conditions": summary,
            })

    return {
        "total": len(data.get("items", [])),
        "unhealthy": unhealthy,
    }
