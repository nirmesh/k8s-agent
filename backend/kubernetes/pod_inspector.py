from backend.kubernetes.executor import run_kubectl_json
from backend.core.logging import logger

PROBLEMATIC_STATUSES = {
    "CrashLoopBackOff",
    "ImagePullBackOff",
    "ErrImagePull",
    "Pending",
    "Error",
    "OOMKilled",
    "ContainerCreating",
    "Evicted",
    "Terminating",
}


def inspect_pods() -> dict:
    """Inspect pods and return healthy status plus problematic pods."""
    data = run_kubectl_json(["get", "pods", "--all-namespaces"])
    if data is None:
        logger.error("Failed to retrieve pods")
        return {"healthy": False, "total": 0, "problematic_pods": [], "error": "kubectl failed"}

    total = 0
    problematic = []

    for pod in data.get("items", []):
        total += 1
        metadata = pod.get("metadata", {})
        status = pod.get("status", {})

        name = metadata.get("name", "unknown")
        namespace = metadata.get("namespace", "default")
        phase = status.get("phase", "")
        pod_status = phase
        message = ""

        for container_status in status.get("containerStatuses", []):
            state = container_status.get("state", {})
            if "waiting" in state:
                reason = state["waiting"].get("reason", "")
                if reason:
                    pod_status = reason
                    message = state["waiting"].get("message", "")
                    break
            if "terminated" in state:
                reason = state["terminated"].get("reason", "")
                if reason in PROBLEMATIC_STATUSES or reason:
                    pod_status = reason
                    message = state["terminated"].get("message", "")
                    break

        if pod_status in PROBLEMATIC_STATUSES:
            problematic.append({
                "name": name,
                "namespace": namespace,
                "status": pod_status,
                "message": message,
            })

    return {
        "healthy": len(problematic) == 0,
        "total": total,
        "problematic_pods": problematic,
    }
