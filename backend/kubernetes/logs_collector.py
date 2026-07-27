from backend.kubernetes.executor import run_kubectl
from backend.core.logging import logger

TAIL_LINES = 50


def _fetch_pod_logs(name: str, namespace: str, previous: bool = False) -> str:
    """Fetch logs for a single pod."""
    args = ["logs", name, "-n", namespace, f"--tail={TAIL_LINES}"]
    if previous:
        args.append("--previous")
    result = run_kubectl(args, timeout=15)
    return result["stdout"] if result["success"] else ""


def collect_logs(problematic_pods: list[dict]) -> dict:
    """Collect concise logs for problematic pods."""
    logs = {}
    for pod in problematic_pods:
        name = pod["name"]
        namespace = pod["namespace"]
        key = f"{namespace}/{name}"

        logger.info(f"Collecting logs for {key}")

        # Prefer previous container logs for crash-looped pods, fall back to current.
        previous_logs = _fetch_pod_logs(name, namespace, previous=True)
        current_logs = ""
        if not previous_logs:
            current_logs = _fetch_pod_logs(name, namespace, previous=False)

        pod_logs = {}
        if previous_logs:
            pod_logs["previous"] = previous_logs
        if current_logs:
            pod_logs["current"] = current_logs

        if pod_logs:
            logs[key] = pod_logs
        else:
            logs[key] = {"message": "No logs available"}

    return logs
