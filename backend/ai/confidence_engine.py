from typing import Any


def _has_value(value: Any) -> bool:
    """Return True if a value contains meaningful data."""
    if value is None:
        return False
    if isinstance(value, (list, dict, set)):
        return len(value) > 0
    if isinstance(value, str):
        return bool(value.strip())
    return True


def compute_confidence(investigation: dict, llm_output: dict) -> int:
    """Score confidence based on the strength of the investigation evidence."""
    score = 30

    pods = investigation.get("pods", {})
    logs = investigation.get("logs", {})
    events = investigation.get("events", {})
    deployments = investigation.get("deployments", {})
    network = investigation.get("network", {})

    problematic = pods.get("problematic_pods", [])
    if problematic:
        score += 20
        if any(p.get("status") in ("CrashLoopBackOff", "ImagePullBackOff", "OOMKilled") for p in problematic):
            score += 10

    if _has_value(logs):
        score += 15

    if events.get("findings"):
        score += 10

    if deployments.get("unhealthy"):
        score += 10

    if network.get("issues"):
        score += 5

    llm_confidence = llm_output.get("confidence")
    if isinstance(llm_confidence, int) and 0 <= llm_confidence <= 100:
        score = int((score + llm_confidence) / 2)

    return min(score, 95)
