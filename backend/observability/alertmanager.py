from typing import Any


def build_incident_description(alert: dict[str, Any]) -> str:
    """Convert a single Alertmanager alert into an incident description string."""
    labels = alert.get("labels", {})
    annotations = alert.get("annotations", {})
    name = labels.get("alertname", "unknown")
    summary = annotations.get("summary") or annotations.get("message") or ""
    description = annotations.get("description") or ""
    resource = labels.get("resource") or labels.get("pod") or labels.get("deployment") or ""
    parts = [f"Alert: {name}"]
    if resource:
        parts.append(f"Resource: {resource}")
    if summary:
        parts.append(f"Summary: {summary}")
    if description:
        parts.append(f"Description: {description}")
    return "\n".join(parts)


def parse_alerts(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract the list of alerts from an Alertmanager webhook payload."""
    alerts = payload.get("alerts") or payload.get("data", {}).get("alerts", [])
    if isinstance(alerts, list):
        return alerts
    return []
