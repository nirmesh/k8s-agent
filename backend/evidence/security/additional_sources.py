from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from datetime import datetime
from typing import Any

from backend.kubernetes.toolkit import K8sToolkit

FALCO_LIVE_WINDOW_SECONDS = int(os.getenv("FALCO_LIVE_WINDOW_SECONDS", "300"))
FALCO_PRIORITY = {
    "EMERGENCY": "CRITICAL", "ALERT": "CRITICAL", "CRITICAL": "CRITICAL",
    "ERROR": "HIGH", "WARNING": "HIGH", "NOTICE": "MEDIUM",
    "INFORMATIONAL": "LOW", "INFO": "LOW", "DEBUG": "LOW",
}
CLASSIC_FALCO_LINE = re.compile(
    r"^(?:\d{2}:\d{2}:\d{2}(?:\.\d+)?\s*:\s*)?"
    r"(?P<priority>EMERGENCY|ALERT|CRITICAL|ERROR|WARNING|NOTICE|INFORMATIONAL|INFO|DEBUG)\s+"
    r"(?P<output>.+)$", re.IGNORECASE)
KEY_VALUE_FALCO_LINE = re.compile(r"priority=(?P<priority>\w+).*?(?:rule=)(?P<rule>[^|]+)", re.IGNORECASE)
JSON_PRIORITY_PREFIX = re.compile(
    r"^\s*(?:\d{2}:\d{2}:\d{2}(?:\.\d+)?\s*:\s*)?"
    r"(?P<priority>EMERGENCY|ALERT|CRITICAL|ERROR|WARNING|NOTICE|INFORMATIONAL|INFO|DEBUG)\s+"
    r"(?P<output>.+)$", re.IGNORECASE)
FALCO_TIME = re.compile(r"(?<!\d)(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})(?:\.(?P<fraction>\d+))?")
CONTAINER_ID_RE = re.compile(r"(?:container_id|container\.id)=(?:containerd://|docker://|cri-o://)?(?P<id>[A-Za-z0-9_-]+)", re.IGNORECASE)


def _resource_from_log(payload: dict[str, Any], fallback_namespace: str, fallback_pod: str) -> str:
    fields = payload.get("output_fields") or {}
    namespace = fields.get("k8s.ns.name") or fields.get("k8s.namespace.name") or fallback_namespace
    pod = fields.get("k8s.pod.name") or fields.get("k8s.pod") or fallback_pod
    container = fields.get("container.name")
    return f"Pod/{namespace}/{pod}" + (f" container={container}" if container else "")


def _falco_event_age_seconds(line: str) -> float | None:
    match = FALCO_TIME.search(line)
    if not match:
        return None
    now = datetime.now().astimezone()
    try:
        micros = int((match.group("fraction") or "")[:6].ljust(6, "0") or 0)
        event = now.replace(hour=int(match.group("hour")), minute=int(match.group("minute")), second=int(match.group("second")), microsecond=micros)
        age = (now - event).total_seconds()
        if age < -12 * 3600:
            age += 24 * 3600
        elif age > 12 * 3600:
            age -= 24 * 3600
        return age
    except ValueError:
        return None


def _is_live_falco_line(line: str) -> bool:
    age = _falco_event_age_seconds(line)
    # A live security view must never treat an event with no trustworthy
    # event timestamp as current. Historical pod logs are not live evidence.
    return age is not None and 0 <= age <= FALCO_LIVE_WINDOW_SECONDS


def collect_additional_sources(toolkit: K8sToolkit, add: Callable[..., None]) -> dict[str, Any]:
    result = {
        "falco": {
            "installed": False,
            "alerts": 0,
            "pods": 0,
            "error": None,
            "live_window_seconds": FALCO_LIVE_WINDOW_SECONDS,
        }
    }
    _collect_falco(toolkit, add, result["falco"])
    return result


def _is_falco_pod(pod: dict[str, Any]) -> bool:
    meta = pod.get("metadata") or {}
    name = str(meta.get("name") or "").lower()
    labels = meta.get("labels") or {}
    return (
        str(labels.get("app.kubernetes.io/name") or "").lower() == "falco"
        or str(labels.get("app") or "").lower() == "falco"
        or name == "falco" or name.startswith("falco-")
    )


def _falco_container(pod: dict[str, Any]) -> str | None:
    names = [str(c.get("name")) for c in ((pod.get("spec") or {}).get("containers") or []) if c.get("name")]
    for preferred in ("falco", "falco-main"):
        if preferred in names:
            return preferred
    return names[0] if names else None


def _container_resource_map(pods: list[dict[str, Any]]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for pod in pods:
        meta = pod.get("metadata") or {}
        namespace = str(meta.get("namespace") or "default")
        name = str(meta.get("name") or "unknown")
        for status in ((pod.get("status") or {}).get("container_statuses") or []):
            raw_id = str(status.get("container_id") or "")
            if raw_id:
                mapping[re.sub(r"^[a-z]+://", "", raw_id)] = f"Pod/{namespace}/{name}"
    return mapping


def _parse_falco_line(line: str, namespace: str, pod: str) -> tuple[str, str, str, str, bool]:
    payload = None
    try:
        candidate = json.loads(line)
        if isinstance(candidate, dict):
            payload = candidate
    except Exception:
        pass

    resource = f"Pod/{namespace}/{pod}"
    if payload:
        priority = str(payload.get("priority") or "").upper()
        output = str(payload.get("output") or payload.get("rule") or line.strip())
        rule = str(payload.get("rule") or "")
        resource = _resource_from_log(payload, namespace, pod)
        match = JSON_PRIORITY_PREFIX.match(output)
        if match:
            priority = match.group("priority").upper()
            output = match.group("output").strip()
        if not priority:
            match = CLASSIC_FALCO_LINE.match(output)
            if match:
                priority = match.group("priority").upper()
                output = match.group("output").strip()
        if not rule:
            rule = output.split(" | ", 1)[0].strip()
        return rule, output, priority, resource, True

    match = KEY_VALUE_FALCO_LINE.search(line)
    if match:
        return match.group("rule").strip(), line.strip(), match.group("priority").upper(), resource, False
    match = CLASSIC_FALCO_LINE.match(line.strip())
    if match:
        output = match.group("output").strip()
        return output.split(" | ", 1)[0].strip(), output, match.group("priority").upper(), resource, True
    return "", line.strip(), "", resource, False


def _collect_falco(toolkit: K8sToolkit, add: Callable[..., None], status: dict[str, Any]) -> None:
    pods_result = toolkit.get_resources("pod")
    if not pods_result.get("success"):
        status["error"] = (pods_result.get("error") or {}).get("message") or "Could not list pods"
        return
    all_pods = (pods_result.get("data") or {}).get("items") or []
    container_resources = _container_resource_map(all_pods)
    falco_pods: list[tuple[str, str, str | None]] = []
    for pod in all_pods:
        if _is_falco_pod(pod):
            meta = pod.get("metadata") or {}
            falco_pods.append((str(meta.get("namespace") or "default"), str(meta.get("name") or ""), _falco_container(pod)))
    if not falco_pods:
        status["error"] = "No Falco pod matched the standard Falco labels/name."
        return

    status["installed"] = True
    status["pods"] = len(falco_pods)
    seen: set[str] = set()
    for namespace, pod, container in falco_pods[:5]:
        logs_result = toolkit.get_logs(namespace, pod, container=container, tail_lines=100)
        if not logs_result.get("success") and container:
            logs_result = toolkit.get_logs(namespace, pod, tail_lines=100)
        if not logs_result.get("success"):
            status["error"] = (logs_result.get("error") or {}).get("message") or "Could not read Falco logs"
            continue
        logs = str((logs_result.get("data") or {}).get("logs") or "")
        for line in logs.splitlines():
            if not _is_live_falco_line(line):
                continue
            rule, output, priority, resource, _ = _parse_falco_line(line, namespace, pod)
            if not priority or rule.lower().startswith("falco internal:"):
                continue
            severity = FALCO_PRIORITY.get(priority)
            if not severity or severity == "LOW":
                continue
            match = CONTAINER_ID_RE.search(output)
            if match:
                resource = container_resources.get(match.group("id"), resource)
            key = f"{rule}|{resource}|{output[:300]}"
            if key in seen:
                continue
            seen.add(key)
            status["alerts"] += 1
            add(
                title=f"Falco detected: {rule}" if rule else "Falco runtime alert",
                severity=severity,
                category="runtime_detection",
                resource=resource,
                layer="RUNTIME",
                source="falco",
                context=5 if severity == "CRITICAL" else 3,
                proof=f"Falco runtime alert: {output[:500]}",
                why="Falco observed runtime behavior matching a security detection rule; this is live runtime evidence rather than a static configuration finding.",
                fix="Investigate the process/activity first; contain the workload only after confirming the alert is unexpected.",
                verify="Confirm the runtime alert stops and review the workload/process that generated it.",
                issue_key=f"falco|{rule}|{resource}",
            )
