from __future__ import annotations

import json
import re
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from backend.kubernetes.toolkit import K8sToolkit

KUBESCAPE_SOURCES = (
    ("spdx.softwarecomposition.kubescape.io", "workloadconfigurationscansummaries", "v1beta1"),
    ("spisec.armosec.io", "clusterconfigurationscansummaries", "v1beta1"),
)
FALCO_LIVE_WINDOW_SECONDS = 5 * 60

FALCO_PRIORITY = {
    "EMERGENCY": "CRITICAL", "ALERT": "CRITICAL", "CRITICAL": "CRITICAL",
    "ERROR": "HIGH", "WARNING": "HIGH", "NOTICE": "MEDIUM",
    "INFORMATIONAL": "LOW", "INFO": "LOW", "DEBUG": "LOW",
}

CLASSIC_FALCO_LINE = re.compile(
    r"^(?:\d{2}:\d{2}:\d{2}(?:\.\d+)?\s*:\s*|[^:]+:\s*)?"
    r"(?P<priority>EMERGENCY|ALERT|CRITICAL|ERROR|WARNING|NOTICE|INFORMATIONAL|INFO|DEBUG)\s+"
    r"(?P<output>.+)$", re.IGNORECASE)
KEY_VALUE_FALCO_LINE = re.compile(r"priority=(?P<priority>\w+).*?(?:rule=)(?P<rule>[^|]+)", re.IGNORECASE)
JSON_PRIORITY_PREFIX = re.compile(
    r"^\s*(?:\d{2}:\d{2}:\d{2}(?:\.\d+)?\s*:\s*)?"
    r"(?P<priority>EMERGENCY|ALERT|CRITICAL|ERROR|WARNING|NOTICE|INFORMATIONAL|INFO|DEBUG)\s+"
    r"(?P<output>.+)$", re.IGNORECASE)
EMBEDDED_FALCO_PRIORITY = re.compile(
    r"(?P<priority>EMERGENCY|ALERT|CRITICAL|ERROR|WARNING|NOTICE|INFORMATIONAL|INFO|DEBUG)\s+"
    r"(?P<output>(?:Sensitive file opened for reading.*|.+))$", re.IGNORECASE)
FALCO_TIME = re.compile(r"(?<!\d)(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})(?:\.\d+)?")
CONTAINER_ID_RE = re.compile(r"(?:container_id|container\.id)=(?:containerd://|docker://|cri-o://)?(?P<id>[A-Za-z0-9_-]+)", re.IGNORECASE)


def _resource_from_log(payload: dict[str, Any], fallback_namespace: str, fallback_pod: str) -> str:
    fields = payload.get("output_fields") or {}
    namespace = fields.get("k8s.ns.name") or fields.get("k8s.namespace.name") or fallback_namespace
    pod = fields.get("k8s.pod.name") or fields.get("k8s.pod") or fallback_pod
    container = fields.get("container.name")
    suffix = f" container={container}" if container else ""
    return f"Pod/{namespace}/{pod}{suffix}"


def _falco_event_age_seconds(line: str) -> float | None:
    """Return age for Falco's HH:MM:SS prefix; None when no timestamp exists."""
    match = FALCO_TIME.search(line)
    if not match:
        return None
    now = datetime.now().astimezone()
    try:
        event = now.replace(
            hour=int(match.group("hour")),
            minute=int(match.group("minute")),
            second=int(match.group("second")),
            microsecond=0,
        )
        age = (now - event).total_seconds()
        # Handle a timestamp just before midnight.
        if age < -12 * 3600:
            age += 24 * 3600
        elif age > 12 * 3600:
            age -= 24 * 3600
        return max(0.0, age)
    except ValueError:
        return None


def _is_live_falco_line(line: str) -> bool:
    age = _falco_event_age_seconds(line)
    # Untimestamped formats are retained because the source itself does not
    # expose enough information to safely age them out.
    return age is None or age <= FALCO_LIVE_WINDOW_SECONDS


def collect_additional_sources(toolkit: K8sToolkit, add: Callable[..., None]) -> dict[str, Any]:
    result = {
        "kubescape": {"installed": False, "reports": 0, "failed_controls": 0, "source": None, "error": None},
        "falco": {"installed": False, "alerts": 0, "pods": 0, "error": None, "live_window_seconds": FALCO_LIVE_WINDOW_SECONDS},
    }
    _collect_kubescape(toolkit, add, result["kubescape"])
    _collect_falco(toolkit, add, result["falco"])
    return result


def _control_items(report: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    for controls in [((report.get("status") or {}).get("controls")), ((report.get("spec") or {}).get("controls"))]:
        if isinstance(controls, dict):
            return [(str(control_id), value or {}) for control_id, value in controls.items()]
        if isinstance(controls, list):
            result = []
            for index, value in enumerate(controls):
                if isinstance(value, dict):
                    result.append((str(value.get("id") or value.get("controlID") or value.get("controlId") or index), value))
            if result:
                return result
    return []


def _kubescape_failed(control: dict[str, Any]) -> bool:
    status = control.get("status")
    if isinstance(status, dict):
        status = status.get("status")
    return str(status or control.get("state") or "").lower() in {"failed", "fail", "error"}


def _kubescape_severity(control: dict[str, Any]) -> str:
    severity = control.get("severity")
    if isinstance(severity, dict):
        severity = severity.get("severity") or severity.get("value")
    severity = str(severity or "MEDIUM").upper()
    return severity if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"} else "MEDIUM"


def _collect_kubescape(toolkit: K8sToolkit, add: Callable[..., None], status: dict[str, Any]) -> None:
    attempted = []
    for group, plural, version in KUBESCAPE_SOURCES:
        reports = toolkit.get_custom_resources(group, version, plural)
        attempted.append(f"{plural}.{group}/{version}")
        if not reports.get("success"):
            reports = toolkit.get_custom_resources(group, None, plural)
            attempted.append(f"{plural}.{group}/discovered")
        if not reports.get("success"):
            continue

        data = reports.get("data") or {}
        items = data.get("items") or []
        status["installed"] = True
        status["reports"] = len(items)
        status["source"] = f"{group}/{plural}/{data.get('version') or version}"
        for report in items:
            meta = report.get("metadata") or {}
            namespace = str(meta.get("namespace") or "cluster")
            name = str(meta.get("name") or "unknown")
            for control_id, control in _control_items(report):
                if not _kubescape_failed(control):
                    continue
                severity = _kubescape_severity(control)
                status["failed_controls"] += 1
                title = str(control.get("name") or control.get("title") or f"Kubescape control {control_id} failed")
                add(
                    title=title, severity=severity, category="kubescape_control",
                    resource=f"Workload/{namespace}/{name}", layer="COMPLIANCE", source="kubescape",
                    context=3 if severity == "CRITICAL" else 2,
                    proof=f"Kubescape {group}/{plural} {namespace}/{name}: control {control_id} status=failed",
                    why="Kubescape independently reported this Kubernetes security control as failed.",
                    fix="Review the Kubescape control and remediate the affected workload configuration.",
                    verify="Re-run the Kubescape continuous scan and confirm the control passes.",
                    issue_key=f"kubescape|{control_id}|{namespace}|{name}",
                )
        return
    status["error"] = f"No readable Kubescape result CRD found. Tried: {', '.join(attempted)}"


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
        for container_status in ((pod.get("status") or {}).get("container_statuses") or []):
            raw_id = str(container_status.get("container_id") or "")
            if raw_id:
                container_id = re.sub(r"^[a-z]+://", "", raw_id)
                if container_id:
                    mapping[container_id] = f"Pod/{namespace}/{name}"
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
            if not rule:
                rule = output.split(" | ", 1)[0].strip()
        elif not priority:
            match = CLASSIC_FALCO_LINE.match(output)
            if match:
                priority = match.group("priority").upper()
                output = match.group("output").strip()
                if not rule:
                    rule = output.split(" | ", 1)[0].strip()
        if not priority:
            match = EMBEDDED_FALCO_PRIORITY.search(output)
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

    match = EMBEDDED_FALCO_PRIORITY.search(line)
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
    falco_pods = []
    for pod in all_pods:
        if _is_falco_pod(pod):
            meta = pod.get("metadata") or {}
            falco_pods.append((str(meta.get("namespace") or "default"), str(meta.get("name") or ""), _falco_container(pod)))
    if not falco_pods:
        status["error"] = "No Falco pod matched the standard Falco labels/name."
        return

    status["installed"] = True
    status["pods"] = len(falco_pods)
    seen_alerts: set[str] = set()
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
            rule, output, priority, resource, classic = _parse_falco_line(line, namespace, pod)
            if not priority or rule.lower().startswith("falco internal:"):
                continue
            severity = FALCO_PRIORITY.get(priority)
            if not severity or severity == "LOW":
                continue
            if classic and not any(marker in output for marker in (
                "evt_type=", "proc=", "container_name=", "k8s_ns=", "k8s_pod_name=",
                "/etc/shadow", "/etc/passwd", "/etc/sudoers",
            )):
                continue
            container_match = CONTAINER_ID_RE.search(output)
            if container_match:
                resource = container_resources.get(container_match.group("id"), resource)

            key = f"{rule}|{resource}|{output[:300]}"
            if key in seen_alerts:
                continue
            seen_alerts.add(key)
            status["alerts"] += 1
            add(
                title=f"Falco detected: {rule}" if rule else "Falco runtime alert",
                severity=severity, category="runtime_detection", resource=resource,
                layer="RUNTIME", source="falco", context=5 if severity == "CRITICAL" else 3,
                proof=f"Falco runtime alert: {output[:500]}",
                why="Falco observed runtime behavior matching a security detection rule; this is live runtime evidence rather than a static configuration finding.",
                fix="Investigate the process/activity first; contain the workload only after confirming the alert is unexpected.",
                verify="Confirm the runtime alert stops and review the workload/process that generated it.",
                issue_key=f"falco|{rule}|{resource}",
            )
