from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

from backend.kubernetes.toolkit import K8sToolkit


# Current Kubescape Operator uses the SPDX API group. Older ARMO/Kubescape
# installations used spisec.armosec.io, so support both instead of silently
# reporting "not detected" when the cluster has the older CRDs.
KUBESCAPE_SOURCES = (
    ("spdx.softwarecomposition.kubescape.io", "workloadconfigurationscansummaries"),
    ("spisec.armosec.io", "clusterconfigurationscansummaries"),
)

FALCO_PRIORITY = {
    "EMERGENCY": "CRITICAL",
    "ALERT": "CRITICAL",
    "CRITICAL": "CRITICAL",
    "ERROR": "HIGH",
    "WARNING": "HIGH",
    "NOTICE": "MEDIUM",
    "INFORMATIONAL": "LOW",
    "INFO": "LOW",
    "DEBUG": "LOW",
}

# Falco has two common log formats: JSON and the classic text format. The
# latter looks like: "12:34:56.123: Warning <rule output>" and does not contain
# a literal "rule=" field. The previous collector only understood the JSON or
# key=value format, so a real `kubectl exec ... cat /etc/shadow` event could be
# missed even though Falco was running.
CLASSIC_FALCO_LINE = re.compile(
    r"^(?:\d{2}:\d{2}:\d{2}(?:\.\d+)?|[^:]+:\s*)?\s*"
    r"(?P<priority>EMERGENCY|ALERT|CRITICAL|ERROR|WARNING|NOTICE|INFORMATIONAL|INFO|DEBUG)"
    r"\s+(?P<output>.+)$",
    re.IGNORECASE,
)
KEY_VALUE_FALCO_LINE = re.compile(
    r"priority=(?P<priority>\w+).*?(?:rule=)(?P<rule>[^|]+)",
    re.IGNORECASE,
)


def _resource_from_log(payload: dict[str, Any], fallback_namespace: str, fallback_pod: str) -> str:
    fields = payload.get("output_fields") or {}
    namespace = fields.get("k8s.ns.name") or fields.get("k8s.namespace.name") or fallback_namespace
    pod = fields.get("k8s.pod.name") or fields.get("k8s.pod") or fallback_pod
    container = fields.get("container.name")
    suffix = f" container={container}" if container else ""
    return f"Pod/{namespace}/{pod}{suffix}"


def collect_additional_sources(
    toolkit: K8sToolkit,
    add: Callable[..., None],
) -> dict[str, Any]:
    """Collect bounded, live evidence from Kubescape and Falco."""
    result: dict[str, Any] = {
        "kubescape": {"installed": False, "failed_controls": 0, "source": None, "error": None},
        "falco": {"installed": False, "alerts": 0, "pods": 0, "error": None},
    }
    _collect_kubescape(toolkit, add, result["kubescape"])
    _collect_falco(toolkit, add, result["falco"])
    return result


def _control_items(report: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Normalize the two Kubescape control layouts seen in the wild."""
    candidates = [
        ((report.get("status") or {}).get("controls")),
        ((report.get("spec") or {}).get("controls")),
    ]
    for controls in candidates:
        if isinstance(controls, dict):
            return [(str(control_id), value or {}) for control_id, value in controls.items()]
        if isinstance(controls, list):
            result: list[tuple[str, dict[str, Any]]] = []
            for index, value in enumerate(controls):
                if not isinstance(value, dict):
                    continue
                control_id = value.get("id") or value.get("controlID") or value.get("controlId") or str(index)
                result.append((str(control_id), value))
            if result:
                return result
    return []


def _kubescape_failed(control: dict[str, Any]) -> bool:
    status = control.get("status")
    if isinstance(status, dict):
        status = status.get("status")
    status_text = str(status or control.get("state") or "").lower()
    return status_text in {"failed", "fail", "error"}


def _kubescape_severity(control: dict[str, Any]) -> str:
    severity = control.get("severity")
    if isinstance(severity, dict):
        severity = severity.get("severity") or severity.get("value")
    severity = str(severity or control.get("severity") or "MEDIUM").upper()
    return severity if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"} else "MEDIUM"


def _collect_kubescape(toolkit: K8sToolkit, add: Callable[..., None], status: dict[str, Any]) -> None:
    attempted: list[str] = []
    for group, plural in KUBESCAPE_SOURCES:
        reports = toolkit.get_custom_resources(group, None, plural)
        attempted.append(f"{plural}.{group}")
        if not reports.get("success"):
            continue

        status["installed"] = True
        status["source"] = f"{group}/{plural}"
        for report in (reports.get("data") or {}).get("items") or []:
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
                    title=title,
                    severity=severity,
                    category="kubescape_control",
                    resource=f"Workload/{namespace}/{name}",
                    layer="COMPLIANCE",
                    source="kubescape",
                    context=3 if severity == "CRITICAL" else 2,
                    proof=f"Kubescape {group}/{plural} {namespace}/{name}: control {control_id} status=failed",
                    why="Kubescape independently reported this Kubernetes security control as failed.",
                    fix="Review the Kubescape control and remediate the affected workload configuration.",
                    verify="Re-run the Kubescape continuous scan and confirm the control passes.",
                    issue_key=f"kubescape|{control_id}",
                )
        return

    # Do not hide API/RBAC problems behind a generic NOT DETECTED badge.
    status["error"] = f"No readable Kubescape result CRD found. Tried: {', '.join(attempted)}"


def _is_falco_pod(pod: dict[str, Any]) -> bool:
    meta = pod.get("metadata") or {}
    name = str(meta.get("name") or "").lower()
    labels = meta.get("labels") or {}
    return (
        str(labels.get("app.kubernetes.io/name") or "").lower() == "falco"
        or str(labels.get("app") or "").lower() == "falco"
        or name == "falco"
        or name.startswith("falco-")
    )


def _falco_container(pod: dict[str, Any]) -> str | None:
    containers = (pod.get("spec") or {}).get("containers") or []
    names = [str(c.get("name")) for c in containers if c.get("name")]
    for preferred in ("falco", "falco-main"):
        if preferred in names:
            return preferred
    return names[0] if names else None


def _collect_falco(toolkit: K8sToolkit, add: Callable[..., None], status: dict[str, Any]) -> None:
    pods_result = toolkit.get_resources("pod")
    if not pods_result.get("success"):
        status["error"] = (pods_result.get("error") or {}).get("message") or "Could not list pods"
        return

    falco_pods: list[tuple[str, str, str | None]] = []
    for pod in (pods_result.get("data") or {}).get("items") or []:
        if not _is_falco_pod(pod):
            continue
        meta = pod.get("metadata") or {}
        namespace = str(meta.get("namespace") or "default")
        name = str(meta.get("name") or "")
        falco_pods.append((namespace, name, _falco_container(pod)))

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
            continue

        logs = str((logs_result.get("data") or {}).get("logs") or "")
        for line in logs.splitlines():
            payload: dict[str, Any] | None = None
            try:
                candidate = json.loads(line)
                if isinstance(candidate, dict):
                    payload = candidate
            except Exception:
                pass

            rule = ""
            output = line.strip()
            priority = ""
            resource = f"Pod/{namespace}/{pod}"

            if payload:
                rule = str(payload.get("rule") or "")
                priority = str(payload.get("priority") or "").upper()
                output = str(payload.get("output") or rule or output)
                resource = _resource_from_log(payload, namespace, pod)
            else:
                match = KEY_VALUE_FALCO_LINE.search(line)
                if match:
                    priority = match.group("priority").upper()
                    rule = match.group("rule").strip()
                else:
                    match = CLASSIC_FALCO_LINE.match(line.strip())
                    if match:
                        priority = match.group("priority").upper()
                        output = match.group("output").strip()
                        # Classic Falco output often has no rule name. Keep the
                        # actual event text as the finding title/proof.
                        rule = output[:180]

            if not priority:
                continue
            if rule.lower().startswith("falco internal:"):
                continue
            severity = FALCO_PRIORITY.get(priority)
            if not severity or severity == "LOW":
                continue

            key = f"{rule}|{resource}"
            if key in seen_alerts:
                continue
            seen_alerts.add(key)
            status["alerts"] += 1
            title = f"Falco detected: {rule}" if rule else "Falco runtime alert"
            add(
                title=title,
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
                issue_key=f"falco|{rule}",
            )
