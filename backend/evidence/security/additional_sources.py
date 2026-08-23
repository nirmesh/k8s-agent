from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

from backend.evidence.security.model import SecurityEvidence, SecurityFinding
from backend.kubernetes.toolkit import K8sToolkit


KUBESCAPE_GROUP = "spdx.softwarecomposition.kubescape.io"
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


def _resource_from_log(payload: dict[str, Any]) -> str:
    fields = payload.get("output_fields") or {}
    namespace = fields.get("k8s.ns.name") or fields.get("k8s.namespace.name")
    pod = fields.get("k8s.pod.name") or fields.get("k8s.pod")
    container = fields.get("container.name")
    if namespace and pod:
        suffix = f" container={container}" if container else ""
        return f"Pod/{namespace}/{pod}{suffix}"
    return "cluster/runtime"


def collect_additional_sources(
    toolkit: K8sToolkit,
    add: Callable[..., None],
) -> dict[str, Any]:
    """Collect small, high-value signals from already-installed Falco/Kubescape.

    This is intentionally read-only and bounded. It does not execute either tool's
    CLI or dump their complete result stores into the investigation document.
    """
    result: dict[str, Any] = {
        "kubescape": {"installed": False, "failed_controls": 0},
        "falco": {"installed": False, "alerts": 0},
    }
    _collect_kubescape(toolkit, add, result["kubescape"])
    _collect_falco(toolkit, add, result["falco"])
    return result


def _collect_kubescape(toolkit: K8sToolkit, add: Callable[..., None], status: dict[str, Any]) -> None:
    reports = toolkit.get_custom_resources(
        KUBESCAPE_GROUP,
        None,
        "workloadconfigurationscansummaries",
    )
    if not reports.get("success"):
        return

    status["installed"] = True
    for report in (reports.get("data") or {}).get("items") or []:
        meta = report.get("metadata") or {}
        namespace = str(meta.get("namespace") or "cluster")
        name = str(meta.get("name") or "unknown")
        controls = ((report.get("spec") or {}).get("controls") or {})
        for control_id, control in controls.items():
            control = control or {}
            control_status = ((control.get("status") or {}).get("status") or "").lower()
            if control_status not in {"failed", "fail", "error"}:
                continue
            severity = str(((control.get("severity") or {}).get("severity")) or "MEDIUM").upper()
            severity = severity if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"} else "MEDIUM"
            status["failed_controls"] += 1
            title = control.get("name") or f"Kubescape control {control_id} failed"
            add(
                title=title,
                severity=severity,
                category="kubescape_control",
                resource=f"Workload/{namespace}/{name}",
                layer="COMPLIANCE",
                source="kubescape",
                context=3 if severity == "CRITICAL" else 2,
                proof=f"Kubescape WorkloadConfigurationScanSummary {namespace}/{name}: control {control_id} status={control_status}",
                why="Kubescape independently reported this Kubernetes security control as failed.",
                fix="Review the Kubescape control and remediate the affected workload configuration.",
                verify="Re-run the Kubescape continuous scan and confirm the control passes.",
                issue_key=f"kubescape|{control_id}",
            )


def _collect_falco(toolkit: K8sToolkit, add: Callable[..., None], status: dict[str, Any]) -> None:
    pods_result = toolkit.get_resources("pod")
    if not pods_result.get("success"):
        return

    falco_pods: list[tuple[str, str]] = []
    for pod in (pods_result.get("data") or {}).get("items") or []:
        meta = pod.get("metadata") or {}
        name = str(meta.get("name") or "")
        namespace = str(meta.get("namespace") or "")
        labels = meta.get("labels") or {}
        app_name = str(labels.get("app.kubernetes.io/name") or "").lower()
        if namespace == "falco-operator":
            continue
        if app_name == "falco" or name.startswith("falco-") or name == "falco":
            falco_pods.append((namespace, name))

    if not falco_pods:
        return

    status["installed"] = True
    # A few recent log lines from a few Falco pods are enough to establish runtime
    # evidence without turning investigation into a log ingestion pipeline.
    seen_alerts: set[str] = set()
    for namespace, pod in falco_pods[:3]:
        logs_result = toolkit.get_logs(namespace, pod, container="falco", tail_lines=40)
        if not logs_result.get("success"):
            logs_result = toolkit.get_logs(namespace, pod, tail_lines=40)
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
                payload = None

            if payload:
                rule = str(payload.get("rule") or "")
                priority = str(payload.get("priority") or "").upper()
                if rule.lower().startswith("falco internal:") or not rule or priority in {"DEBUG", "INFORMATIONAL"}:
                    continue
                severity = FALCO_PRIORITY.get(priority, "MEDIUM")
                output = str(payload.get("output") or rule)
                resource = _resource_from_log(payload)
            else:
                match = re.search(r"priority=(\w+).*?rule=([^|]+)", line, re.IGNORECASE)
                if not match:
                    continue
                priority = match.group(1).upper()
                rule = match.group(2).strip()
                if rule.lower().startswith("falco internal:"):
                    continue
                severity = FALCO_PRIORITY.get(priority, "MEDIUM")
                output = line.strip()
                resource = f"Pod/{namespace}/{pod}"

            key = f"{rule}|{resource}"
            if key in seen_alerts:
                continue
            seen_alerts.add(key)
            status["alerts"] += 1
            add(
                title=f"Falco detected: {rule}",
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
