"""Deterministic Kubernetes signal detectors.

These detectors do not diagnose or remediate incidents. They only surface
observable anomalies so a cluster-wide investigation has concrete starting
points instead of asking the LLM to exhaustively scan the whole cluster.
"""
from __future__ import annotations

from typing import Any

from backend.kubernetes.toolkit import K8sToolkit


def _items(result: dict) -> list[dict]:
    if not result.get("success"):
        return []
    data = result.get("data") or {}
    return data.get("items") or []


def collect_cluster_signals(toolkit: K8sToolkit, limit: int = 30) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []

    # Warning events are strong incident seeds and work across resource kinds.
    events = toolkit.get_events(event_type="Warning")
    if events.get("success"):
        data = events.get("data") or {}
        event_items = data.get("items") or data.get("events") or []
        for event in event_items[-10:]:
            meta = event.get("metadata") or {}
            involved = event.get("involved_object") or event.get("involvedObject") or {}
            signals.append({
                "signal": "warning_event",
                "resource": f"{involved.get('kind','Resource')}/{meta.get('namespace','default')}/{involved.get('name','unknown')}",
                "reason": event.get("reason"),
                "message": event.get("message"),
            })

    # Pod/container state signals.
    for pod in _items(toolkit.list_resources("pod")):
        meta = pod.get("metadata") or {}
        status = pod.get("status") or {}
        ns, name = meta.get("namespace", "default"), meta.get("name", "unknown")
        phase = status.get("phase")
        container_statuses = status.get("container_statuses") or status.get("containerStatuses") or []
        reasons = []
        for cs in container_statuses:
            state = cs.get("state") or {}
            waiting = state.get("waiting") or {}
            terminated = state.get("terminated") or {}
            if waiting.get("reason"):
                reasons.append(waiting.get("reason"))
            if terminated.get("reason") and terminated.get("reason") not in {"Completed"}:
                reasons.append(terminated.get("reason"))
        if phase not in {"Running", "Succeeded"} or reasons:
            signals.append({
                "signal": "pod_unhealthy",
                "resource": f"Pod/{ns}/{name}",
                "phase": phase,
                "reasons": reasons,
            })

    # Workload readiness signals.
    for dep in _items(toolkit.list_resources("deployment")):
        meta, spec, status = dep.get("metadata") or {}, dep.get("spec") or {}, dep.get("status") or {}
        desired = spec.get("replicas") or 0
        ready = status.get("ready_replicas") if "ready_replicas" in status else status.get("readyReplicas", 0)
        available = status.get("available_replicas") if "available_replicas" in status else status.get("availableReplicas", 0)
        if ready != desired or available != desired:
            signals.append({
                "signal": "deployment_not_ready",
                "resource": f"Deployment/{meta.get('namespace','default')}/{meta.get('name','unknown')}",
                "desired": desired,
                "ready": ready,
                "available": available,
            })

    # Service routing signals. A Service with a selector but no ready backend is
    # anomalous even when its Pods/Deployment are otherwise healthy.
    endpoints_by_key: dict[tuple[str, str], dict] = {}
    for ep in _items(toolkit.list_resources("endpoints")):
        meta = ep.get("metadata") or {}
        endpoints_by_key[(meta.get("namespace", "default"), meta.get("name", ""))] = ep

    for svc in _items(toolkit.list_resources("service")):
        meta, spec = svc.get("metadata") or {}, svc.get("spec") or {}
        if spec.get("type") == "ExternalName" or not spec.get("selector"):
            continue
        ns, name = meta.get("namespace", "default"), meta.get("name", "unknown")
        ep = endpoints_by_key.get((ns, name)) or {}
        subsets = ep.get("subsets") or []
        ready_addresses = sum(len(s.get("addresses") or []) for s in subsets)
        if ready_addresses == 0:
            signals.append({
                "signal": "service_no_ready_endpoints",
                "resource": f"Service/{ns}/{name}",
                "selector": spec.get("selector"),
                "readyEndpoints": 0,
            })

    # Storage binding signals.
    for pvc in _items(toolkit.list_resources("pvc")):
        meta, status = pvc.get("metadata") or {}, pvc.get("status") or {}
        if status.get("phase") != "Bound":
            signals.append({
                "signal": "pvc_not_bound",
                "resource": f"Pvc/{meta.get('namespace','default')}/{meta.get('name','unknown')}",
                "phase": status.get("phase"),
            })

    # Deduplicate and bound prompt size.
    unique: list[dict[str, Any]] = []
    seen: set[tuple] = set()
    for signal in signals:
        key = (signal.get("signal"), signal.get("resource"), str(signal.get("reason")))
        if key not in seen:
            seen.add(key)
            unique.append(signal)
        if len(unique) >= limit:
            break
    return unique
