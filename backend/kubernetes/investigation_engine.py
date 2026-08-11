from __future__ import annotations

import hashlib
import json
from typing import Any

from backend.evidence.model import Evidence
from backend.kubernetes.toolkit import K8sToolkit


TERMINAL_OK = {"Running", "Succeeded"}
WAITING_FAILURES = {
    "ErrImagePull",
    "ImagePullBackOff",
    "CrashLoopBackOff",
    "CreateContainerConfigError",
    "CreateContainerError",
    "RunContainerError",
}


def _items(result: dict[str, Any]) -> list[dict[str, Any]]:
    if not result.get("success"):
        return []
    return (result.get("data") or {}).get("items") or []


def _resource(kind: str, obj: dict[str, Any]) -> str:
    meta = obj.get("metadata") or {}
    namespace = meta.get("namespace") or "-"
    return f"{kind}/{namespace}/{meta.get('name', 'unknown')}"


def _stable_id(signal: str, resource: str, payload: dict[str, Any]) -> str:
    raw = json.dumps({"signal": signal, "resource": resource, "payload": payload}, sort_keys=True, default=str)
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


def _evidence(signal: str, resource: str, payload: dict[str, Any], severity: str = "MEDIUM", related: list[str] | None = None) -> dict[str, Any]:
    return {
        "id": _stable_id(signal, resource, payload),
        "provider": "kubernetes",
        "type": "operational_signal",
        "signal": signal,
        "resource": resource,
        "severity": severity,
        "related_resources": related or [],
        "payload": payload,
    }


def _event_matches(events: list[dict[str, Any]], tokens: tuple[str, ...]) -> list[dict[str, Any]]:
    matches = []
    for event in events:
        reason = str(event.get("reason") or "")
        message = str(event.get("message") or "")
        haystack = f"{reason} {message}".lower()
        if any(token.lower() in haystack for token in tokens):
            matches.append(event)
    return matches


def _owner_chain(toolkit: K8sToolkit, kind: str, namespace: str, name: str) -> list[str]:
    result = toolkit.get_owner(kind, namespace, name)
    if not result.get("success"):
        return []
    owners = result.get("data", {}).get("owners") or []
    return [_resource(o.get("kind", "Resource"), o) for o in owners if o]


def _selector_string(selector: dict[str, Any]) -> str:
    return ",".join(f"{key}={value}" for key, value in sorted(selector.items()))


def collect_operational_evidence(toolkit: K8sToolkit, limit: int = 100) -> list[dict[str, Any]]:
    """Collect verified operational evidence without asking the LLM to discover it."""
    evidence: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(item: dict[str, Any]) -> None:
        if item["id"] in seen or len(evidence) >= limit:
            return
        seen.add(item["id"])
        evidence.append(item)

    pods = _items(toolkit.list_resources("pod"))
    deployments = _items(toolkit.list_resources("deployment"))
    services = _items(toolkit.list_resources("service"))
    pvcs = _items(toolkit.list_resources("persistentvolumeclaim"))

    # Pod/container failures are the primary operational seed. Events are scoped to
    # the pod, preventing unrelated Warning events elsewhere from contaminating it.
    for pod in pods:
        meta = pod.get("metadata") or {}
        ns, name = meta.get("namespace", "default"), meta.get("name", "unknown")
        pod_resource = f"Pod/{ns}/{name}"
        status = pod.get("status") or {}
        phase = status.get("phase")
        container_statuses = status.get("container_statuses") or status.get("containerStatuses") or []
        failures = []
        images = []
        for cs in container_statuses:
            images.append(cs.get("image") or cs.get("image_id"))
            state = cs.get("state") or {}
            waiting = state.get("waiting") or {}
            terminated = state.get("terminated") or {}
            reason = waiting.get("reason") or terminated.get("reason")
            if reason and reason not in {"Completed"}:
                failures.append({"container": cs.get("name"), "reason": reason})

        events_result = toolkit.get_events(namespace=ns, resource_name=name, event_type="Warning")
        pod_events = _items(events_result)
        image_events = _event_matches(pod_events, ("Failed", "ErrImagePull", "ImagePullBackOff", "pull image"))
        probe_events = _event_matches(pod_events, ("Readiness probe failed", "Liveness probe failed", "Startup probe failed", "probe failed"))
        schedule_events = _event_matches(pod_events, ("FailedScheduling", "failedscheduling", "unschedulable"))

        if phase not in TERMINAL_OK or failures or image_events or probe_events or schedule_events:
            owners = _owner_chain(toolkit, "Pod", ns, name)
            payload = {
                "phase": phase,
                "container_failures": failures,
                "images": [x for x in images if x],
                "warning_events": [
                    {"reason": e.get("reason"), "message": e.get("message")} for e in pod_events
                ],
            }
            signal = "pod_unhealthy"
            if image_events or any(f.get("reason") in {"ErrImagePull", "ImagePullBackOff"} for f in failures):
                signal = "image_pull_failure"
                payload["image_events"] = [{"reason": e.get("reason"), "message": e.get("message")} for e in image_events]
            elif probe_events:
                signal = "probe_failure"
                payload["probe_events"] = [{"reason": e.get("reason"), "message": e.get("message")} for e in probe_events]
            elif schedule_events:
                signal = "scheduling_failure"
                payload["scheduling_events"] = [{"reason": e.get("reason"), "message": e.get("message")} for e in schedule_events]
            severity = "HIGH" if signal in {"image_pull_failure", "probe_failure", "scheduling_failure"} else "MEDIUM"
            add(_evidence(signal, pod_resource, payload, severity, owners))

            # If the pod has a controller owner, inspect the controller's actual
            # spec. This is where probe paths, images and scheduling constraints
            # are verified; no replacement values are invented.
            for owner_resource in owners:
                okind, ons, oname = owner_resource.split("/", 2)
                owner_result = toolkit.get_resource(okind, ons, oname)
                if not owner_result.get("success"):
                    continue
                owner_obj = (owner_result.get("data") or {}).get("resource") or {}
                template = ((owner_obj.get("spec") or {}).get("template") or {})
                containers = ((template.get("spec") or {}).get("containers") or [])
                if signal == "image_pull_failure":
                    add(_evidence(
                        "image_reference",
                        owner_resource,
                        {"containers": [{"name": c.get("name"), "image": c.get("image")} for c in containers]},
                        "HIGH",
                        [pod_resource],
                    ))
                if signal == "probe_failure":
                    probes = []
                    for c in containers:
                        probes.append({
                            "name": c.get("name"),
                            "readiness": c.get("readiness_probe") or c.get("readinessProbe"),
                            "liveness": c.get("liveness_probe") or c.get("livenessProbe"),
                            "startup": c.get("startup_probe") or c.get("startupProbe"),
                        })
                    add(_evidence("probe_configuration", owner_resource, {"containers": probes}, "HIGH", [pod_resource]))
                if signal == "scheduling_failure":
                    add(_evidence(
                        "scheduling_constraints",
                        owner_resource,
                        {"node_selector": (template.get("spec") or {}).get("node_selector") or (template.get("spec") or {}).get("nodeSelector"),
                         "affinity": (template.get("spec") or {}).get("affinity"),
                         "tolerations": (template.get("spec") or {}).get("tolerations")},
                        "HIGH",
                        [pod_resource],
                    ))

    # Deployment rollout state is independent evidence and is linked to the
    # deployment, not every other workload in the namespace.
    for dep in deployments:
        meta, spec, status = dep.get("metadata") or {}, dep.get("spec") or {}, dep.get("status") or {}
        desired = spec.get("replicas", 0)
        ready = status.get("ready_replicas", status.get("readyReplicas", 0)) or 0
        available = status.get("available_replicas", status.get("availableReplicas", 0)) or 0
        conditions = status.get("conditions") or []
        failed_progress = [c for c in conditions if c.get("type") == "Progressing" and c.get("reason") in {"ProgressDeadlineExceeded", "ProgressDeadlineExceeded"}]
        if ready != desired or available != desired or failed_progress:
            resource = _resource("Deployment", dep)
            add(_evidence(
                "deployment_rollout_failure",
                resource,
                {"desired": desired, "ready": ready, "available": available, "conditions": conditions},
                "HIGH",
            ))

    # Service evidence explicitly ties selector -> matching pods -> endpoints.
    endpoints_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for ep in _items(toolkit.list_resources("endpoints")):
        meta = ep.get("metadata") or {}
        endpoints_by_key[(meta.get("namespace", "default"), meta.get("name", ""))] = ep

    for svc in services:
        meta, spec = svc.get("metadata") or {}, svc.get("spec") or {}
        selector = spec.get("selector") or {}
        if spec.get("type") == "ExternalName" or not selector:
            continue
        ns, name = meta.get("namespace", "default"), meta.get("name", "unknown")
        selector_query = _selector_string(selector)
        matching_pods = _items(toolkit.list_resources("pod", namespace=ns, label_selector=selector_query))
        ep = endpoints_by_key.get((ns, name)) or {}
        addresses = []
        not_ready = []
        for subset in ep.get("subsets") or []:
            addresses.extend(subset.get("addresses") or [])
            not_ready.extend(subset.get("not_ready_addresses") or subset.get("notReadyAddresses") or [])
        if not matching_pods or not addresses:
            resource = f"Service/{ns}/{name}"
            add(_evidence(
                "service_routing_failure",
                resource,
                {
                    "selector": selector,
                    "matching_pods": [_resource("Pod", p) for p in matching_pods],
                    "ready_endpoint_count": len(addresses),
                    "not_ready_endpoint_count": len(not_ready),
                    "endpoint_resource": f"Endpoints/{ns}/{name}",
                },
                "HIGH",
                [_resource("Pod", p) for p in matching_pods] + [f"Endpoints/{ns}/{name}"],
            ))

    # PVC evidence is deliberately limited to the claim and its events.
    for pvc in pvcs:
        status = pvc.get("status") or {}
        if status.get("phase") == "Bound":
            continue
        meta = pvc.get("metadata") or {}
        ns, name = meta.get("namespace", "default"), meta.get("name", "unknown")
        events = _items(toolkit.get_events(namespace=ns, resource_name=name, event_type="Warning"))
        add(_evidence(
            "pvc_binding_failure",
            f"PersistentVolumeClaim/{ns}/{name}",
            {"phase": status.get("phase"), "warning_events": [{"reason": e.get("reason"), "message": e.get("message")} for e in events]},
            "HIGH",
        ))

    return evidence


def evidence_as_json(evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return json.loads(json.dumps(evidence, default=str))
