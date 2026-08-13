from __future__ import annotations

import re
from typing import Any

WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}
PRIMARY_SIGNALS = {
    "image_pull_failure", "probe_failure", "scheduling_failure", "service_routing_failure",
    "pvc_binding_failure", "pod_unhealthy", "deployment_rollout_failure",
}
CONSEQUENCE_SIGNALS = {"deployment_rollout_failure"}
CAUSE_SIGNALS = PRIMARY_SIGNALS - CONSEQUENCE_SIGNALS


def _parts(resource: str) -> tuple[str, str, str]:
    parts = resource.split("/", 2)
    return (parts[0], parts[1], parts[2]) if len(parts) == 3 else ("", "", "")


def _canonical_name(kind: str, name: str) -> str:
    if kind == "ReplicaSet":
        match = re.match(r"^(.+)-[a-z0-9]{5,12}$", name)
        return match.group(1) if match else name
    if kind == "Pod":
        match = re.match(r"^(.+)-[a-z0-9]{5,12}-[a-z0-9]{4,12}$", name)
        if match:
            return _canonical_name("ReplicaSet", match.group(1))
    return name


def _workload_key(resource: str) -> tuple[str, str]:
    kind, namespace, name = _parts(resource)
    return namespace, _canonical_name(kind, name)


def _resource_for_key(resources: set[str], key: tuple[str, str]) -> str:
    namespace, canonical = key
    candidates: list[str] = []
    for resource in resources:
        kind, ns, name = _parts(resource)
        if ns == namespace and _canonical_name(kind, name) == canonical:
            if kind == "Deployment":
                return resource
            if kind in {"StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"}:
                candidates.append(resource)
    return sorted(candidates)[0] if candidates else f"Deployment/{namespace}/{canonical}"


def _merge(incident: dict[str, Any], item: dict[str, Any]) -> None:
    evidence_id = str(item.get("id"))
    if evidence_id not in incident["evidence_ids"]:
        incident["evidence_ids"].append(evidence_id)
    resource = str(item.get("resource") or "")
    if resource and resource not in incident["resources"]:
        incident["resources"].append(resource)
    for related in item.get("related_resources") or []:
        related = str(related)
        if related and related not in incident["resources"]:
            incident["resources"].append(related)

    signal = str(item.get("signal") or "")
    payload = item.get("payload") or {}
    if signal == "probe_failure":
        incident["facts"]["probe_failures"] = (incident["facts"].get("probe_failures") or []) + (payload.get("probe_events") or payload.get("warning_events") or [])
    elif signal == "probe_configuration":
        incident["facts"]["probe_configuration"] = payload.get("containers") or []
    elif signal == "image_pull_failure":
        incident["facts"]["image_pull_failures"] = (incident["facts"].get("image_pull_failures") or []) + [{"resource": resource, "events": payload.get("image_events") or payload.get("warning_events") or [], "images": payload.get("images") or []}]
    elif signal == "image_reference":
        incident["facts"]["image_references"] = payload.get("containers") or []
    elif signal == "scheduling_failure":
        incident["facts"]["scheduling_events"] = payload.get("scheduling_events") or payload.get("warning_events") or []
    elif signal == "scheduling_constraints":
        incident["facts"]["scheduling_constraints"] = payload
    elif signal == "service_routing_failure":
        incident["facts"].update({"selector": payload.get("selector"), "matching_pods": payload.get("matching_pods"), "ready_endpoint_count": payload.get("ready_endpoint_count"), "not_ready_endpoint_count": payload.get("not_ready_endpoint_count")})
    elif signal == "pvc_binding_failure":
        incident["facts"].update({"phase": payload.get("phase"), "warning_events": payload.get("warning_events") or []})
    elif signal == "deployment_rollout_failure":
        incident["facts"].update({"desired": payload.get("desired"), "ready": payload.get("ready"), "available": payload.get("available"), "conditions": payload.get("conditions") or []})


def correlate_incidents(evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse low-level observations into workload-level independent incidents."""
    resources = {str(item.get("resource")) for item in evidence if item.get("resource")}
    records: list[dict[str, Any]] = []

    for item in evidence:
        signal = str(item.get("signal") or "")
        if signal not in PRIMARY_SIGNALS and signal not in {"probe_configuration", "image_reference", "scheduling_constraints"}:
            continue
        resource = str(item.get("resource") or "")
        records.append({
            "item": item,
            "signal": signal,
            "resource": resource,
            "key": _workload_key(resource),
            "supporting": signal not in PRIMARY_SIGNALS,
        })

    keys = {r["key"] for r in records if r["key"] != ("", "")}
    root_by_key = {key: _resource_for_key(resources, key) for key in keys}
    groups: dict[tuple[str, tuple[str, str]], dict[str, Any]] = {}

    for record in records:
        signal, key = record["signal"], record["key"]
        if record["supporting"] or signal in CONSEQUENCE_SIGNALS:
            continue
        group_key = (signal, key)
        if group_key not in groups:
            root = root_by_key.get(key, record["resource"])
            groups[group_key] = {
                "incident_id": f"{signal}:{root}",
                "type": signal,
                "root_resource": root,
                "resources": [],
                "evidence_ids": [],
                "affected_pods": [],
                "facts": {},
                "consequences": [],
            }
        _merge(groups[group_key], record["item"])

    # Attach supporting evidence to the primary incident for the same workload.
    preferred_by_signal = {
        "probe_configuration": "probe_failure",
        "image_reference": "image_pull_failure",
        "scheduling_constraints": "scheduling_failure",
    }
    for record in records:
        if not record["supporting"]:
            continue
        target = groups.get((preferred_by_signal[record["signal"]], record["key"]))
        if target:
            _merge(target, record["item"])

    # Rollout failures are consequences when a more-specific cause exists for the same workload.
    for record in records:
        if record["signal"] != "deployment_rollout_failure":
            continue
        key = record["key"]
        causes = [g for (signal, gkey), g in groups.items() if gkey == key and signal in CAUSE_SIGNALS]
        if causes:
            for cause in causes:
                _merge(cause, record["item"])
                cause["consequences"].append({
                    "signal": "deployment_rollout_failure",
                    "resource": record["resource"],
                    "evidence_id": str(record["item"].get("id")),
                    "reason": "same workload has a more specific verified failure",
                })
        else:
            root = root_by_key.get(key, record["resource"])
            group_key = ("deployment_rollout_failure", key)
            groups[group_key] = {
                "incident_id": f"deployment_rollout_failure:{root}",
                "type": "deployment_rollout_failure",
                "root_resource": root,
                "resources": [],
                "evidence_ids": [],
                "affected_pods": [],
                "facts": {},
                "consequences": [],
            }
            _merge(groups[group_key], record["item"])

    incidents = list(groups.values())
    for incident in incidents:
        pods = set(incident.get("affected_pods") or [])
        for evidence_id in incident["evidence_ids"]:
            item = next((e for e in evidence if str(e.get("id")) == evidence_id), None)
            if item and str(item.get("resource") or "").startswith("Pod/"):
                pods.add(str(item.get("resource")))
        incident["affected_pods"] = sorted(pods)
        incident["resources"] = sorted(set(incident["resources"]))
        incident["evidence_ids"] = sorted(set(incident["evidence_ids"]))
        incident["consequences"] = sorted(incident["consequences"], key=lambda x: x.get("evidence_id", ""))

    return sorted(incidents, key=lambda x: (x["root_resource"], x["type"]))
