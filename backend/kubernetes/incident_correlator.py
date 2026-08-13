from __future__ import annotations

from collections import defaultdict
from typing import Any

WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}
PRIMARY_SIGNALS = {
    "image_pull_failure",
    "probe_failure",
    "scheduling_failure",
    "service_routing_failure",
    "pvc_binding_failure",
    "pod_unhealthy",
    "deployment_rollout_failure",
}
CONSEQUENCE_SIGNALS = {"deployment_rollout_failure"}
CAUSE_SIGNALS = {"image_pull_failure", "probe_failure", "scheduling_failure", "service_routing_failure", "pvc_binding_failure", "pod_unhealthy"}


def _kind(resource: str) -> str:
    return resource.split("/", 1)[0] if resource else ""


def _ns_name(resource: str) -> tuple[str, str]:
    parts = resource.split("/", 2)
    if len(parts) != 3:
        return "", ""
    return parts[1], parts[2]


def _workload_from_relationships(item: dict[str, Any], resources: set[str]) -> str:
    resource = str(item.get("resource") or "")
    related = [str(x) for x in item.get("related_resources") or []]
    candidates = [resource, *related]
    for candidate in candidates:
        if candidate in resources and _kind(candidate) in WORKLOAD_KINDS:
            return candidate
    return resource


def _incident_for_workload(workload: str, signal: str) -> str:
    return f"{signal}:{workload}"


def _merge_incident(incident: dict[str, Any], item: dict[str, Any], resources: set[str]) -> None:
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
    payload = item.get("payload") or {}
    signal = str(item.get("signal") or "")
    if signal == "probe_failure":
        incident["facts"]["probe_failure"] = payload.get("probe_events") or payload.get("warning_events") or []
        incident["facts"]["affected_pods"] = [resource]
    elif signal == "probe_configuration":
        incident["facts"]["probe_configuration"] = payload.get("containers") or []
    elif signal == "image_pull_failure":
        incident["facts"]["image_pull_failures"] = (incident["facts"].get("image_pull_failures") or []) + [{"resource": resource, "events": payload.get("image_events") or payload.get("warning_events") or [], "images": payload.get("images") or []}]
        for image in payload.get("images") or []:
            if image and "image" not in incident["facts"]:
                incident["facts"]["image"] = image
    elif signal == "image_reference":
        refs = payload.get("containers") or []
        incident["facts"]["image_references"] = refs
        for ref in refs:
            image = ref.get("image")
            if image:
                incident["facts"]["image"] = image
    elif signal == "scheduling_failure":
        incident["facts"]["scheduling_events"] = payload.get("scheduling_events") or payload.get("warning_events") or []
    elif signal == "scheduling_constraints":
        incident["facts"]["scheduling_constraints"] = payload
    elif signal == "service_routing_failure":
        incident["facts"].update({
            "selector": payload.get("selector"),
            "matching_pods": payload.get("matching_pods"),
            "ready_endpoint_count": payload.get("ready_endpoint_count"),
            "not_ready_endpoint_count": payload.get("not_ready_endpoint_count"),
        })
    elif signal == "pvc_binding_failure":
        incident["facts"].update({"phase": payload.get("phase"), "warning_events": payload.get("warning_events") or []})
    elif signal == "deployment_rollout_failure":
        incident["facts"].update({
            "desired": payload.get("desired"),
            "ready": payload.get("ready"),
            "available": payload.get("available"),
            "conditions": payload.get("conditions") or [],
        })


def _can_link(candidate: dict[str, Any], cause: dict[str, Any]) -> bool:
    if cause["signal"] not in CAUSE_SIGNALS:
        return False
    if candidate["signal"] not in CONSEQUENCE_SIGNALS:
        return False
    candidate_workload = candidate["workload"]
    cause_workload = cause["workload"]
    if candidate_workload == cause_workload:
        return True
    candidate_related = set(candidate.get("related_resources") or [])
    cause_resources = set(cause.get("resources") or [])
    return bool(candidate_related & cause_resources)


def correlate_incidents(evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize raw operational evidence into independent incidents.

    Multiple replicas and low-level evidence items are collapsed into one incident
    per root workload/signal. Deployment rollout failures are attached as consequences
    when the same workload already has a more specific cause signal.
    """
    resources = {str(item.get("resource")) for item in evidence if item.get("resource")}
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    raw_items: list[dict[str, Any]] = []

    for item in evidence:
        signal = str(item.get("signal") or "")
        if signal not in PRIMARY_SIGNALS and signal not in {"probe_configuration", "image_reference", "scheduling_constraints"}:
            continue
        resource = str(item.get("resource") or "")
        workload = _workload_from_relationships(item, resources)
        if signal in {"probe_configuration", "image_reference", "scheduling_constraints"}:
            # Attach supporting evidence to the most likely primary incident on the same workload.
            raw_items.append({"item": item, "signal": signal, "workload": workload, "resource": resource, "supporting": True})
            continue
        raw = {"item": item, "signal": signal, "workload": workload, "resource": resource, "related_resources": [str(x) for x in item.get("related_resources") or []]}
        raw_items.append(raw)

        if signal == "deployment_rollout_failure":
            continue
        key = (signal, workload)
        if key not in groups:
            groups[key] = {
                "incident_id": f"{signal}:{workload}",
                "type": signal,
                "root_resource": workload,
                "resources": [],
                "evidence_ids": [],
                "affected_pods": [],
                "facts": {},
                "consequences": [],
            }
        _merge_incident(groups[key], item, resources)

    # Attach supporting evidence such as probe configuration and image references.
    for raw in raw_items:
        if not raw.get("supporting"):
            continue
        item = raw["item"]
        workload = raw["workload"]
        candidate_groups = [g for g in groups.values() if g["root_resource"] == workload]
        if not candidate_groups:
            continue
        # Prefer a matching cause type when possible.
        if raw["signal"] == "probe_configuration":
            preferred = [g for g in candidate_groups if g["type"] == "probe_failure"]
        elif raw["signal"] == "image_reference":
            preferred = [g for g in candidate_groups if g["type"] == "image_pull_failure"]
        else:
            preferred = [g for g in candidate_groups if g["type"] == "scheduling_failure"]
        target = preferred[0] if preferred else candidate_groups[0]
        _merge_incident(target, item, resources)

    # Convert rollout failures into consequences where a specific cause exists;
    # otherwise preserve the rollout failure as its own incident.
    for raw in raw_items:
        if raw["signal"] != "deployment_rollout_failure":
            continue
        item = raw["item"]
        candidate = {
            "signal": raw["signal"],
            "workload": raw["workload"],
            "related_resources": raw.get("related_resources") or [],
            "resources": [str(item.get("resource") or "")],
        }
        causes = [g for g in groups.values() if _can_link(candidate, g)]
        if causes:
            for cause in causes:
                _merge_incident(cause, item, resources)
                consequence = {"signal": "deployment_rollout_failure", "resource": str(item.get("resource") or ""), "evidence_id": str(item.get("id")), "reason": "same workload has fewer ready/available replicas while a more specific verified failure is present"}
                if consequence not in cause["consequences"]:
                    cause["consequences"].append(consequence)
        else:
            key = ("deployment_rollout_failure", raw["workload"])
            groups[key] = {
                "incident_id": f"deployment_rollout_failure:{raw['workload']}",
                "type": "deployment_rollout_failure",
                "root_resource": raw["workload"],
                "resources": [],
                "evidence_ids": [],
                "affected_pods": [],
                "facts": {},
                "consequences": [],
            }
            _merge_incident(groups[key], item, resources)

    incidents = list(groups.values())
    for incident in incidents:
        pods = set(incident.get("affected_pods") or [])
        for evidence_id in incident.get("evidence_ids") or []:
            item = next((e for e in evidence if str(e.get("id")) == evidence_id), None)
            if item and str(item.get("resource") or "").startswith("Pod/"):
                pods.add(str(item.get("resource")))
        incident["affected_pods"] = sorted(pods)
        incident["resources"] = sorted(set(incident.get("resources") or []))
        incident["evidence_ids"] = sorted(set(incident.get("evidence_ids") or []))
        incident["consequences"] = sorted(incident.get("consequences") or [], key=lambda x: x.get("evidence_id", ""))
    return sorted(incidents, key=lambda x: (x["root_resource"], x["type"]))
