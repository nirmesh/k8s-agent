from __future__ import annotations

from typing import Any


def _first_image(facts: dict[str, Any]) -> str | None:
    image = facts.get("image")
    if image:
        return str(image)
    for item in facts.get("image_references") or []:
        if item.get("image"):
            return str(item["image"])
    for item in facts.get("image_pull_failures") or []:
        for candidate in item.get("images") or []:
            if candidate:
                return str(candidate)
    return None


def _probe_facts(facts: dict[str, Any]) -> dict[str, Any]:
    configurations = facts.get("probe_configuration") or []
    probe = configurations[0] if configurations else {}
    readiness = probe.get("readiness") or {}
    http_get = readiness.get("http_get") or readiness.get("httpGet") or {}
    output: dict[str, Any] = {}
    if http_get.get("path") is not None:
        output["probe"] = "readiness"
        output["protocol"] = http_get.get("scheme") or "HTTP"
        output["path"] = http_get.get("path")
        output["port"] = http_get.get("port")
    failures = facts.get("probe_failures") or []
    for event in failures:
        message = str(event.get("message") or "")
        if "statuscode:" in message:
            output["observed_status"] = message.split("statuscode:", 1)[1].strip().split()[0]
            break
    if failures:
        output["failure_events"] = [{"reason": e.get("reason"), "message": e.get("message")} for e in failures]
    return output


def project_incidents_for_llm(incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert correlated Kubernetes incidents into compact semantic model input.

    This intentionally removes Kubernetes-client serialization artifacts (null fields,
    timestamps and full status/condition objects) while retaining the facts needed for
    diagnosis and exact evidence references for later validation.
    """
    projected: list[dict[str, Any]] = []
    for incident in incidents:
        signal = str(incident.get("type") or "unknown")
        facts = incident.get("facts") or {}
        compact: dict[str, Any] = {
            "incident_id": incident.get("incident_id"),
            "type": signal,
            "root_resource": incident.get("root_resource"),
            "resources": incident.get("resources") or [],
            "evidence_ids": incident.get("evidence_ids") or [],
            "affected_pods": incident.get("affected_pods") or [],
            "facts": {},
            "consequences": [],
        }

        if signal == "probe_failure":
            probe = _probe_facts(facts)
            if probe:
                compact["facts"]["probe"] = probe
            compact["facts"]["desired_replicas"] = facts.get("desired")
            compact["facts"]["ready_replicas"] = facts.get("ready")
            compact["facts"]["available_replicas"] = facts.get("available")
        elif signal == "image_pull_failure":
            compact["facts"]["image"] = _first_image(facts)
            compact["facts"]["container_status"] = "ImagePullBackOff"
            compact["facts"]["affected_pod_count"] = len(incident.get("affected_pods") or [])
        elif signal == "scheduling_failure":
            events = facts.get("scheduling_events") or []
            compact["facts"]["scheduling_failures"] = [{"reason": e.get("reason"), "message": e.get("message")} for e in events]
            constraints = facts.get("scheduling_constraints") or {}
            if constraints.get("node_selector"):
                compact["facts"]["node_selector"] = constraints.get("node_selector")
            if constraints.get("affinity"):
                compact["facts"]["affinity_present"] = True
        elif signal == "service_routing_failure":
            compact["facts"] = {
                "selector": facts.get("selector"),
                "matching_pods": facts.get("matching_pods") or [],
                "ready_endpoint_count": facts.get("ready_endpoint_count"),
                "not_ready_endpoint_count": facts.get("not_ready_endpoint_count"),
            }
        elif signal == "pvc_binding_failure":
            compact["facts"] = {
                "phase": facts.get("phase"),
                "warning_events": [{"reason": e.get("reason"), "message": e.get("message")} for e in facts.get("warning_events") or []],
            }
        elif signal == "deployment_rollout_failure":
            compact["facts"] = {
                "desired_replicas": facts.get("desired"),
                "ready_replicas": facts.get("ready"),
                "available_replicas": facts.get("available"),
            }
        else:
            compact["facts"] = {k: v for k, v in facts.items() if v not in (None, [], {}, "")}

        for consequence in incident.get("consequences") or []:
            compact["consequences"].append({
                "type": consequence.get("signal"),
                "resource": consequence.get("resource"),
                "evidence_id": consequence.get("evidence_id"),
            })

        # Remove empty optional fields to keep the prompt compact.
        compact["facts"] = {k: v for k, v in compact["facts"].items() if v not in (None, [], {}, "")}
        if not compact["resources"]:
            compact.pop("resources")
        if not compact["affected_pods"]:
            compact.pop("affected_pods")
        if not compact["consequences"]:
            compact.pop("consequences")
        projected.append(compact)

    return projected
