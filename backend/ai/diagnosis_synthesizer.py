from __future__ import annotations

import json
import os
from typing import Any

from backend.ai.llm_client import chat
from backend.core.logging import logger

SYSTEM_PROMPT = """You are the diagnosis synthesis layer of a Kubernetes SRE agent.

You are NOT a Kubernetes API navigator. You receive VERIFIED, STRUCTURED evidence collected by deterministic investigators.

Hard rules:
- Use only facts present in VERIFIED_EVIDENCE.
- Never invent resources, namespaces, image tags, selectors, probe paths, ports, commands, CVEs, or fixes.
- Do not merge evidence from unrelated resources just because they are in the same namespace.
- Prefer explicit resource relationships: owner, selector match, Endpoint/EndpointSlice membership, pod ownership, or the same involvedObject.
- A security finding is not an operational root cause unless the evidence explicitly establishes the causal relationship.
- If multiple independent incidents exist, return one finding for EACH independent incident. Do not return only the single most severe incident.
- Every independent operational signal in VERIFIED_EVIDENCE must either be represented by a finding or be explicitly explained as a consequence/symptom of another finding on the same resource relationship.
- A deployment rollout failure caused by a verified probe/image/scheduling failure on the same workload is a consequence, not a second incident. An unrelated broken Deployment MUST remain a separate finding.
- If evidence is insufficient or contradictory, return NEED_MORE_EVIDENCE.
- Do not propose remediation. The investigation phase only explains what is wrong and why.
- Confidence is your confidence in the diagnosis, not the severity of the issue.

Return ONLY JSON:
{
  "status": "DIAGNOSED | NEED_MORE_EVIDENCE | NO_ISSUE",
  "summary": "short human-readable summary",
  "findings": [
    {
      "incident_type": "stable signal name",
      "root_cause": "one evidence-grounded sentence",
      "explanation": "short causal explanation",
      "confidence": 0.0,
      "affected_resources": ["Kind/namespace/name"],
      "evidence_ids": ["evidence-id"]
    }
  ]
}
"""


def _debug_prompt_logging_enabled() -> bool:
    return os.getenv("DEBUG_LLM_PROMPT", "false").strip().lower() in {"1", "true", "yes", "on"}


def _log_llm_input(payload: dict[str, Any]) -> None:
    if not _debug_prompt_logging_enabled():
        return
    prompt = json.dumps(payload, default=str, indent=2)
    logger.warning("=== LLM INPUT BEGIN ===")
    logger.warning("SYSTEM_PROMPT:\n{}", SYSTEM_PROMPT)
    logger.warning("USER_PAYLOAD:\n{}", prompt)
    logger.warning("=== LLM INPUT END ===")


def synthesize(evidence: list[dict[str, Any]], incident: str | None = None) -> dict[str, Any]:
    if not evidence:
        return {"status": "NO_ISSUE", "summary": "No operational anomalies were verified.", "findings": []}
    payload = {"incident": incident or "Cluster investigation", "VERIFIED_EVIDENCE": evidence}
    _log_llm_input(payload)
    message = chat(
        [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": json.dumps(payload, default=str)}],
        tools=None,
    )
    raw = (message.get("content") or "").strip()
    try:
        start = raw.index("{")
        result, _ = json.JSONDecoder().raw_decode(raw, start)
    except Exception:
        return {"status": "NEED_MORE_EVIDENCE", "summary": "The diagnosis model did not return valid structured output.", "findings": [], "model_error": "invalid_json"}
    if not isinstance(result, dict):
        return {"status": "NEED_MORE_EVIDENCE", "summary": "The diagnosis model returned an invalid result.", "findings": []}
    return result

_SIGNAL_ALIASES = {
    "image": {"image_pull_failure", "image_reference"}, "pull": {"image_pull_failure", "image_reference"},
    "probe": {"probe_failure", "probe_configuration", "deployment_rollout_failure"}, "readiness": {"probe_failure", "probe_configuration", "deployment_rollout_failure"},
    "liveness": {"probe_failure", "probe_configuration", "deployment_rollout_failure"}, "startup": {"probe_failure", "probe_configuration", "deployment_rollout_failure"},
    "schedule": {"scheduling_failure", "scheduling_constraints"}, "scheduling": {"scheduling_failure", "scheduling_constraints"},
    "service": {"service_routing_failure"}, "endpoint": {"service_routing_failure"},
    "pvc": {"pvc_binding_failure"}, "storage": {"pvc_binding_failure"},
    "deployment": {"deployment_rollout_failure"}, "rollout": {"deployment_rollout_failure"},
    "pod": {"pod_unhealthy", "image_pull_failure", "probe_failure", "scheduling_failure"},
}

PRIMARY_SIGNALS = {
    "image_pull_failure",
    "probe_failure",
    "scheduling_failure",
    "service_routing_failure",
    "pvc_binding_failure",
    "pod_unhealthy",
    "deployment_rollout_failure",
}


def _finding_is_grounded(finding: dict[str, Any], by_id: dict[str, dict[str, Any]], valid_resources: set[str]) -> bool:
    evidence_ids = [str(x) for x in finding.get("evidence_ids") or [] if str(x) in by_id]
    resources = [str(x) for x in finding.get("affected_resources") or [] if str(x) in valid_resources]
    if not evidence_ids or not resources:
        return False
    incident_type = str(finding.get("incident_type") or "").lower()
    relevant_signals: set[str] = set()
    for alias, signals in _SIGNAL_ALIASES.items():
        if alias in incident_type:
            relevant_signals.update(signals)
    cited = [by_id[eid] for eid in evidence_ids]
    cited_signals = {str(item.get("signal")) for item in cited}
    if relevant_signals and not (cited_signals & relevant_signals):
        return False
    return any(item.get("resource") in resources or set(item.get("related_resources") or []) & set(resources) for item in cited)


def _workload_resource(item: dict[str, Any], valid_resources: set[str]) -> str:
    resource = str(item.get("resource") or "")
    for related in item.get("related_resources") or []:
        related = str(related)
        if related in valid_resources and related.split("/", 1)[0] in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}:
            return related
    return resource


def _deterministic_finding(item: dict[str, Any], valid_resources: set[str]) -> dict[str, Any]:
    signal = str(item.get("signal"))
    resource = _workload_resource(item, valid_resources)
    if signal == "image_pull_failure":
        root = f"{resource} has a container image pull failure; the verified Pod evidence shows the image could not be pulled."
        explanation = "The Kubernetes Pod/container status or scoped Warning events contain image-pull-specific failure evidence."
        incident_type = "image_pull_failure"
    elif signal == "probe_failure":
        root = f"{resource} has a failing health probe; the verified Pod evidence shows the configured probe is failing."
        explanation = "The affected Pod has a scoped probe failure event, and the owning workload configuration was captured as evidence."
        incident_type = "probe_failure"
    elif signal == "scheduling_failure":
        root = f"{resource} has a scheduling failure preventing the workload from being placed on a node."
        explanation = "The affected Pod has a scoped FailedScheduling or unschedulable event."
        incident_type = "scheduling_failure"
    elif signal == "service_routing_failure":
        root = f"{resource} has no usable Service routing path to ready endpoints."
        explanation = "The verified Service selector, matching Pods, and Endpoints evidence show that the Service has no ready endpoint path."
        incident_type = "service_routing_failure"
    elif signal == "pvc_binding_failure":
        root = f"{resource} is not Bound, so the requested persistent storage is unavailable."
        explanation = "The PVC status and its resource-scoped Warning events show a binding problem."
        incident_type = "pvc_binding_failure"
    elif signal == "deployment_rollout_failure":
        root = f"{resource} has fewer ready or available replicas than desired."
        explanation = "The verified Deployment spec/status shows the rollout has not reached its desired replica state."
        incident_type = "deployment_rollout_failure"
    else:
        root = f"{resource} is unhealthy according to verified Kubernetes status/events."
        explanation = "The workload has a verified unhealthy Pod signal, but the available evidence does not establish a more specific cause."
        incident_type = "pod_unhealthy"

    confidence = 0.92 if signal != "deployment_rollout_failure" else 0.90
    return {
        "incident_type": incident_type,
        "root_cause": root,
        "explanation": explanation,
        "confidence": confidence,
        "affected_resources": [resource],
        "evidence_ids": [str(item.get("id"))],
        "deterministic": True,
    }


def _covered_by_existing(item: dict[str, Any], findings: list[dict[str, Any]], by_id: dict[str, dict[str, Any]]) -> bool:
    signal = str(item.get("signal"))
    resource = str(item.get("resource") or "")
    related = {str(x) for x in item.get("related_resources") or []}
    for finding in findings:
        finding_resources = {str(x) for x in finding.get("affected_resources") or []}
        finding_evidence = {str(x) for x in finding.get("evidence_ids") or []}
        if str(item.get("id")) in finding_evidence:
            return True
        if resource in finding_resources or related & finding_resources:
            if signal == "deployment_rollout_failure":
                return any(str(by_id[eid].get("signal")) in {"image_pull_failure", "probe_failure", "scheduling_failure"} for eid in finding_evidence if eid in by_id)
            if signal in PRIMARY_SIGNALS:
                return True
    return False


def ensure_complete_findings(result: dict[str, Any], evidence: list[dict[str, Any]]) -> dict[str, Any]:
    by_id = {str(item.get("id")): item for item in evidence}
    findings = list(result.get("findings") or [])
    for item in evidence:
        if str(item.get("signal")) not in PRIMARY_SIGNALS:
            continue
        if not _covered_by_existing(item, findings, by_id):
            findings.append(_deterministic_finding(item, {str(e.get("resource")) for e in evidence if e.get("resource")}))
    result["findings"] = findings
    result["status"] = "DIAGNOSED" if findings else ("NO_ISSUE" if not evidence else "NEED_MORE_EVIDENCE")
    return result


def validate_diagnosis(result: dict[str, Any], evidence: list[dict[str, Any]]) -> dict[str, Any]:
    by_id = {str(item.get("id")): item for item in evidence}
    valid_resources = {str(item.get("resource")) for item in evidence if item.get("resource")}
    findings = []
    for finding in result.get("findings") or []:
        if not isinstance(finding, dict) or not _finding_is_grounded(finding, by_id, valid_resources):
            continue
        finding["evidence_ids"] = [str(x) for x in finding.get("evidence_ids") or [] if str(x) in by_id]
        finding["affected_resources"] = [str(x) for x in finding.get("affected_resources") or [] if str(x) in valid_resources]
        try:
            finding["confidence"] = max(0.0, min(1.0, float(finding.get("confidence", 0))))
        except (TypeError, ValueError):
            finding["confidence"] = 0.0
        findings.append(finding)
    result["findings"] = findings
    if not findings:
        result["status"] = "NEED_MORE_EVIDENCE" if evidence else "NO_ISSUE"
        result.setdefault("summary", "No evidence-grounded diagnosis was established.")
        return result
    result["status"] = "DIAGNOSED"
    return result
