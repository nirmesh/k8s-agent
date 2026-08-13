from __future__ import annotations

import json
import os
from typing import Any

from backend.ai.llm_client import chat
from backend.core.logging import logger

SYSTEM_PROMPT = """You are the diagnosis synthesis layer of a Kubernetes SRE agent.

You are NOT a Kubernetes API navigator. You receive VERIFIED, CORRELATED incidents produced by deterministic Kubernetes investigators.

Hard rules:
- Use only facts present in VERIFIED_INCIDENTS and their evidence_ids.
- Never invent resources, namespaces, image tags, selectors, probe paths, ports, commands, CVEs, or fixes.
- Do not merge unrelated incidents just because they are in the same namespace or use the same image.
- Each object in VERIFIED_INCIDENTS is already an independently correlated operational incident.
- Return one finding for EACH verified incident. Do not collapse multiple incidents into one summary.
- Do not create additional incidents that are not present in VERIFIED_INCIDENTS.
- Treat items listed under an incident's consequences as symptoms/consequences, not separate incidents.
- If a verified incident lacks enough detail for a precise explanation, preserve the incident and say NEED_MORE_EVIDENCE for that finding.
- A security finding is not an operational root cause unless explicitly present in the operational incidents supplied here.
- Do not propose remediation. The investigation phase only explains what is wrong and why.
- Confidence is confidence in the diagnosis, not severity.

Return ONLY JSON:
{
  "status": "DIAGNOSED | NEED_MORE_EVIDENCE | NO_ISSUE",
  "summary": "short human-readable summary",
  "findings": [
    {
      "incident_id": "exact incident_id from VERIFIED_INCIDENTS",
      "incident_type": "exact incident type",
      "root_cause": "one evidence-grounded sentence",
      "explanation": "short causal explanation",
      "confidence": 0.0,
      "affected_resources": ["exact resources from incident"],
      "evidence_ids": ["exact evidence ids from incident"]
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


def _call_model(payload: dict[str, Any]) -> dict[str, Any]:
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


def synthesize_incidents(incidents: list[dict[str, Any]], incident: str | None = None) -> dict[str, Any]:
    if not incidents:
        return {"status": "NO_ISSUE", "summary": "No operational anomalies were verified.", "findings": []}
    payload = {"incident": incident or "Cluster investigation", "VERIFIED_INCIDENTS": incidents}
    return _call_model(payload)


def synthesize(evidence: list[dict[str, Any]], incident: str | None = None) -> dict[str, Any]:
    """Backward-compatible raw-evidence synthesis; new LangGraph flow uses synthesize_incidents."""
    if not evidence:
        return {"status": "NO_ISSUE", "summary": "No operational anomalies were verified.", "findings": []}
    payload = {"incident": incident or "Cluster investigation", "VERIFIED_EVIDENCE": evidence}
    return _call_model(payload)


def validate_diagnosis(result: dict[str, Any], evidence: list[dict[str, Any]]) -> dict[str, Any]:
    """Reject model claims that cannot be traced to the verified evidence graph."""
    by_id = {str(item.get("id")): item for item in evidence}
    valid_resources = {str(item.get("resource")) for item in evidence if item.get("resource")}
    findings = []
    for finding in result.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        evidence_ids = [str(x) for x in finding.get("evidence_ids") or [] if str(x) in by_id]
        resources = [str(x) for x in finding.get("affected_resources") or [] if str(x) in valid_resources]
        if not evidence_ids or not resources:
            continue
        if not any(item.get("resource") in resources or set(item.get("related_resources") or []) & set(resources) for item in (by_id[eid] for eid in evidence_ids)):
            continue
        finding["evidence_ids"] = evidence_ids
        finding["affected_resources"] = resources
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


def ensure_complete_findings_from_incidents(result: dict[str, Any], incidents: list[dict[str, Any]]) -> dict[str, Any]:
    """Guarantee one validated finding per deterministic incident."""
    existing = {str(f.get("incident_id")) for f in result.get("findings") or []}
    findings = list(result.get("findings") or [])
    for incident in incidents:
        incident_id = str(incident.get("incident_id"))
        if incident_id in existing:
            continue
        findings.append({
            "incident_id": incident_id,
            "incident_type": incident.get("type", "unknown"),
            "root_cause": f"{incident.get('root_resource')} has a verified {incident.get('type')} incident.",
            "explanation": "The incident was established by deterministic Kubernetes evidence; the model did not return a complete finding for it.",
            "confidence": 0.90,
            "affected_resources": [incident.get("root_resource")] + list(incident.get("resources") or []),
            "evidence_ids": list(incident.get("evidence_ids") or []),
            "deterministic": True,
        })
    result["findings"] = findings
    result["status"] = "DIAGNOSED" if findings else "NO_ISSUE"
    return result
