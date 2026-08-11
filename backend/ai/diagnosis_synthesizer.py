from __future__ import annotations

import json
from typing import Any, Callable

from backend.ai.llm_client import chat


SYSTEM_PROMPT = """You are the diagnosis synthesis layer of a Kubernetes SRE agent.

You are NOT a Kubernetes API navigator. You receive VERIFIED, STRUCTURED evidence collected by deterministic investigators.

Hard rules:
- Use only facts present in VERIFIED_EVIDENCE.
- Never invent resources, namespaces, image tags, selectors, probe paths, ports, commands, CVEs, or fixes.
- Do not merge evidence from unrelated resources just because they are in the same namespace.
- Prefer explicit resource relationships: owner, selector match, Endpoint/EndpointSlice membership, pod ownership, or the same involvedObject.
- A security finding is not an operational root cause unless the evidence explicitly establishes the causal relationship.
- If multiple independent incidents exist, return multiple findings rather than forcing one root cause.
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


def synthesize(evidence: list[dict[str, Any]], incident: str | None = None) -> dict[str, Any]:
    if not evidence:
        return {
            "status": "NO_ISSUE",
            "summary": "No operational anomalies were verified.",
            "findings": [],
        }

    payload = {
        "incident": incident or "Cluster investigation",
        "VERIFIED_EVIDENCE": evidence,
    }
    message = chat(
        [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(payload, default=str)},
        ],
        tools=None,
    )
    raw = (message.get("content") or "").strip()
    try:
        start = raw.index("{")
        result, _ = json.JSONDecoder().raw_decode(raw, start)
    except Exception:
        return {
            "status": "NEED_MORE_EVIDENCE",
            "summary": "The diagnosis model did not return a valid structured diagnosis.",
            "findings": [],
            "model_error": "invalid_json",
        }
    if not isinstance(result, dict):
        return {
            "status": "NEED_MORE_EVIDENCE",
            "summary": "The diagnosis model returned an invalid result.",
            "findings": [],
        }
    return result


def validate_diagnosis(result: dict[str, Any], evidence: list[dict[str, Any]]) -> dict[str, Any]:
    """Reject model claims that cannot be traced to collected evidence."""
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
        confidence = finding.get("confidence", 0)
        try:
            confidence = max(0.0, min(1.0, float(confidence)))
        except (TypeError, ValueError):
            confidence = 0.0
        finding["evidence_ids"] = evidence_ids
        finding["affected_resources"] = resources
        finding["confidence"] = confidence
        findings.append(finding)

    if not findings:
        result["status"] = "NEED_MORE_EVIDENCE" if evidence else "NO_ISSUE"
        result["findings"] = []
        result.setdefault("summary", "No evidence-grounded diagnosis was established.")
        return result

    result["findings"] = findings
    result["status"] = "DIAGNOSED"
    return result
