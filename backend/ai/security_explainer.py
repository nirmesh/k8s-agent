from __future__ import annotations

import json
from typing import Any

from backend.ai.llm_client import chat
from backend.core.logging import logger

SYSTEM_PROMPT = """You are the security-explanation layer of a Kubernetes security agent.

You receive VERIFIED security findings produced by deterministic providers such as Kubernetes, Trivy and Falco. You do not invent evidence.

For each finding:
- preserve the exact id and evidence facts;
- explain why the observed behavior/configuration matters in this specific cluster context;
- provide a concise, actionable remediation and a concrete verification step;
- classify severity as CRITICAL, HIGH, MEDIUM, LOW, or UNKNOWN from the verified evidence and provider severity;
- do not call something critical merely because it sounds scary;
- do not downgrade a provider CRITICAL finding;
- if evidence is insufficient, use UNKNOWN and say what evidence is missing;
- do not invent commands, resources, CVEs, namespaces, ports, image tags, or configuration values.

Return ONLY JSON in this shape:
{"findings":[{"id":"exact-id","severity":"CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN","why":"...","fix":"...","verify":"..."}]}
"""


def _decode(raw: str) -> dict[str, Any] | None:
    try:
        start = raw.index("{")
        value, _ = json.JSONDecoder().raw_decode(raw, start)
        return value if isinstance(value, dict) else None
    except Exception:
        return None


def enrich_security_issues(issues: list[dict[str, Any]], limit: int = 10) -> list[dict[str, Any]]:
    """Use the configured LLM to explain the operator-visible security findings.

    The scanner/provider remains the source of truth for evidence. The model only
    rewrites the human-facing explanation, remediation, verification and severity.
    """
    candidates = issues[:limit]
    if not candidates:
        return issues

    payload = {
        "verified_findings": [
            {
                "id": i.get("id"),
                "title": i.get("title"),
                "provider": i.get("source"),
                "provider_severity": i.get("severity"),
                "category": i.get("category"),
                "layer": i.get("layer"),
                "affected_resources": i.get("affected_resources") or [],
                "evidence": i.get("proof") or i.get("evidence") or "",
                "occurrences": i.get("occurrences", 1),
            }
            for i in candidates
        ]
    }

    try:
        response = chat(
            [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(payload, default=str)},
            ],
            tools=None,
        )
        result = _decode((response.get("content") or "").strip())
        if not result:
            logger.warning("Security explanation LLM returned invalid JSON")
            return issues

        by_id = {str(item.get("id")): item for item in (result.get("findings") or []) if isinstance(item, dict)}
        allowed = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
        for issue in candidates:
            model = by_id.get(str(issue.get("id")))
            if not model:
                continue
            severity = str(model.get("severity") or issue.get("severity") or "UNKNOWN").upper()
            if severity not in allowed:
                severity = issue.get("severity") or "UNKNOWN"
            if str(issue.get("severity")).upper() == "CRITICAL":
                severity = "CRITICAL"
            issue["severity"] = severity
            if model.get("why"):
                issue["why"] = str(model["why"])
            if model.get("fix"):
                issue["fix"] = str(model["fix"])
            if model.get("verify"):
                issue["verify"] = str(model["verify"])
            issue["explanation_source"] = "llm"
        return issues
    except Exception as exc:
        logger.warning("Security explanation LLM failed: %s", exc)
        return issues
