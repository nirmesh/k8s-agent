import json
from datetime import datetime, timezone
from typing import Any

from backend.evidence.security.model import SecurityEvidence, SecurityFinding
from backend.evidence.security.provider import SecurityProvider


class KubescapeAdapter(SecurityProvider):
    """Kubescape adapter. Accepts Kubescape JSON summary or list of results."""

    def __init__(self, source: Any | None = None):
        self._source = source

    @property
    def name(self) -> str:
        return "kubescape"

    def _load(self, query: dict[str, Any] | None) -> dict[str, Any] | None:
        source = (query or {}).get("source") if isinstance(query, dict) else None
        source = source or self._source
        if source is None:
            return None
        if isinstance(source, str):
            try:
                return json.loads(source)
            except json.JSONDecodeError:
                with open(source, "r", encoding="utf-8") as f:
                    return json.load(f)
        if isinstance(source, bytes):
            return json.loads(source.decode("utf-8"))
        return source if isinstance(source, dict) else None

    def collect(self, query: dict[str, Any] | None = None) -> list[SecurityEvidence]:
        data = self._load(query)
        if data is None:
            return []
        evidence: list[SecurityEvidence] = []
        results = data.get("results") if isinstance(data, dict) else data
        if not isinstance(results, list):
            results = [data] if data else []
        for result in results:
            resource = result.get("resourceID") or result.get("resourceID", "cluster/-/-")
            for control in result.get("controls") or []:
                status = control.get("status", {})
                if not status.get("status") or status.get("status") == "passed":
                    continue
                finding = SecurityFinding(
                    category="misconfiguration",
                    resource=resource,
                    finding=control.get("name", "unknown"),
                    description=control.get("description", ""),
                    severity=self._normalize_severity(control.get("severity", "UNKNOWN")),
                    confidence=1.0,
                    remediation=control.get("remediation", "") or None,
                    rule_id=control.get("controlID") or control.get("id"),
                    cve_id=None,
                )
                evidence.append(
                    SecurityEvidence(
                        provider=self.name,
                        type="security",
                        resource=finding.resource,
                        timestamp=datetime.now(timezone.utc),
                        confidence=finding.confidence,
                        severity=finding.severity,
                        payload=finding,
                    )
                )
        return evidence

    def _normalize_severity(self, severity: str) -> str:
        return str(severity).upper() if severity else "UNKNOWN"
