import json
from datetime import datetime, timezone
from typing import Any

from backend.evidence.security.model import SecurityEvidence, SecurityFinding
from backend.evidence.security.provider import SecurityProvider


class TrivyAdapter(SecurityProvider):
    """Trivy scanner adapter. Expects Trivy JSON report payload.

    Supports:
      - path to a JSON file
      - raw JSON string
      - parsed Python dict/list
    """

    def __init__(self, source: Any | None = None):
        self._source = source

    @property
    def name(self) -> str:
        return "trivy"

    def _load(self, query: dict[str, Any] | None) -> list[dict[str, Any]]:
        source = (query or {}).get("source") if isinstance(query, dict) else None
        source = source or self._source
        if source is None:
            return []
        if isinstance(source, str):
            try:
                data = json.loads(source)
            except json.JSONDecodeError:
                with open(source, "r", encoding="utf-8") as f:
                    data = json.load(f)
        elif isinstance(source, bytes):
            data = json.loads(source.decode("utf-8"))
        else:
            data = source
        if isinstance(data, dict):
            return [data]
        return data if isinstance(data, list) else []

    def collect(self, query: dict[str, Any] | None = None) -> list[SecurityEvidence]:
        reports = self._load(query)
        evidence: list[SecurityEvidence] = []
        for report in reports:
            for result in report.get("Results", []):
                target = result.get("Target", "unknown")
                for vuln in result.get("Vulnerabilities") or result.get("Vulnerabilities", []):
                    finding = SecurityFinding(
                        category="vulnerability",
                        resource=f"image/{target}",
                        finding=f"{vuln.get('VulnerabilityID', 'unknown')}: {vuln.get('Title', '')}",
                        description=vuln.get("Description", ""),
                        severity=self._normalize_severity(vuln.get("Severity", "UNKNOWN")),
                        confidence=1.0,
                        remediation=self._remediation(vuln),
                        rule_id=None,
                        cve_id=vuln.get("VulnerabilityID"),
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

    def _remediation(self, vuln: dict[str, Any]) -> str | None:
        parts = []
        if vuln.get("FixedVersion"):
            parts.append(f"Upgrade to {vuln['FixedVersion']}.")
        if vuln.get("PrimaryURL"):
            parts.append(vuln["PrimaryURL"])
        return " ".join(parts) if parts else None
