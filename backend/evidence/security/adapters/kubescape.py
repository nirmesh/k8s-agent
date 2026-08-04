import json
import re
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
        requested_category = (query or {}).get("category")
        requested_resource = (query or {}).get("resource")
        framework = self._framework(data)
        evidence: list[SecurityEvidence] = []

        # Kubescape can report results per resource or per control summary.
        results = data.get("results") if isinstance(data, dict) else data
        if not isinstance(results, list):
            results = [data] if data else []
        for result in results:
            resource = result.get("resourceID") or "cluster/-/-"
            if requested_resource and requested_resource not in resource:
                continue
            for control in result.get("controls") or []:
                status = control.get("status", {})
                if status.get("status") == "passed" or not status.get("status"):
                    continue
                category = self._control_category(control)
                if requested_category and category != requested_category.lower():
                    continue
                finding = SecurityFinding(
                    category=category,
                    resource=resource,
                    finding=control.get("name", "unknown"),
                    description=control.get("description", ""),
                    severity=self._normalize_severity(control.get("severity", "UNKNOWN")),
                    confidence=1.0,
                    remediation=control.get("remediation", "") or None,
                    rule_id=control.get("controlID") or control.get("id"),
                    cve_id=None,
                    framework=framework,
                    mitre_id=self._mitre_id(control),
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

        summary = data.get("summaryDetails", {}) if isinstance(data, dict) else {}
        controls = summary.get("controls") if isinstance(summary, dict) else None
        if isinstance(controls, dict):
            for control_id, control in controls.items():
                status = control.get("status", {})
                if status.get("status") == "passed" or not status.get("status"):
                    continue
                category = self._control_category(control)
                if requested_category and category != requested_category.lower():
                    continue
                resource = control.get("resourceID") or "cluster/-/-"
                if requested_resource and requested_resource not in resource:
                    continue
                finding = SecurityFinding(
                    category=category,
                    resource=resource,
                    finding=control.get("name", "unknown"),
                    description=control.get("description", ""),
                    severity=self._normalize_severity(control.get("severity", "UNKNOWN")),
                    confidence=1.0,
                    remediation=control.get("remediation", "") or None,
                    rule_id=control.get("controlID") or control_id,
                    cve_id=None,
                    framework=framework,
                    mitre_id=self._mitre_id(control),
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

    def _framework(self, data: dict[str, Any]) -> str | None:
        frameworks = data.get("metadata", {}).get("frameworks") if isinstance(data, dict) else None
        if isinstance(frameworks, list) and frameworks:
            return frameworks[0]
        fw = data.get("framework") if isinstance(data, dict) else None
        return str(fw) if fw else None

    def _control_category(self, control: dict[str, Any]) -> str:
        name = str(control.get("name", "")).lower()
        cid = str(control.get("controlID", control.get("id", ""))).lower()
        tags = [str(t).lower() for t in (control.get("tags") or [])]
        combined = name + " " + cid + " " + " ".join(tags)

        if any(k in combined for k in ("rbac", "role", "serviceaccount", "clusterrole")):
            return "rbac"
        if any(k in combined for k in ("network", "networkpolicy")):
            return "networkpolicy"
        if any(k in combined for k in ("secret", "credentials")):
            return "secrets"
        if any(k in combined for k in ("nsa", "nsa-cisa")):
            return "nsa_controls"
        if any(k in combined for k in ("mitre", "attack")):
            return "mitre"
        if any(k in combined for k in ("pod", "security", "privileged", "seccomp", "apparmor")):
            return "pod_security"
        return "misconfiguration"

    def _mitre_id(self, control: dict[str, Any]) -> str | None:
        tags = control.get("tags") or []
        for tag in tags:
            if isinstance(tag, str):
                match = re.search(r"T\d{4}(\.\d{3})?", tag)
                if match:
                    return match.group(0)
        return control.get("mitreAttack") or control.get("mitreID")

    def _normalize_severity(self, severity: str) -> str:
        return str(severity).upper() if severity else "UNKNOWN"
