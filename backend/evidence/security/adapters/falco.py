import json
from datetime import datetime, timezone
from typing import Any

from backend.evidence.security.model import SecurityEvidence, SecurityFinding
from backend.evidence.security.provider import SecurityProvider


class FalcoAdapter(SecurityProvider):
    """Falco adapter. Accepts newline-delimited JSON Falco events or a list of dicts."""

    def __init__(self, source: Any | None = None):
        self._source = source

    @property
    def name(self) -> str:
        return "falco"

    def _load(self, query: dict[str, Any] | None) -> list[dict[str, Any]]:
        source = (query or {}).get("source") if isinstance(query, dict) else None
        source = source or self._source
        if source is None:
            return []
        if isinstance(source, str):
            try:
                parsed = json.loads(source)
                if isinstance(parsed, list):
                    return parsed
                if isinstance(parsed, dict):
                    return [parsed]
            except json.JSONDecodeError:
                events = []
                for line in source.strip().splitlines():
                    line = line.strip()
                    if line:
                        events.append(json.loads(line))
                return events
        elif isinstance(source, bytes):
            return self._load({"source": source.decode("utf-8")})
        elif isinstance(source, list):
            return source
        elif isinstance(source, dict):
            return [source]
        return []

    def collect(self, query: dict[str, Any] | None = None) -> list[SecurityEvidence]:
        events = self._load(query)
        requested_category = (query or {}).get("category")
        requested_resource = (query or {}).get("resource")
        evidence: list[SecurityEvidence] = []
        for event in events:
            category = self._event_category(event)
            if requested_category and category != requested_category.lower():
                continue
            resource = self._event_resource(event)
            if requested_resource and requested_resource not in resource:
                continue
            rule = event.get("rule", "unknown")
            description = event.get("output", "")
            finding = SecurityFinding(
                category=category,
                resource=resource,
                finding=rule,
                description=description,
                severity=self._normalize_severity(event.get("priority", "UNKNOWN")),
                confidence=1.0,
                remediation=None,
                rule_id=rule,
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

    def _event_resource(self, event: dict[str, Any]) -> str:
        fields = event.get("output_fields") or {}
        for key in ("pod.name", "k8s.pod.name", "proc.name", "fd.name"):
            val = fields.get(key)
            if val:
                return str(val)
        return "cluster/-/-"

    def _event_category(self, event: dict[str, Any]) -> str:
        rule = str(event.get("rule", "")).lower()
        fields = event.get("output_fields") or {}
        proc = str(fields.get("proc.name", "")).lower()
        fd = str(fields.get("fd.name", "")).lower()
        fd_type = str(fields.get("fd.type", "")).lower()
        evt_type = str(fields.get("evt.type", "")).lower()
        cmd = str(fields.get("proc.cmdline", "")).lower()

        if "shell" in rule or proc.endswith(("/sh", "/bash", "/zsh")) or "shell" in cmd:
            return "shell_execution"
        if any(k in rule for k in ("privilege", "sudo", "setuid", "escalation")):
            return "privilege_escalation"
        if any(k in rule for k in ("escape", "nsenter", "chroot", "mount")):
            return "container_escape"
        if any(k in rule for k in ("write", "modify", "modification", "file")):
            return "file_modification"
        if any(k in rule for k in ("network", "connection", "outbound", "egress")) or fd_type in ("ipv4", "ipv6"):
            return "unexpected_network_connection"
        return "threat"

    def _normalize_severity(self, priority: str) -> str:
        return str(priority).upper() if priority else "UNKNOWN"
