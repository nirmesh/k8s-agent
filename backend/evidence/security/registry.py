from __future__ import annotations

from typing import Any

from backend.core.logging import logger
from backend.evidence.model import Evidence
from backend.evidence.security.model import SecurityEvidence
from backend.evidence.security.provider import SecurityProvider


class SecurityRegistry:
    """Registry of security provider adapters.

    Investigation logic consumes normalized evidence by layer/domain. Individual
    scanner names remain implementation details and provenance only.
    """

    _TOOL_NAME = "collect_security_evidence"

    def __init__(self):
        self._providers: dict[str, SecurityProvider] = {}

    def register(self, provider: SecurityProvider) -> "SecurityRegistry":
        self._providers[provider.name] = provider
        return self

    def list(self) -> list[str]:
        return list(self._providers.keys())

    def collect_all(self, query: dict[str, Any] | None = None) -> list[SecurityEvidence]:
        evidence: list[SecurityEvidence] = []
        for provider in self._providers.values():
            try:
                items = provider.collect(query)
                for item in items:
                    if query:
                        if query.get("resource") and item.resource != query["resource"]:
                            continue
                        if query.get("category") and item.category != query["category"]:
                            continue
                        if query.get("severity") and (item.severity or "").upper() != str(query["severity"]).upper():
                            continue
                    evidence.append(item)
            except Exception as exc:
                logger.warning(f"Security provider '{provider.name}' collection failed: {exc}")
        return evidence

    def execute(self, tool: str, **kwargs) -> Evidence:
        if tool != self._TOOL_NAME:
            raise NotImplementedError(f"Security registry does not support tool '{tool}'")
        query = {k: v for k, v in kwargs.items() if v is not None}
        evidence = self.collect_all(query or None)
        return Evidence(
            provider="security",
            type="security",
            resource=query.get("resource") or "cluster/-/-",
            payload=[e.model_dump(mode="json") for e in evidence],
            confidence=1.0,
            severity=None,
        )

    def tools(self) -> list[dict[str, Any]]:
        return [{
            "type": "function",
            "function": {
                "name": self._TOOL_NAME,
                "description": "Collect normalized security evidence from enabled security providers. Filter by resource, layer, domain, category, or severity.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "resource": {"type": ["string", "null"]},
                        "layer": {"type": ["string", "null"], "enum": ["posture", "attack_surface", "supply_chain", "runtime", "compliance", None]},
                        "domain": {"type": ["string", "null"]},
                        "category": {"type": ["string", "null"]},
                        "severity": {"type": ["string", "null"]},
                    },
                    "required": [],
                },
            }
        }]

    def health(self) -> dict[str, Any]:
        return {name: provider.health() for name, provider in self._providers.items()}


_DEFAULT_REGISTRY: SecurityRegistry | None = None


def get_security_registry(
    trivy_source: Any | None = None,
    falco_source: Any | None = None,
    kubescape_source: Any | None = None,
    posture_source: Any | None = None,
) -> SecurityRegistry:
    """Return a default registry with optional security providers."""
    global _DEFAULT_REGISTRY
    if _DEFAULT_REGISTRY is None:
        from backend.evidence.security.adapters.falco import FalcoAdapter
        from backend.evidence.security.adapters.kubescape import KubescapeAdapter
        from backend.evidence.security.adapters.posture import KubernetesPostureAdapter
        from backend.evidence.security.adapters.trivy import TrivyAdapter

        _DEFAULT_REGISTRY = SecurityRegistry()
        _DEFAULT_REGISTRY.register(TrivyAdapter(source=trivy_source))
        _DEFAULT_REGISTRY.register(FalcoAdapter(source=falco_source))
        _DEFAULT_REGISTRY.register(KubescapeAdapter(source=kubescape_source))
        _DEFAULT_REGISTRY.register(KubernetesPostureAdapter(source=posture_source))
    return _DEFAULT_REGISTRY
