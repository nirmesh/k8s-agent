from __future__ import annotations

from typing import Any

from backend.core.logging import logger
from backend.evidence.model import Evidence
from backend.evidence.security.model import SecurityDomain, SecurityEvidence, SecurityLayer
from backend.evidence.security.provider import SecurityProvider


class SecurityRegistry:
    """Registry of security adapters exposed through a tool-agnostic contract.

    Investigators ask for security evidence by layer/domain/category. Concrete
    scanner names remain implementation details of registered adapters.
    """

    _TOOL_NAME = "collect_security_evidence"

    def __init__(self):
        self._providers: dict[str, SecurityProvider] = {}

    def register(self, provider: SecurityProvider) -> "SecurityRegistry":
        self._providers[provider.name] = provider
        return self

    def list(self) -> list[str]:
        return list(self._providers.keys())

    def capabilities(self) -> list[dict[str, Any]]:
        return [
            {
                "source": provider.source,
                "layer": provider.layer.value,
                "domains": [domain.value for domain in provider.domains],
            }
            for provider in self._providers.values()
        ]

    def collect_all(self, query: dict[str, Any] | None = None) -> list[SecurityEvidence]:
        query = query or {}
        evidence: list[SecurityEvidence] = []
        for provider in self._providers.values():
            try:
                evidence.extend(provider.collect(query))
            except Exception as exc:
                logger.warning(f"Security provider '{provider.name}' collection failed: {exc}")

        return self._filter(evidence, query)

    @staticmethod
    def _filter(evidence: list[SecurityEvidence], query: dict[str, Any]) -> list[SecurityEvidence]:
        resource = query.get("resource")
        category = query.get("category")
        severity = str(query.get("severity") or "").upper() or None
        layer = query.get("layer")
        domain = query.get("domain")

        return [
            item
            for item in evidence
            if (not resource or item.resource == resource)
            and (not category or item.category == category)
            and (not severity or str(item.severity or "").upper() == severity)
            and (not layer or item.layer.value == layer)
            and (not domain or item.domain.value == domain)
        ]

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
        return [
            {
                "type": "function",
                "function": {
                    "name": self._TOOL_NAME,
                    "description": (
                        "Collect normalized Kubernetes security evidence by security layer/domain. "
                        "Scanner/tool identity is provenance only; do not assume a specific scanner."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "resource": {"type": ["string", "null"], "description": "Optional resource identifier."},
                            "category": {"type": ["string", "null"], "description": "Optional finding category."},
                            "severity": {"type": ["string", "null"], "description": "Optional severity."},
                            "layer": {"type": ["string", "null"], "enum": [x.value for x in SecurityLayer], "description": "Optional security lifecycle layer."},
                            "domain": {"type": ["string", "null"], "enum": [x.value for x in SecurityDomain], "description": "Optional security domain."},
                        },
                        "required": [],
                    },
                },
            }
        ]

    def health(self) -> dict[str, Any]:
        return {name: provider.health() for name, provider in self._providers.items()}


_DEFAULT_REGISTRY: SecurityRegistry | None = None


def get_security_registry(
    trivy_source: Any | None = None,
    falco_source: Any | None = None,
    kubescape_source: Any | None = None,
) -> SecurityRegistry:
    """Return the default registry lazily initialized with built-in adapters."""
    global _DEFAULT_REGISTRY
    if _DEFAULT_REGISTRY is None:
        from backend.evidence.security.adapters.falco import FalcoAdapter
        from backend.evidence.security.adapters.kubescape import KubescapeAdapter
        from backend.evidence.security.adapters.trivy import TrivyAdapter

        _DEFAULT_REGISTRY = SecurityRegistry()
        _DEFAULT_REGISTRY.register(TrivyAdapter(source=trivy_source))
        _DEFAULT_REGISTRY.register(FalcoAdapter(source=falco_source))
        _DEFAULT_REGISTRY.register(KubescapeAdapter(source=kubescape_source))
    return _DEFAULT_REGISTRY
