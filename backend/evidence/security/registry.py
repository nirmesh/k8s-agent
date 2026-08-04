from __future__ import annotations

import json
from typing import Any

from backend.core.logging import logger
from backend.evidence.model import Evidence
from backend.evidence.security.model import SecurityEvidence
from backend.evidence.security.provider import SecurityProvider


class SecurityRegistry:
    """Registry of security scanner adapters.

    Investigators ask this registry for SecurityEvidence. The registry dispatches
    to the registered scanners and normalizes their output. Future scanners plug
    in here without changing investigation logic.
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
                evidence.extend(provider.collect(query))
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
        return [
            {
                "type": "function",
                "function": {
                    "name": self._TOOL_NAME,
                    "description": (
                        "Collect normalized security evidence from all registered security scanners. "
                        "Optionally filter by resource, category, or severity. "
                        "The investigator must not assume which scanner produced the evidence."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "resource": {
                                "type": ["string", "null"],
                                "description": "Optional resource identifier to scope findings.",
                            },
                            "category": {
                                "type": ["string", "null"],
                                "description": "Optional category filter: vulnerability, threat, misconfiguration, compliance.",
                            },
                            "severity": {
                                "type": ["string", "null"],
                                "description": "Optional severity filter: CRITICAL, HIGH, MEDIUM, LOW.",
                            },
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
    """Return a default SecurityRegistry lazily initialized with built-in adapters."""
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
