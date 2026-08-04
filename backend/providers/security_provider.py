from __future__ import annotations

from typing import Any

from backend.evidence.security import get_security_registry
from backend.evidence.security.registry import SecurityRegistry
from backend.providers.base import EvidenceProvider


class SecurityEvidenceProvider(EvidenceProvider):
    """Provider bridge that exposes the Security Registry to the investigator.

    The investigator calls generic `collect_security_evidence` and receives
    normalized SecurityEvidence without knowing which scanner produced it.
    """

    def __init__(self, registry: SecurityRegistry | None = None):
        self._registry = registry or get_security_registry()

    @property
    def name(self) -> str:
        return "security"

    def health(self) -> dict[str, Any]:
        return {"healthy": True, "providers": self._registry.health()}

    def capabilities(self) -> list[str]:
        return ["security"]

    def tools(self) -> list[dict[str, Any]]:
        return self._registry.tools()

    def execute(self, tool: str, **kwargs) -> Any:
        return self._registry.execute(tool, **kwargs)

    def collect(self, query: dict[str, Any] | None = None) -> list[Any]:
        return self._registry.collect_all(query)
