from abc import ABC, abstractmethod
from typing import Any

from backend.evidence.security.model import SecurityDomain, SecurityLayer, SecurityEvidence, provider_metadata, canonical_source


class SecurityProvider(ABC):
    """Base interface for a security scanner adapter.

    Adapters translate scanner-specific output into normalized SecurityEvidence.
    The AI Investigator depends on this interface plus security layer/domain,
    not on scanner-specific output.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique provider name used for provenance, e.g. 'trivy' or 'falco'."""

    @property
    def source(self) -> str:
        """Stable product source name, normalized from the adapter name."""
        return canonical_source(self.name) or self.name

    @property
    def layer(self) -> SecurityLayer:
        """Security lifecycle layer represented by this provider."""
        return provider_metadata(self.source).get("layer", SecurityLayer.POSTURE)

    @property
    def domains(self) -> tuple[SecurityDomain, ...]:
        """Security domains represented by this provider."""
        return tuple(provider_metadata(self.source).get("domains", [SecurityDomain.WORKLOAD]))

    @abstractmethod
    def collect(self, query: dict[str, Any] | None = None) -> list[SecurityEvidence]:
        """Collect normalized security evidence for the optional query."""

    def health(self) -> dict[str, Any]:
        return {"healthy": True, "source": self.source, "layer": self.layer.value, "domains": [d.value for d in self.domains]}

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name} source={self.source} layer={self.layer.value}>"
