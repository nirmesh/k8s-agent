from abc import ABC, abstractmethod
from typing import Any

from backend.evidence.security.model import SecurityEvidence


class SecurityProvider(ABC):
    """Base interface for a security scanner adapter.

    Adapters translate scanner-specific output into normalized SecurityEvidence.
    The AI Investigator never sees scanner-specific JSON.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique provider name, e.g. 'trivy', 'falco', 'kubescape'."""

    @abstractmethod
    def collect(self, query: dict[str, Any] | None = None) -> list[SecurityEvidence]:
        """Collect normalized security evidence for the optional query."""

    def health(self) -> dict[str, Any]:
        return {"healthy": True}

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name}>"
