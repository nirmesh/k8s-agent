from abc import ABC, abstractmethod
from typing import Any

from backend.evidence.model import Evidence


class EvidenceProvider(ABC):
    """Base interface for all evidence providers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique provider name."""

    @abstractmethod
    def collect(self, query: dict[str, Any] | None = None) -> list[Evidence]:
        """Collect evidence for the optional query and return normalized Evidence objects."""

    @abstractmethod
    def health(self) -> dict[str, Any]:
        """Return provider health metadata."""

    @abstractmethod
    def capabilities(self) -> list[str]:
        """Return a list of capability strings, e.g. ['kubernetes', 'logs']."""

    def tools(self) -> list[dict[str, Any]]:
        """Optional tools exposed to the investigator. Override if the provider exposes tools."""
        return []

    def execute(self, tool: str, **kwargs) -> Evidence:
        """Execute a named investigator tool and return the result as Evidence.

        Raises NotImplementedError for tools not supported by this provider.
        """
        raise NotImplementedError(f"Tool '{tool}' is not supported by provider '{self.name}'")

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name}>"
