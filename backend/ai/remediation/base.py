from __future__ import annotations

import dataclasses
from abc import ABC, abstractmethod
from typing import Any


@dataclasses.dataclass
class Remediation:
    """Rule-based remediation proposal returned by a Remediator."""

    root_cause: str
    confidence: float
    risk: str
    remediation_type: str
    tool: str | None
    arguments: dict[str, Any]
    target: dict[str, str]
    changes: list[dict[str, Any]]
    reason: str
    verification: dict[str, str]
    rollback: dict[str, Any]
    kubectl_commands: list[str]
    verification_steps: list[str]
    rollback_steps: list[str]
    question: str | None = None
    summary: str | None = None


class Remediator(ABC):
    """Abstract base class for a pluggable, symptom-specific remediator."""

    @abstractmethod
    def propose(
        self,
        diagnosis: dict[str, Any],
        resource: dict[str, str],
        manifest: dict[str, Any],
        toolkit: Any,
    ) -> Remediation | None:
        """Return a Remediation proposal, or None if this remediator cannot handle the case."""
        ...
