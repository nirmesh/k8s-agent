from __future__ import annotations

from typing import Any, TypedDict


class InvestigationState(TypedDict, total=False):
    context: str | None
    incident_description: str
    operational_evidence: list[dict[str, Any]]
    normalized_evidence: list[dict[str, Any]]
    correlated_incidents: list[dict[str, Any]]
    security_evidence: list[dict[str, Any]]
    security_summary: dict[str, Any]
    synthesis: dict[str, Any]
    expansion_passes: int
