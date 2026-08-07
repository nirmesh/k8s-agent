from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from backend.evidence.model import Evidence


class SecurityFinding(BaseModel):
    """Normalized security finding produced by any scanner.

    This is the only shape the AI Investigator ever sees. Scanner-specific JSON is
    translated into this common model by provider adapters.
    """

    category: str = Field(
        description="High-level category: vulnerability, threat, misconfiguration, compliance."
    )
    resource: str = Field(
        description="Resource identifier, e.g. Pod/sre-lab/nginx or image/nginx:1.2.3."
    )
    namespace: str | None = Field(default=None, description="Resource namespace, if namespaced.")
    title: str | None = Field(default=None, description="Short finding title.")
    finding: str = Field(description="Short finding title (legacy alias).")
    description: str = Field(description="Detailed finding description.")
    severity: str = Field(description="Severity label, e.g. CRITICAL, HIGH, MEDIUM, LOW.")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence score.")
    remediation: str | None = Field(default=None, description="Suggested remediation or fix.")
    recommendation: str | None = Field(default=None, description="Actionable recommendation.")
    references: list[str] | None = Field(default=None, description="Reference URLs.")
    rule_id: str | None = Field(default=None, description="Scanner rule/control ID.")
    cve_id: str | None = Field(default=None, description="CVE/CWE identifier when applicable.")
    framework: str | None = Field(default=None, description="Control framework, e.g. NSA, MITRE, CIS.")
    mitre_id: str | None = Field(default=None, description="MITRE ATT&CK technique ID if mapped.")

    class Config:
        arbitrary_types_allowed = True


class SecurityEvidence(Evidence):
    """A single normalized security evidence item from any security provider."""

    type: str = "security"
    namespace: str | None = Field(default=None, description="Resource namespace.")
    category: str | None = Field(default=None, description="Finding category.")
    title: str | None = Field(default=None, description="Short finding title.")
    description: str | None = Field(default=None, description="Detailed description.")
    recommendation: str | None = Field(default=None, description="Actionable recommendation.")
    references: list[str] | None = Field(default=None, description="Reference URLs.")
    payload: SecurityFinding | dict[str, Any] = Field(
        description="Normalized security finding payload or structured artifact (e.g. SBOM)."
    )

    class Config:
        arbitrary_types_allowed = True
