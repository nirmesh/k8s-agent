from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from backend.evidence.model import Evidence


class SecurityLayer(str, Enum):
    """Where a security signal sits in the security lifecycle."""

    POSTURE = "posture"
    ATTACK_SURFACE = "attack_surface"
    SUPPLY_CHAIN = "supply_chain"
    RUNTIME = "runtime"
    COMPLIANCE = "compliance"


class SecurityDomain(str, Enum):
    """What security concern a finding describes."""

    WORKLOAD = "workload"
    CLUSTER = "cluster"
    CONTROL_PLANE = "control_plane"
    IDENTITY = "identity"
    NETWORK = "network"
    SUPPLY_CHAIN = "supply_chain"
    RUNTIME = "runtime"
    COMPLIANCE = "compliance"
    SECRETS = "secrets"


class SecurityFinding(BaseModel):
    """Normalized security finding produced by any security provider.

    Provider/tool-specific output is translated into this common contract so the
    investigation and UI can reason about security by layer and domain rather
    than by scanner name.
    """

    category: str = Field(description="Finding category, e.g. vulnerability, threat, misconfiguration.")
    layer: SecurityLayer = Field(default=SecurityLayer.POSTURE, description="Security lifecycle layer.")
    domain: SecurityDomain = Field(default=SecurityDomain.WORKLOAD, description="Security concern domain.")
    source: str | None = Field(default=None, description="Optional provider/tool identifier for provenance.")
    resource: str = Field(description="Resource identifier, e.g. Pod/sre-lab/nginx or image/nginx:1.2.3.")
    namespace: str | None = Field(default=None, description="Resource namespace, if namespaced.")
    title: str | None = Field(default=None, description="Short finding title.")
    finding: str = Field(description="Short finding title (legacy alias).")
    description: str = Field(description="Detailed finding description.")
    severity: str = Field(description="Severity label, e.g. CRITICAL, HIGH, MEDIUM, LOW.")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence score.")
    remediation: str | None = Field(default=None, description="Suggested remediation or fix.")
    recommendation: str | None = Field(default=None, description="Actionable recommendation.")
    impact: str | None = Field(default=None, description="Why this finding matters to the environment.")
    references: list[str] | None = Field(default=None, description="Reference URLs.")
    rule_id: str | None = Field(default=None, description="Scanner rule/control ID.")
    cve_id: str | None = Field(default=None, description="CVE/CWE identifier when applicable.")
    framework: str | None = Field(default=None, description="Control framework, e.g. CIS, NSA, MITRE.")
    mitre_id: str | None = Field(default=None, description="MITRE ATT&CK technique ID if mapped.")

    class Config:
        arbitrary_types_allowed = True


class SecurityEvidence(Evidence):
    """A single normalized security evidence item from any security provider."""

    type: str = "security"
    layer: SecurityLayer = Field(default=SecurityLayer.POSTURE, description="Security lifecycle layer.")
    domain: SecurityDomain = Field(default=SecurityDomain.WORKLOAD, description="Security concern domain.")
    source: str | None = Field(default=None, description="Optional provider/tool identifier for provenance.")
    namespace: str | None = Field(default=None, description="Resource namespace.")
    category: str | None = Field(default=None, description="Finding category.")
    title: str | None = Field(default=None, description="Short finding title.")
    description: str | None = Field(default=None, description="Detailed description.")
    recommendation: str | None = Field(default=None, description="Actionable recommendation.")
    impact: str | None = Field(default=None, description="Why this finding matters to the environment.")
    references: list[str] | None = Field(default=None, description="Reference URLs.")
    payload: SecurityFinding | dict[str, Any] = Field(
        description="Normalized security finding payload or structured artifact (e.g. SBOM)."
    )

    class Config:
        arbitrary_types_allowed = True
