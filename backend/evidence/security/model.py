from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, model_validator

from backend.evidence.model import Evidence


class SecurityLayer(str, Enum):
    """Product-level security layer; intentionally independent of scanner names."""

    POSTURE = "posture"
    ATTACK_SURFACE = "attack_surface"
    SUPPLY_CHAIN = "supply_chain"
    RUNTIME = "runtime"
    COMPLIANCE = "compliance"


class SecurityDomain(str, Enum):
    """Security concern being evaluated."""

    WORKLOAD = "workload"
    CLUSTER = "cluster"
    CONTROL_PLANE = "control_plane"
    IDENTITY = "identity"
    NETWORK = "network"
    SUPPLY_CHAIN = "supply_chain"
    RUNTIME = "runtime"
    COMPLIANCE = "compliance"
    SECRETS = "secrets"


# Registry is product metadata, not execution logic. New scanners/providers can be
# plugged in here without forcing the UI or investigation engine to know their names.
SECURITY_PROVIDER_REGISTRY: dict[str, dict[str, Any]] = {
    "trivy": {
        "layer": SecurityLayer.POSTURE,
        "domains": [SecurityDomain.WORKLOAD, SecurityDomain.SUPPLY_CHAIN, SecurityDomain.SECRETS],
    },
    "kube-bench": {
        "layer": SecurityLayer.COMPLIANCE,
        "domains": [SecurityDomain.CLUSTER, SecurityDomain.CONTROL_PLANE, SecurityDomain.IDENTITY],
    },
    "kube-hunter": {
        "layer": SecurityLayer.ATTACK_SURFACE,
        "domains": [SecurityDomain.CLUSTER, SecurityDomain.NETWORK, SecurityDomain.IDENTITY],
    },
    "syft": {
        "layer": SecurityLayer.SUPPLY_CHAIN,
        "domains": [SecurityDomain.SUPPLY_CHAIN, SecurityDomain.WORKLOAD],
    },
    "grype": {
        "layer": SecurityLayer.SUPPLY_CHAIN,
        "domains": [SecurityDomain.SUPPLY_CHAIN, SecurityDomain.WORKLOAD],
    },
    "falco": {
        "layer": SecurityLayer.RUNTIME,
        "domains": [SecurityDomain.RUNTIME, SecurityDomain.WORKLOAD, SecurityDomain.NETWORK],
    },
    "sonobuoy": {
        "layer": SecurityLayer.COMPLIANCE,
        "domains": [SecurityDomain.COMPLIANCE, SecurityDomain.CLUSTER],
    },
    "kubernetes-native": {
        "layer": SecurityLayer.POSTURE,
        "domains": [
            SecurityDomain.CLUSTER,
            SecurityDomain.CONTROL_PLANE,
            SecurityDomain.IDENTITY,
            SecurityDomain.NETWORK,
            SecurityDomain.SECRETS,
        ],
    },
}


def provider_metadata(source: str | None) -> dict[str, Any]:
    """Return provider metadata without making callers depend on a scanner."""
    return SECURITY_PROVIDER_REGISTRY.get(source or "", {})


def classify_finding(source: str | None, category: str) -> tuple[SecurityLayer, SecurityDomain]:
    """Translate provider/category into the stable product vocabulary."""
    meta = provider_metadata(source)
    layer = meta.get("layer", SecurityLayer.POSTURE)
    domains = meta.get("domains") or [SecurityDomain.WORKLOAD]

    if source == "trivy":
        domain_by_category = {
            "vulnerability": SecurityDomain.WORKLOAD,
            "misconfiguration": SecurityDomain.WORKLOAD,
            "exposed_secret": SecurityDomain.SECRETS,
            "sbom": SecurityDomain.SUPPLY_CHAIN,
        }
        return layer, domain_by_category.get(category, domains[0])

    return layer, domains[0]


class SecurityFinding(BaseModel):
    """Normalized security finding produced by any security provider.

    Provider/tool-specific output is translated into this common contract so the
    investigation and UI reason about layers/domains rather than scanner names.
    """

    category: str = Field(description="Finding category, e.g. vulnerability, threat, misconfiguration.")
    layer: SecurityLayer = Field(default=SecurityLayer.POSTURE, description="Security lifecycle layer.")
    domain: SecurityDomain = Field(default=SecurityDomain.WORKLOAD, description="Security concern domain.")
    source: str | None = Field(default=None, description="Provider/tool identifier for provenance.")
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

    @model_validator(mode="after")
    def derive_classification(self) -> "SecurityFinding":
        # If an adapter provides a source, classification is authoritative.
        # Otherwise preserve explicitly supplied layer/domain values.
        if self.source:
            self.layer, self.domain = classify_finding(self.source, self.category)
        return self

    class Config:
        arbitrary_types_allowed = True


class SecurityEvidence(Evidence):
    """A single normalized security evidence item from any security provider."""

    type: str = "security"
    layer: SecurityLayer = Field(default=SecurityLayer.POSTURE, description="Security lifecycle layer.")
    domain: SecurityDomain = Field(default=SecurityDomain.WORKLOAD, description="Security concern domain.")
    source: str | None = Field(default=None, description="Provider/tool identifier for provenance.")
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

    @model_validator(mode="after")
    def sync_from_payload(self) -> "SecurityEvidence":
        if isinstance(self.payload, SecurityFinding):
            self.source = self.source or self.payload.source
            self.layer = self.payload.layer
            self.domain = self.payload.domain
            self.category = self.category or self.payload.category
            self.impact = self.impact or self.payload.impact
        elif self.source and self.category:
            self.layer, self.domain = classify_finding(self.source, self.category)
        return self

    class Config:
        arbitrary_types_allowed = True
