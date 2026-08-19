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


# Product metadata: scanners are implementation details; layers/domains are the
# stable contract consumed by the investigation engine and UI.
SECURITY_PROVIDER_REGISTRY: dict[str, dict[str, Any]] = {
    "trivy": {"layer": SecurityLayer.POSTURE, "domains": [SecurityDomain.WORKLOAD, SecurityDomain.SUPPLY_CHAIN, SecurityDomain.SECRETS]},
    "kube-bench": {"layer": SecurityLayer.COMPLIANCE, "domains": [SecurityDomain.CLUSTER, SecurityDomain.CONTROL_PLANE, SecurityDomain.IDENTITY]},
    "kube-hunter": {"layer": SecurityLayer.ATTACK_SURFACE, "domains": [SecurityDomain.CLUSTER, SecurityDomain.NETWORK, SecurityDomain.IDENTITY]},
    "syft": {"layer": SecurityLayer.SUPPLY_CHAIN, "domains": [SecurityDomain.SUPPLY_CHAIN, SecurityDomain.WORKLOAD]},
    "grype": {"layer": SecurityLayer.SUPPLY_CHAIN, "domains": [SecurityDomain.SUPPLY_CHAIN, SecurityDomain.WORKLOAD]},
    "falco": {"layer": SecurityLayer.RUNTIME, "domains": [SecurityDomain.RUNTIME, SecurityDomain.WORKLOAD, SecurityDomain.NETWORK]},
    "sonobuoy": {"layer": SecurityLayer.COMPLIANCE, "domains": [SecurityDomain.COMPLIANCE, SecurityDomain.CLUSTER]},
    "kubernetes-native": {"layer": SecurityLayer.POSTURE, "domains": [SecurityDomain.CLUSTER, SecurityDomain.CONTROL_PLANE, SecurityDomain.IDENTITY, SecurityDomain.NETWORK, SecurityDomain.SECRETS]},
}


def canonical_source(provider: str | None) -> str | None:
    """Map provider implementation names to the stable product source name."""
    if not provider:
        return None
    value = provider.lower()
    if value.startswith("trivy"):
        return "trivy"
    if value.startswith("kube-bench"):
        return "kube-bench"
    if value.startswith("kube-hunter"):
        return "kube-hunter"
    if value.startswith("sonobuoy"):
        return "sonobuoy"
    if value.startswith("falco"):
        return "falco"
    if value.startswith("syft"):
        return "syft"
    if value.startswith("grype"):
        return "grype"
    if value.startswith("kubernetes"):
        return "kubernetes-native"
    return value


def provider_metadata(source: str | None) -> dict[str, Any]:
    return SECURITY_PROVIDER_REGISTRY.get(canonical_source(source) or "", {})


def classify_finding(source: str | None, category: str) -> tuple[SecurityLayer, SecurityDomain]:
    """Translate provider/category into stable product vocabulary."""
    source = canonical_source(source)
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
    """Normalized security finding produced by any security provider."""

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
        if self.source:
            self.source = canonical_source(self.source)
            self.layer, self.domain = classify_finding(self.source, self.category)
        return self

    class Config:
        arbitrary_types_allowed = True


class SecurityEvidence(Evidence):
    """A single normalized security evidence item from any security provider."""

    type: str = "security"
    layer: SecurityLayer = Field(default=SecurityLayer.POSTURE, description="Security lifecycle layer.")
    domain: SecurityDomain = Field(default=SecurityDomain.WORKLOAD, description="Security concern domain.")
    source: str | None = Field(default=None, description="Stable provider/tool identifier for provenance.")
    namespace: str | None = Field(default=None, description="Resource namespace.")
    category: str | None = Field(default=None, description="Finding category.")
    title: str | None = Field(default=None, description="Short finding title.")
    description: str | None = Field(default=None, description="Detailed description.")
    recommendation: str | None = Field(default=None, description="Actionable recommendation.")
    impact: str | None = Field(default=None, description="Why this finding matters to the environment.")
    references: list[str] | None = Field(default=None, description="Reference URLs.")
    payload: SecurityFinding | dict[str, Any] = Field(description="Normalized finding payload or structured artifact.")

    @model_validator(mode="after")
    def sync_from_payload(self) -> "SecurityEvidence":
        source = canonical_source(self.source or self.provider)
        self.source = source
        if isinstance(self.payload, SecurityFinding):
            self.source = self.payload.source or source
            self.layer, self.domain = classify_finding(self.source, self.payload.category)
            self.category = self.category or self.payload.category
            self.impact = self.impact or self.payload.impact
        elif self.category:
            self.layer, self.domain = classify_finding(self.source, self.category)
        return self

    class Config:
        arbitrary_types_allowed = True
