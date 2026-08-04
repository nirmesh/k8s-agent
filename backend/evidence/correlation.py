from __future__ import annotations

from collections import Counter
from typing import Any

from backend.evidence.graph import EvidenceGraph
from backend.evidence.model import Evidence


class CorrelationEngine:
    """Correlate heterogeneous evidence into a concise risk assessment.

    Inputs may come from any provider (Kubernetes, Trivy, Falco, Kubescape).
    The output is a normalized risk signal with an evidence trail.
    No internal chain of thought is exposed.
    """

    def __init__(self, graph: EvidenceGraph | None = None):
        self._graph = graph or EvidenceGraph()

    def add(self, evidence: Evidence | list[Evidence]) -> "CorrelationEngine":
        self._graph.add(evidence)
        return self

    def correlate(
        self, seed_resource: str | None = None, max_hops: int = 1
    ) -> dict[str, Any]:
        evidence = (
            self._graph.related(seed_resource, max_hops=max_hops)
            if seed_resource
            else self._graph.nodes
        )
        if not evidence:
            return {
                "confidence": 0.0,
                "blast_radius": 0,
                "risk": "LOW",
                "recommendation": "No evidence to correlate.",
                "evidence_trail": [],
            }

        resources: set[str] = set()
        providers: set[str] = set()
        categories: Counter[str] = Counter()
        severities: Counter[str] = Counter()

        for item in evidence:
            resources.add(item.resource)
            providers.add(item.provider)
            payload = item.payload
            category = self._payload_attr(payload, "category")
            severity = self._payload_attr(payload, "severity")
            if category:
                categories[category] += 1
            if severity:
                severities[str(severity).upper()] += 1
            else:
                severities["UNKNOWN"] += 1

        blast_radius = len(resources)
        confidence = round(min(0.3 + 0.2 * len(providers), 1.0), 2)
        risk = self._risk(severities)
        recommendation = self._recommendation(risk, categories, resources)
        evidence_trail = self._trail(evidence)

        return {
            "confidence": confidence,
            "blast_radius": blast_radius,
            "risk": risk,
            "recommendation": recommendation,
            "evidence_trail": evidence_trail,
        }

    @staticmethod
    def _payload_attr(payload: Any, attr: str) -> Any:
        if isinstance(payload, dict):
            return payload.get(attr)
        return getattr(payload, attr, None)

    def _risk(self, severities: Counter[str]) -> str:
        if severities["CRITICAL"] > 1:
            return "CRITICAL"
        if severities["CRITICAL"] == 1:
            return "HIGH"
        if severities["HIGH"] >= 2:
            return "HIGH"
        if severities["HIGH"] == 1:
            return "MEDIUM"
        return "LOW"

    def _recommendation(
        self, risk: str, categories: Counter[str], resources: set[str]
    ) -> str:
        if not categories:
            return "No actionable findings."
        top_categories = ", ".join(f"{c}({n})" for c, n in categories.most_common(3))
        top_resources = ", ".join(list(resources)[:3])
        rec = f"Investigate {top_resources}. Priority: {top_categories}."
        if severities := {"CRITICAL", "HIGH"}:
            pass
        if risk == "CRITICAL":
            return f"CRITICAL: {rec}"
        return rec

    def _trail(self, evidence: list[Evidence]) -> list[dict[str, Any]]:
        trail: list[dict[str, Any]] = []
        for item in evidence:
            payload = item.payload
            finding = self._payload_attr(payload, "finding") or self._payload_attr(
                payload, "description"
            )
            trail.append(
                {
                    "provider": item.provider,
                    "resource": item.resource,
                    "type": item.type,
                    "severity": self._payload_attr(payload, "severity"),
                    "category": self._payload_attr(payload, "category"),
                    "finding": finding,
                }
            )
        return trail
