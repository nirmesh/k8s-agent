from __future__ import annotations

from typing import Any, Literal

from langgraph.graph import END, START, StateGraph
from langsmith import traceable

from backend.agentic.state import InvestigationState
from backend.ai.diagnosis_synthesizer import ensure_complete_findings_from_incidents, synthesize_incidents, validate_diagnosis
from backend.core.logging import logger
from backend.evidence.security import SecurityEvidenceCollector
from backend.evidence.security.posture import evaluate_cluster_posture
from backend.evidence.security.collector import SecuritySummarizer
from backend.evidence.security.scoring import score_security_posture
from backend.kubernetes.incident_correlator import correlate_incidents
from backend.kubernetes.investigation_engine import collect_operational_evidence, evidence_as_json
from backend.kubernetes.llm_projection import project_incidents_for_llm
from backend.kubernetes.toolkit import K8sToolkit

MAX_EXPANSION_PASSES = 1
DEFAULT_INCIDENT = "Investigate the Kubernetes cluster for current operational incidents."


@traceable(name="k8s.diagnosis.synthesis", run_type="llm")
def _synthesize_with_trace(incidents: list[dict[str, Any]], incident: str) -> dict[str, Any]:
    """Trace model synthesis as a nested LangSmith run."""
    return synthesize_incidents(incidents, incident)


def collect_operational_node(state: InvestigationState) -> dict[str, Any]:
    toolkit = K8sToolkit(context=state.get("context"))
    evidence = collect_operational_evidence(toolkit, limit=100)
    logger.info("LangGraph collected {} operational evidence items", len(evidence))
    return {"operational_evidence": evidence, "expansion_passes": 0}


def normalize_and_correlate_node(state: InvestigationState) -> dict[str, Any]:
    evidence = evidence_as_json(state.get("operational_evidence") or [])
    incidents = correlate_incidents(evidence)
    logger.info("LangGraph correlated {} raw evidence items into {} independent incidents", len(evidence), len(incidents))
    return {"normalized_evidence": evidence, "correlated_incidents": incidents}


def collect_security_node(state: InvestigationState) -> dict[str, Any]:
    toolkit = K8sToolkit(context=state.get("context"))
    collection = SecurityEvidenceCollector(toolkit).collect()
    trivy_evidence = collection.get("evidence") or []
    posture_evidence = evaluate_cluster_posture(toolkit)
    security_evidence = trivy_evidence + posture_evidence

    # Rebuild the deterministic summary from the combined evidence so native
    # Kubernetes posture findings affect workload risk, counts, and score just
    # like Trivy findings. This keeps scanner/provider names out of the product
    # contract while preserving source/layer/domain in normalized evidence.
    collection_summary = collection.get("summary") or {}
    node_result = toolkit.get_resources("node", None)
    posture_api_available = bool(node_result.get("success"))
    available = collection_summary.get("status") == "AVAILABLE" or posture_api_available
    errors = collection_summary.get("reason")
    summary_errors = [errors] if errors else []

    combined_summary = SecuritySummarizer(
        toolkit,
        security_evidence,
        available=available,
        errors=summary_errors,
    ).summarize()
    combined_summary["native_posture_findings"] = [
        {
            "title": e.title,
            "severity": e.severity,
            "category": e.category,
            "resource": e.resource,
            "namespace": e.namespace,
            "source": e.source,
            "layer": e.layer.value if hasattr(e.layer, "value") else str(e.layer),
            "domain": e.domain.value if hasattr(e.domain, "value") else str(e.domain),
            "description": e.description,
            "recommendation": e.recommendation,
            "impact": e.impact,
            "rule_id": getattr(e.payload, "rule_id", None),
        }
        for e in posture_evidence
    ]
    security_summary = score_security_posture(combined_summary)

    logger.info(
        "Security collection: trivy=%s native_posture=%s total=%s",
        len(trivy_evidence),
        len(posture_evidence),
        len(security_evidence),
    )
    return {
        "security_evidence": [e.model_dump(mode="json") for e in security_evidence],
        "security_summary": security_summary,
    }


def diagnose_node(state: InvestigationState) -> dict[str, Any]:
    evidence = evidence_as_json(state.get("operational_evidence") or [])
    incidents = state.get("correlated_incidents") or []
    llm_incidents = project_incidents_for_llm(incidents)
    incident = state.get("incident_description") or DEFAULT_INCIDENT

    # The LLM receives compact semantic incidents, not raw Kubernetes observations.
    synthesis = _synthesize_with_trace(llm_incidents, incident)
    synthesis = validate_diagnosis(synthesis, evidence)
    synthesis = ensure_complete_findings_from_incidents(synthesis, incidents)
    return {"synthesis": synthesis}


def expand_evidence_node(state: InvestigationState) -> dict[str, Any]:
    toolkit = K8sToolkit(context=state.get("context"))
    expanded = collect_operational_evidence(toolkit, limit=250)
    by_id = {str(item.get("id")): item for item in (state.get("operational_evidence") or [])}
    for item in expanded:
        by_id[str(item.get("id"))] = item
    evidence = list(by_id.values())
    incidents = correlate_incidents(evidence)
    return {
        "operational_evidence": evidence,
        "normalized_evidence": evidence,
        "correlated_incidents": incidents,
        "expansion_passes": int(state.get("expansion_passes", 0)) + 1,
    }


def route_after_diagnosis(state: InvestigationState) -> Literal["expand_evidence", "finish"]:
    synthesis = state.get("synthesis") or {}
    if synthesis.get("status") == "NEED_MORE_EVIDENCE" and int(state.get("expansion_passes", 0)) < MAX_EXPANSION_PASSES:
        return "expand_evidence"
    return "finish"


def diagnosis_from_synthesis(result: dict[str, Any], evidence: list[dict[str, Any]]) -> dict[str, Any]:
    findings = result.get("findings") or []
    if not findings:
        return {
            "status": result.get("status", "NO_ISSUE"),
            "root_cause": result.get("summary", "No verified operational issue was found."),
            "explanation": result.get("summary", "No verified operational issue was found."),
            "fix": "No remediation generated during investigation.",
            "kubectl_command": "",
            "prevention": "",
            "confidence": 0.0,
            "affected_resources": [],
            "findings": [],
            "evidence": [],
        }

    roots = [str(f.get("root_cause") or f.get("explanation") or "") for f in findings]
    primary = findings[0]
    explanation = primary.get("explanation") or primary.get("root_cause") or ""
    if len(findings) > 1:
        explanation += " Additional independent findings: " + " | ".join(roots[1:])

    evidence_by_id = {str(item.get("id")): item for item in evidence}
    selected_evidence = [
        evidence_by_id[eid]
        for finding in findings
        for eid in finding.get("evidence_ids", [])
        if eid in evidence_by_id
    ]

    return {
        "status": result.get("status", "DIAGNOSED"),
        "root_cause": roots[0] if len(findings) == 1 else f"{len(findings)} independent incidents detected: " + " | ".join(roots),
        "explanation": explanation,
        "fix": "No remediation generated during investigation.",
        "kubectl_command": "",
        "prevention": "",
        "confidence": max(float(f.get("confidence", 0.0) or 0.0) for f in findings),
        "affected_resources": [resource for finding in findings for resource in (finding.get("affected_resources") or [])],
        "findings": findings,
        "evidence": selected_evidence,
    }


def build_graph():
    builder = StateGraph(InvestigationState)
    builder.add_node("collect_operational", collect_operational_node)
    builder.add_node("normalize_and_correlate", normalize_and_correlate_node)
    builder.add_node("collect_security", collect_security_node)
    builder.add_node("diagnose", diagnose_node)
    builder.add_node("expand_evidence", expand_evidence_node)

    builder.add_edge(START, "collect_operational")
    builder.add_edge("collect_operational", "normalize_and_correlate")
    builder.add_edge("normalize_and_correlate", "collect_security")
    builder.add_edge("collect_security", "diagnose")
    builder.add_conditional_edges(
        "diagnose",
        route_after_diagnosis,
        {"expand_evidence": "expand_evidence", "finish": END},
    )
    builder.add_edge("expand_evidence", "normalize_and_correlate")
    return builder.compile()


graph = build_graph()
