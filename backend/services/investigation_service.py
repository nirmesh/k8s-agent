from collections.abc import Callable

from backend.ai.diagnosis_synthesizer import synthesize, validate_diagnosis
from backend.core.logging import logger
from backend.evidence.security import SecurityEvidenceCollector
from backend.kubernetes.investigation_engine import collect_operational_evidence, evidence_as_json
from backend.kubernetes.toolkit import K8sToolkit

DEFAULT_INCIDENT = "Investigate the Kubernetes cluster for current operational incidents."


def _diagnosis_from_synthesis(result: dict, evidence: list[dict]) -> dict:
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

    primary = findings[0]
    extra = findings[1:]
    explanation = primary.get("explanation") or primary.get("root_cause") or ""
    if extra:
        explanation += " Additional independent findings: " + " ".join(
            str(f.get("root_cause") or f.get("explanation") or "") for f in extra[:4]
        )
    evidence_by_id = {str(item.get("id")): item for item in evidence}
    selected_evidence = [evidence_by_id[eid] for eid in primary.get("evidence_ids", []) if eid in evidence_by_id]
    return {
        "status": result.get("status", "DIAGNOSED"),
        "root_cause": primary.get("root_cause") or result.get("summary", ""),
        "explanation": explanation,
        "fix": "No remediation generated during investigation.",
        "kubectl_command": "",
        "prevention": "",
        "confidence": float(primary.get("confidence", 0.0) or 0.0),
        "affected_resources": primary.get("affected_resources") or [],
        "findings": findings,
        "evidence": selected_evidence,
    }


def run_investigation(
    progress_callback: Callable[[str], None] | None = None,
    context: str | None = None,
    incident_description: str | None = None,
) -> dict:
    """Read-only evidence-first investigation; remediation is a separate phase."""
    logger.info("Starting evidence-driven SRE investigation")
    toolkit = K8sToolkit(context=context)

    if progress_callback:
        progress_callback("Checking Pods")
    operational_evidence = collect_operational_evidence(toolkit)

    if progress_callback:
        progress_callback("Analyzing Events")
        progress_callback("Inspecting Deployments")
        progress_callback("Checking Networking")

    security_collection = SecurityEvidenceCollector(toolkit).collect()
    security_evidence = security_collection.get("evidence") or []
    security_summary = security_collection.get("summary") or {}

    if progress_callback:
        progress_callback("AI Reasoning")

    verified = evidence_as_json(operational_evidence)
    synthesis = synthesize(verified, incident_description or DEFAULT_INCIDENT)
    synthesis = validate_diagnosis(synthesis, verified)
    diagnosis = _diagnosis_from_synthesis(synthesis, verified)

    if progress_callback:
        progress_callback("Root Cause Found")

    return {
        "pods": {},
        "logs": {},
        "events": {},
        "deployments": {},
        "network": {"signals": operational_evidence},
        "operational_evidence": operational_evidence,
        "security_evidence": [e.model_dump(mode="json") for e in security_evidence],
        "security_summary": security_summary,
        "diagnosis": diagnosis,
        "remediation_plan": None,
        "trace": [],
        "signals": operational_evidence,
    }
