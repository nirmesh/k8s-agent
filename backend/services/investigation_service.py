from collections.abc import Callable

from backend.agentic.graph import diagnosis_from_synthesis, graph
from backend.core.logging import logger

DEFAULT_INCIDENT = "Investigate the Kubernetes cluster for current operational incidents."


def run_investigation(
    progress_callback: Callable[[str], None] | None = None,
    context: str | None = None,
    incident_description: str | None = None,
) -> dict:
    """Run the read-only evidence-first investigation through LangGraph."""
    logger.info("Starting LangGraph evidence-driven SRE investigation")

    if progress_callback:
        progress_callback("Checking Pods")

    state = graph.invoke(
        {
            "context": context,
            "incident_description": incident_description or DEFAULT_INCIDENT,
        }
    )

    evidence = state.get("operational_evidence") or []
    synthesis = state.get("synthesis") or {
        "status": "NO_ISSUE",
        "summary": "No verified operational issue was found.",
        "findings": [],
    }

    if progress_callback:
        progress_callback("Analyzing Events")
        progress_callback("Inspecting Deployments")
        progress_callback("Checking Networking")
        progress_callback("AI Reasoning")

    diagnosis = diagnosis_from_synthesis(synthesis, evidence)

    if progress_callback:
        progress_callback("Root Cause Found")

    return {
        "pods": {},
        "logs": {},
        "events": {},
        "deployments": {},
        "network": {"signals": evidence},
        "operational_evidence": evidence,
        "security_evidence": state.get("security_evidence") or [],
        "security_summary": state.get("security_summary") or {},
        "diagnosis": diagnosis,
        "remediation_plan": None,
        "trace": [],
        "signals": evidence,
    }
