from collections.abc import Callable

from backend.agentic.graph import diagnosis_from_synthesis, graph
from backend.core.logging import logger

DEFAULT_INCIDENT = "Investigate the Kubernetes cluster for current operational incidents."


def run_investigation(
    progress_callback: Callable[..., None] | None = None,
    context: str | None = None,
    incident_description: str | None = None,
    security_precomputed: dict | None = None,
) -> dict:
    """Run the read-only evidence-first investigation through LangGraph."""
    logger.info("Starting LangGraph evidence-driven SRE investigation")

    state_input = {
        "context": context,
        "incident_description": incident_description or DEFAULT_INCIDENT,
    }
    if security_precomputed:
        state_input["security_precomputed"] = security_precomputed

    node_steps = {
        "collect_operational": ("Checking Pods", "Collecting live workload and event evidence"),
        "normalize_and_correlate": ("Analyzing Events", "Correlating independent signals into incidents"),
        "collect_security": ("Checking Networking", "Merging verified security evidence"),
        "diagnose": ("AI Reasoning", "LLM is explaining verified evidence"),
        "expand_evidence": ("Reading Logs", "Expanding evidence because more context was requested"),
    }
    next_step = {
        "collect_operational": "Analyzing Events",
        "normalize_and_correlate": "Checking Networking",
        "collect_security": "AI Reasoning",
        "expand_evidence": "Analyzing Events",
        "diagnose": "Root Cause Found",
    }
    step_details = {name: detail for name, detail in node_steps.values()}

    state = dict(state_input)
    if progress_callback:
        progress_callback("Checking Pods", False, "Collecting live workload and event evidence")

    for update in graph.stream(state_input, config={"run_name": "sre_investigation"}):
        if not isinstance(update, dict):
            continue
        for node_name, node_output in update.items():
            if not isinstance(node_output, dict):
                continue
            state.update(node_output)
            step = node_steps.get(node_name)
            if not step or not progress_callback:
                continue
            name, detail = step
            progress_callback(name, True, detail)
            upcoming = next_step.get(node_name)
            if upcoming and upcoming != "Root Cause Found":
                progress_callback(upcoming, False, step_details.get(upcoming, "Working with live cluster evidence"))

    evidence = state.get("operational_evidence") or []
    incidents = state.get("correlated_incidents") or []
    synthesis = state.get("synthesis") or {
        "status": "NO_ISSUE",
        "summary": "No verified operational issue was found.",
        "findings": [],
    }

    diagnosis = diagnosis_from_synthesis(synthesis, evidence)
    if progress_callback:
        progress_callback("Root Cause Found", True, "Diagnosis validated against collected evidence")

    return {
        "pods": {},
        "logs": {},
        "events": {},
        "deployments": {},
        "network": {"signals": evidence},
        "operational_evidence": evidence,
        "correlated_incidents": incidents,
        "security_evidence": state.get("security_evidence") or [],
        "security_summary": state.get("security_summary") or {},
        "diagnosis": diagnosis,
        "remediation_plan": None,
        "trace": [],
        "signals": evidence,
    }
