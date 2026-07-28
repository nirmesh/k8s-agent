from collections.abc import Callable

from backend.ai.remediation_planner import RemediationPlanner
from backend.ai.sre_agent import SREAgent, normalize_diagnosis
from backend.core.logging import logger

DEFAULT_INCIDENT = (
    "Investigate the Kubernetes cluster for current incidents, unhealthy resources, "
    "failing workloads, or any other anomalous state. Determine the root cause."
)


def run_investigation(
    progress_callback: Callable[[str], None] | None = None,
    context: str | None = None,
) -> dict:
    """Run the tool-using SRE agent and return a structured diagnosis."""
    logger.info("Starting SRE agent investigation")
    agent = SREAgent(context=context)
    diagnosis = agent.run(
        incident_description=DEFAULT_INCIDENT,
        progress_callback=progress_callback,
    )

    remediation_plan = RemediationPlanner(context=context).plan(diagnosis)

    return {
        "pods": {},
        "logs": {},
        "events": {},
        "deployments": {},
        "network": {},
        "diagnosis": normalize_diagnosis(diagnosis),
        "remediation_plan": remediation_plan,
        "trace": agent.trace,
    }
