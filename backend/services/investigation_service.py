from collections.abc import Callable
import json

from backend.ai.remediation_planner import RemediationPlanner
from backend.ai.sre_agent import SREAgent, normalize_diagnosis
from backend.core.logging import logger
from backend.kubernetes.detectors import collect_cluster_signals
from backend.kubernetes.toolkit import K8sToolkit

DEFAULT_INCIDENT = (
    "Investigate the Kubernetes cluster for current incidents, unhealthy resources, "
    "failing workloads, or any other anomalous state. Determine the root cause."
)


def _enrich_affected_with_owners(diagnosis: dict, toolkit: K8sToolkit) -> None:
    """Add controller owner IDs (ReplicaSet, Deployment, etc.) to affected resources."""
    affected = diagnosis.get("affected_resources") or diagnosis.get("affectedResources") or []
    if not isinstance(affected, list):
        return

    extras: set[str] = set()
    for ar in affected:
        if not isinstance(ar, str):
            continue
        parts = ar.split("/")
        if len(parts) != 3:
            continue
        kind, namespace, name = parts
        owner_result = toolkit.get_owner(kind, namespace, name)
        if not owner_result.get("success"):
            continue
        for owner in owner_result.get("data", {}).get("owners", []):
            okind = (owner.get("kind") or "").lower()
            meta = owner.get("metadata") or {}
            oname = meta.get("name") or owner.get("name", "")
            ons = meta.get("namespace") or namespace
            if okind and oname:
                extras.add(f"{okind}/{ons}/{oname}")

    if extras:
        diagnosis["affected_resources"] = list(set(affected) | extras)


def run_investigation(
    progress_callback: Callable[[str], None] | None = None,
    context: str | None = None,
    incident_description: str | None = None,
) -> dict:
    """Run detector -> tool-using investigator -> remediation planner.

    Cluster-wide mode first collects deterministic *signals* (not diagnoses) so the
    LLM has concrete starting points. Targeted mode uses the supplied symptom.
    """
    logger.info("Starting SRE agent investigation")
    toolkit = K8sToolkit(context=context)
    signals = collect_cluster_signals(toolkit)

    if incident_description:
        incident = incident_description
        if signals:
            incident += "\n\nCurrently observed cluster signals (treat as leads, verify with tools):\n" + json.dumps(signals, default=str)
    elif signals:
        incident = (
            "Investigate the following automatically detected Kubernetes anomaly signals. "
            "They are leads, not diagnoses. Verify the relevant resources with tools, follow "
            "relationships, determine the root cause, and ignore unrelated healthy resources.\n\n"
            + json.dumps(signals, default=str)
        )
    else:
        incident = DEFAULT_INCIDENT

    agent = SREAgent(context=context)
    diagnosis = agent.run(
        incident_description=incident,
        progress_callback=progress_callback,
    )

    _enrich_affected_with_owners(diagnosis, toolkit)
    remediation_plan = RemediationPlanner(context=context).plan(diagnosis)

    return {
        "pods": {},
        "logs": {},
        "events": {},
        "deployments": {},
        "network": {"signals": signals},
        "diagnosis": normalize_diagnosis(diagnosis),
        "remediation_plan": remediation_plan,
        "trace": agent.trace,
        "signals": signals,
    }
