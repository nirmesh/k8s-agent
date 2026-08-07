from collections.abc import Callable
import json

from backend.ai.remediation_planner import RemediationPlanner
from backend.ai.sre_agent import SREAgent, normalize_diagnosis
from backend.core.logging import logger
from backend.evidence.security import SecurityEvidenceCollector
from backend.kubernetes.detectors import collect_cluster_signals
from backend.kubernetes.toolkit import K8sToolkit

DEFAULT_INCIDENT = (
    "You are an SRE and Kubernetes Security Engineer. Investigate the cluster for "
    "operational incidents AND security findings. Prioritize by business impact. "
    "Explain WHY a workload is risky and recommend only actionable remediation. "
    "Never list raw CVEs unless explicitly requested."
)


def _security_summary_text(summary: dict) -> str:
    if not summary:
        return ""
    lines = [
        f"Cluster Security Score: {summary.get('cluster_security_score', 0)}/100",
        f"Total vulnerabilities: {summary.get('total_vulnerabilities', 0)}",
        f"Total misconfigurations: {summary.get('total_misconfigurations', 0)}",
        f"Total exposed secrets: {summary.get('total_exposed_secrets', 0)}",
    ]
    top = summary.get("top_10_risks") or []
    if top:
        lines.append("Top risky workloads (name: risk score):")
        for w in top[:10]:
            lines.append(
                f"  - {w['namespace']}/{w['name']}: score {w['risk_score']}, "
                f"critical={w['counts'].get('CRITICAL', 0)}, high={w['counts'].get('HIGH', 0)}, "
                f"internet_facing={w.get('internet_facing', False)}, recommendation={w.get('recommendation', '')}"
            )
    return "\n".join(lines)


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
        # Put controller owners first so the remediation planner targets the
        # workload (Deployment, StatefulSet, etc.) rather than an individual Pod.
        kept = [a for a in affected if a not in extras]
        diagnosis["affected_resources"] = list(extras) + kept


def run_investigation(
    progress_callback: Callable[[str], None] | None = None,
    context: str | None = None,
    incident_description: str | None = None,
) -> dict:
    """Run detector -> security collector -> tool-using investigator -> remediation planner.

    Cluster-wide mode collects deterministic operational signals and normalized security
    evidence from Trivy CRDs. Targeted mode uses the supplied symptom.
    """
    logger.info("Starting SRE agent investigation")
    toolkit = K8sToolkit(context=context)
    signals = collect_cluster_signals(toolkit)

    security_collection = SecurityEvidenceCollector(toolkit).collect()
    security_evidence = security_collection.get("evidence") or []
    security_summary = security_collection.get("summary") or {}
    security_text = _security_summary_text(security_summary)

    base = incident_description or DEFAULT_INCIDENT
    parts = [base]
    if signals:
        parts.append(
            "Currently observed operational signals (treat as leads, verify with tools):\n"
            + json.dumps(signals, default=str)
        )
    if security_text:
        parts.append(
            "Collected security evidence from Trivy Operator CRDs (vulnerability, config audit, exposed secret, SBOM):\n"
            + security_text
        )
    incident = "\n\n".join(parts)

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
        "security_evidence": [e.model_dump(mode="json") for e in security_evidence],
        "security_summary": security_summary,
        "diagnosis": normalize_diagnosis(diagnosis),
        "remediation_plan": remediation_plan,
        "trace": agent.trace,
        "signals": signals,
    }
