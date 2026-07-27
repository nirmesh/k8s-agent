from collections.abc import Callable

from backend.ai.reasoning import analyze
from backend.core.logging import logger
from backend.kubernetes.deployment_inspector import inspect_deployments
from backend.kubernetes.events_analyzer import analyze_events
from backend.kubernetes.logs_collector import collect_logs
from backend.kubernetes.network_inspector import inspect_network
from backend.kubernetes.pod_inspector import inspect_pods


def run_investigation(progress_callback: Callable[[str], None] | None = None) -> dict:
    """Orchestrate the Kubernetes investigation layers."""
    logger.info("Starting Kubernetes investigation")

    if progress_callback:
        progress_callback("Checking Pods")
    pods = inspect_pods()

    if progress_callback:
        progress_callback("Reading Logs")
    logs = collect_logs(pods.get("problematic_pods", []))

    if progress_callback:
        progress_callback("Analyzing Events")
    events = analyze_events()

    if progress_callback:
        progress_callback("Inspecting Deployments")
    deployments = inspect_deployments()

    if progress_callback:
        progress_callback("Checking Networking")
    network = inspect_network()

    investigation = {
        "pods": pods,
        "logs": logs,
        "events": events,
        "deployments": deployments,
        "network": network,
    }

    if progress_callback:
        progress_callback("AI Reasoning")
    diagnosis = analyze(investigation)

    if progress_callback:
        progress_callback("Root Cause Found")

    investigation["diagnosis"] = diagnosis
    return investigation
