import json
from typing import Any

from backend.core.logging import logger


def _flatten_text(value: Any) -> str:
    """Recursively flatten a nested structure into a searchable string."""
    if isinstance(value, dict):
        return " ".join(_flatten_text(v) for v in value.values())
    if isinstance(value, list):
        return " ".join(_flatten_text(v) for v in value)
    return str(value).lower()


def _heuristic_root_cause(investigation: dict) -> str:
    """Fallback heuristic when the LLM does not return a root cause."""
    text = _flatten_text(investigation)

    if "database_url" in text or "missing env" in text:
        return "Missing or incorrect environment variable (likely DATABASE_URL)"
    if "imagepullbackoff" in text or "errimagepull" in text:
        return "Container image cannot be pulled"
    if "crashloopbackoff" in text:
        return "Container is crashing on startup"
    if "oomkilled" in text:
        return "Container terminated due to out-of-memory"
    if "failedscheduling" in text:
        return "Pod could not be scheduled"
    if "missing_endpoints" in text:
        return "Service has no matching endpoints"

    return "Could not determine root cause from available evidence"


def extract_root_cause(llm_output: dict, investigation: dict) -> str:
    """Extract the root cause from LLM output or fall back to heuristics."""
    root_cause = llm_output.get("root_cause")
    if root_cause:
        return str(root_cause)

    logger.warning("LLM did not return root_cause, using heuristic fallback")
    return _heuristic_root_cause(investigation)
