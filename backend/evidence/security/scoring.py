from __future__ import annotations


def score_security_posture(summary: dict) -> dict:
    """Compatibility shim: security severity is explicit, not a composite score.

    Older callers still invoke this function. It now deliberately removes the
    legacy score fields instead of calculating points.
    """
    if summary.get("status") != "AVAILABLE":
        summary["cluster_security_score"] = None
        return summary
    summary["cluster_security_score"] = None
    summary["score_basis"] = "Not used. Findings are classified directly by security severity."
    summary["score_explanation"] = "No composite risk score is calculated. CRITICAL, HIGH, MEDIUM, LOW and UNKNOWN are shown directly."
    summary["score_breakdown"] = []
    return summary
