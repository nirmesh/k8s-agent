from __future__ import annotations

import math


def score_security_posture(summary: dict) -> dict:
    """Return a bounded, workload-normalized posture score; UNKNOWN is not scored."""
    if summary.get("status") != "AVAILABLE":
        summary["cluster_security_score"] = None
        summary["score_basis"] = "UNKNOWN: security data unavailable"
        return summary
    critical = int(summary.get("critical_vulnerabilities", 0) or 0)
    high = int(summary.get("high_vulnerabilities", 0) or 0)
    medium = int(summary.get("medium_vulnerabilities", 0) or 0)
    low = int(summary.get("low_vulnerabilities", 0) or 0)
    misconfigs = int(summary.get("total_misconfigurations", 0) or 0)
    secrets = int(summary.get("total_exposed_secrets", 0) or 0)
    priority = summary.get("priority_issues") or []
    native_critical = sum(1 for issue in priority if str(issue.get("severity", "")).upper() == "CRITICAL" and issue.get("source") != "trivy-operator")
    native_high = sum(1 for issue in priority if str(issue.get("severity", "")).upper() == "HIGH" and issue.get("source") != "trivy-operator")
    workloads = max(1, int(summary.get("affected_workloads", 0) or 0))
    known_points = (
        critical * 10 + high * 4 + medium + low * 0.25
        + misconfigs * 2 + secrets * 15
        + native_critical * 8 + native_high * 3
    )
    points_per_workload = known_points / workloads
    penalty = min(95.0, 8.0 * math.sqrt(points_per_workload)) if points_per_workload > 0 else 0.0
    summary["cluster_security_score"] = max(5, round(100 - penalty)) if known_points > 0 else 100
    summary["score_basis"] = "Workload-normalized weighted posture score across scanner and native Kubernetes evidence; duplicate findings are aggregated and UNKNOWN findings are excluded."
    summary["scored_vulnerabilities"] = critical + high + medium + low
    summary["unscored_unknown_vulnerabilities"] = int(summary.get("unknown_vulnerabilities", 0) or 0)
    return summary
