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
    workloads = max(1, int(summary.get("affected_workloads", 0) or 0))
    known_points = critical * 10 + high * 4 + medium + low * 0.25 + misconfigs * 2 + secrets * 15
    points_per_workload = known_points / workloads
    penalty = min(95.0, 8.0 * math.sqrt(points_per_workload)) if points_per_workload > 0 else 0.0
    summary["cluster_security_score"] = max(5, round(100 - penalty)) if known_points > 0 else 100
    summary["score_basis"] = "Workload-normalized weighted posture score; UNKNOWN findings excluded. CRITICAL=10, HIGH=4, MEDIUM=1, LOW=0.25, misconfiguration=2, exposed secret=15, with diminishing returns and a 5/100 floor when known risk exists."
    summary["scored_vulnerabilities"] = critical + high + medium + low
    summary["unscored_unknown_vulnerabilities"] = int(summary.get("unknown_vulnerabilities", 0) or 0)
    return summary
