from __future__ import annotations

import math
from typing import Any

from backend.evidence.security.additional_sources import collect_additional_sources
from backend.evidence.security.fast_collector import FastSecurityEvidenceCollector


class LayeredSecurityEvidenceCollector(FastSecurityEvidenceCollector):
    """Fast posture collector with optional Kubescape and Falco signals."""

    def collect(self) -> dict[str, Any]:
        result = super().collect()
        source_status = collect_additional_sources(self.toolkit, self._add)

        issues = sorted(self.issues.values(), key=lambda x: (-x["score"], x["title"]))
        for index, issue in enumerate(issues, 1):
            issue["rank"] = index
            issue["affected_count"] = len(issue["affected_resources"])
            issue["evidence"] = issue.get("proof") or issue.get("evidence", "")

        severity_counts = {
            sev: sum(v for (_, item_sev), v in self.counts.items() if item_sev == sev)
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
        }
        misconfigs = sum(
            v for (category, _), v in self.counts.items()
            if category in {
                "misconfiguration", "native_misconfiguration", "privileged_container",
                "hostpath_mount", "control_plane", "network_isolation", "identity",
                "kubescape_control",
            }
        )
        secrets = sum(v for (category, _), v in self.counts.items() if category == "exposed_secret")
        runtime = sum(v for (category, _), v in self.counts.items() if category == "runtime_detection")
        affected_resources = {r for issue in issues for r in issue["affected_resources"]}
        workloads = max(1, len(affected_resources))

        # One deterministic formula. The UI exposes the same components so the
        # operator can see exactly why the score moved.
        raw_points = (
            severity_counts["CRITICAL"] * 10
            + severity_counts["HIGH"] * 4
            + severity_counts["MEDIUM"]
            + severity_counts["LOW"] * 0.25
            + misconfigs * 2
            + secrets * 15
            + runtime * 3
        )
        points_per_workload = raw_points / workloads
        penalty = min(95.0, 8.0 * math.sqrt(points_per_workload)) if raw_points else 0.0
        score = max(5, round(100 - penalty)) if raw_points else 100

        result["summary"].update({
            "cluster_security_score": score,
            "score_basis": "Verified posture score: weighted security evidence normalized by affected resources. It is a prioritization score, not an exploit probability.",
            "priority_issues": issues[:25],
            "total_unique_issues": len(issues),
            "coverage": dict(self.coverage),
            "source_status": source_status,
            "score_breakdown": [
                {"label": "Critical findings", "points": severity_counts["CRITICAL"] * 10, "detail": f"{severity_counts['CRITICAL']} × 10"},
                {"label": "High findings", "points": severity_counts["HIGH"] * 4, "detail": f"{severity_counts['HIGH']} × 4"},
                {"label": "Configuration gaps", "points": misconfigs * 2, "detail": f"{misconfigs} × 2"},
                {"label": "Exposed secrets", "points": secrets * 15, "detail": f"{secrets} × 15"},
                {"label": "Falco runtime alerts", "points": runtime * 3, "detail": f"{runtime} × 3"},
            ],
            "score_explanation": (
                f"The cluster starts at 100. Verified risk contributes {raw_points:.0f} weighted points "
                f"across {workloads} affected resource(s); the normalization prevents a large cluster from "
                "being punished simply for having more workloads. Critical findings weigh most, then high "
                "findings, configuration gaps, secrets, and runtime alerts."
            ),
        })
        result["diagnostics"].update({
            "source_status": source_status,
            "falco_alerts": source_status["falco"]["alerts"],
            "kubescape_failed_controls": source_status["kubescape"]["failed_controls"],
        })
        return result


SecurityEvidenceCollector = LayeredSecurityEvidenceCollector
