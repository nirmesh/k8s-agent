from __future__ import annotations

import math
from typing import Any

from backend.evidence.security.additional_sources import collect_additional_sources
from backend.evidence.security.fast_collector import FastSecurityEvidenceCollector


class LayeredSecurityEvidenceCollector(FastSecurityEvidenceCollector):
    """Fast posture collector with optional Kubescape and Falco signals."""

    @staticmethod
    def _priority_ten(issues: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Prefer breadth in the hero list; keep Trivy present but secondary."""
        non_scanner = [i for i in issues if i.get("source") != "trivy-operator"]
        scanner = [i for i in issues if i.get("source") == "trivy-operator"]
        selected = non_scanner[:8]
        selected_ids = {i["id"] for i in selected}
        scanner_selected = 0
        for issue in scanner:
            if scanner_selected >= 2:
                break
            if issue["id"] not in selected_ids:
                selected.append(issue)
                selected_ids.add(issue["id"])
                scanner_selected += 1
        if len(selected) < 10:
            for issue in issues:
                if issue["id"] not in selected_ids:
                    selected.append(issue)
                    selected_ids.add(issue["id"])
                if len(selected) == 10:
                    break
        return selected[:10]

    def collect(self) -> dict[str, Any]:
        result = super().collect()
        source_status = collect_additional_sources(self.toolkit, self._add)

        issues = sorted(self.issues.values(), key=lambda x: (-x["score"], x["title"]))
        for index, issue in enumerate(issues, 1):
            issue["rank"] = index
            issue["affected_count"] = len(issue["affected_resources"])
            issue["evidence"] = issue.get("proof") or issue.get("evidence", "")

        # Score each finding once. Secrets and runtime alerts have their own
        # explicit weights; every other verified issue uses severity weight.
        severity_weight = {"CRITICAL": 10, "HIGH": 4, "MEDIUM": 1, "LOW": 0.25, "UNKNOWN": 0.25}
        critical = sum(1 for i in issues if i.get("severity") == "CRITICAL" and i.get("category") not in {"exposed_secret", "runtime_detection"})
        high = sum(1 for i in issues if i.get("severity") == "HIGH" and i.get("category") not in {"exposed_secret", "runtime_detection"})
        medium = sum(1 for i in issues if i.get("severity") == "MEDIUM" and i.get("category") not in {"exposed_secret", "runtime_detection"})
        low = sum(1 for i in issues if i.get("severity") in {"LOW", "UNKNOWN"} and i.get("category") not in {"exposed_secret", "runtime_detection"})
        secrets = sum(1 for i in issues if i.get("category") == "exposed_secret")
        runtime = sum(1 for i in issues if i.get("category") == "runtime_detection")
        affected_resources = {r for issue in issues for r in issue["affected_resources"]}
        workloads = max(1, len(affected_resources))

        raw_points = critical * severity_weight["CRITICAL"] + high * severity_weight["HIGH"] + medium + low * severity_weight["LOW"] + secrets * 15 + runtime * 3
        points_per_workload = raw_points / workloads
        penalty = min(95.0, 8.0 * math.sqrt(points_per_workload)) if raw_points else 0.0
        score = max(5, round(100 - penalty)) if raw_points else 100
        priority = self._priority_ten(issues)

        result["summary"].update({
            "cluster_security_score": score,
            "score_basis": "Verified posture score: each distinct issue is counted once, weighted by severity, then normalized by affected resources. Secrets and Falco runtime alerts have explicit additional weights. This is a prioritization score, not an exploit probability.",
            "priority_issues": priority,
            "total_unique_issues": len(issues),
            "coverage": dict(self.coverage),
            "source_status": source_status,
            "score_breakdown": [
                {"label": "Critical findings", "points": critical * 10, "detail": f"{critical} × 10"},
                {"label": "High findings", "points": high * 4, "detail": f"{high} × 4"},
                {"label": "Medium / lower findings", "points": medium + low * 0.25, "detail": f"{medium} medium + {low} low/unknown"},
                {"label": "Exposed secrets", "points": secrets * 15, "detail": f"{secrets} × 15"},
                {"label": "Falco runtime alerts", "points": runtime * 3, "detail": f"{runtime} × 3"},
            ],
            "score_explanation": (
                f"The cluster starts at 100. We found {len(issues)} distinct verified issue types affecting "
                f"{workloads} resource(s). The weighted risk is {raw_points:.0f} points before normalization. "
                "Critical findings move the score fastest; repeated copies of the same issue do not create extra cards."
            ),
        })
        result["diagnostics"].update({
            "source_status": source_status,
            "falco_alerts": source_status["falco"]["alerts"],
            "kubescape_failed_controls": source_status["kubescape"]["failed_controls"],
        })
        return result


SecurityEvidenceCollector = LayeredSecurityEvidenceCollector
