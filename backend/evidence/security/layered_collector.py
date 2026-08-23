from __future__ import annotations

from typing import Any

from backend.evidence.security.additional_sources import collect_additional_sources
from backend.evidence.security.fast_collector import FastSecurityEvidenceCollector


class LayeredSecurityEvidenceCollector(FastSecurityEvidenceCollector):
    """Fast posture collector with optional Kubescape and Falco signals."""

    def collect(self) -> dict[str, Any]:
        result = super().collect()
        source_status = collect_additional_sources(self.toolkit, self._add)

        issues = sorted(
            self.issues.values(),
            key=lambda x: (-x["score"], x["title"]),
        )
        for index, issue in enumerate(issues, 1):
            issue["rank"] = index
            issue["affected_count"] = len(issue["affected_resources"])
            issue["evidence"] = issue.get("proof") or issue.get("evidence", "")

        result["summary"]["priority_issues"] = issues[:25]
        result["summary"]["total_unique_issues"] = len(issues)
        result["summary"]["coverage"] = dict(self.coverage)
        result["summary"]["source_status"] = source_status

        # Explain the posture score in operator language. The score is a bounded
        # prioritization signal, not a probability of compromise.
        severity_counts = {
            "CRITICAL": sum(v for (category, sev), v in self.counts.items() if sev == "CRITICAL"),
            "HIGH": sum(v for (category, sev), v in self.counts.items() if sev == "HIGH"),
            "MEDIUM": sum(v for (category, sev), v in self.counts.items() if sev == "MEDIUM"),
        }
        misconfigs = sum(
            v for (category, _), v in self.counts.items()
            if category in {
                "misconfiguration", "native_misconfiguration", "privileged_container",
                "hostpath_mount", "control_plane", "network_isolation", "identity",
                "kubescape_control",
            }
        )
        runtime = sum(v for (category, _), v in self.counts.items() if category == "runtime_detection")
        scanner = sum(v for (category, _), v in self.counts.items() if category in {"vulnerability", "exposed_secret"})
        breakdown = [
            {"label": "Critical exposure", "points": severity_counts["CRITICAL"] * 10, "detail": f"{severity_counts['CRITICAL']} critical findings × 10"},
            {"label": "High exposure", "points": severity_counts["HIGH"] * 4, "detail": f"{severity_counts['HIGH']} high findings × 4"},
            {"label": "Configuration gaps", "points": misconfigs * 2, "detail": f"{misconfigs} configuration/control failures × 2"},
            {"label": "Runtime signals", "points": runtime * 3, "detail": f"{runtime} Falco runtime alerts × 3"},
            {"label": "Scanner evidence", "points": scanner, "detail": f"{scanner} prioritized scanner findings × 1"},
        ]
        result["summary"]["score_breakdown"] = breakdown
        result["summary"]["score_explanation"] = (
            "The score starts at 100 and is reduced by verified security evidence. "
            "Critical findings carry the largest penalty, configuration gaps are weighted next, "
            "and runtime/scanner signals provide smaller prioritization penalties. "
            "It is deliberately a posture score, not an exploit probability."
        )
        result["diagnostics"]["source_status"] = source_status
        result["diagnostics"]["falco_alerts"] = source_status["falco"]["alerts"]
        result["diagnostics"]["kubescape_failed_controls"] = source_status["kubescape"]["failed_controls"]
        return result


SecurityEvidenceCollector = LayeredSecurityEvidenceCollector
