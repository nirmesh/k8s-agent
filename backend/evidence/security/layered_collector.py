from __future__ import annotations

from typing import Any

from backend.evidence.security.additional_sources import collect_additional_sources
from backend.evidence.security.fast_collector import FastSecurityEvidenceCollector


class LayeredSecurityEvidenceCollector(FastSecurityEvidenceCollector):
    """Collect native Kubernetes, Trivy, Kubescape and Falco evidence.

    Severity is intentionally explainable: CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN.
    There is no composite points score in the security summary.
    """

    @staticmethod
    def _priority_ten(issues: list[dict[str, Any]]) -> list[dict[str, Any]]:
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        ordered = sorted(issues, key=lambda i: (order.get(str(i.get("severity", "UNKNOWN")).upper(), 4), i.get("title", "")))
        non_scanner = [i for i in ordered if i.get("source") != "trivy-operator"]
        scanner = [i for i in ordered if i.get("source") == "trivy-operator"]
        selected = non_scanner[:8]
        selected_ids = {i["id"] for i in selected}
        for issue in scanner:
            if len(selected) >= 10:
                break
            if issue["id"] not in selected_ids:
                selected.append(issue)
                selected_ids.add(issue["id"])
        for issue in ordered:
            if len(selected) >= 10:
                break
            if issue["id"] not in selected_ids:
                selected.append(issue)
                selected_ids.add(issue["id"])
        return selected[:10]

    def _trivy_status(self) -> dict[str, Any]:
        result = self.toolkit.get_custom_resources("aquasecurity.github.io", None, "vulnerabilityreports")
        if not result.get("success"):
            return {"installed": False, "reports": 0, "findings": 0}
        reports = (result.get("data") or {}).get("items") or []
        return {"installed": True, "reports": len(reports), "findings": 0}

    def collect(self) -> dict[str, Any]:
        self._scan_native()
        source_status = collect_additional_sources(self.toolkit, self._add)

        # Trivy is a first-class provider now, not a fallback hidden behind the UI.
        trivy_status = self._trivy_status()
        self._scan_trivy()
        trivy_status["findings"] = sum(1 for i in self.issues.values() if i.get("source") == "trivy-operator")
        source_status["trivy"] = trivy_status

        issues = list(self.issues.values())
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        issues.sort(key=lambda x: (severity_order.get(str(x.get("severity", "UNKNOWN")).upper(), 4), x.get("title", "")))
        for index, issue in enumerate(issues, 1):
            issue["rank"] = index
            issue["affected_count"] = len(issue["affected_resources"])
            issue["evidence"] = issue.get("proof") or issue.get("evidence", "")

        critical = sum(1 for i in issues if i.get("severity") == "CRITICAL")
        high = sum(1 for i in issues if i.get("severity") == "HIGH")
        medium = sum(1 for i in issues if i.get("severity") == "MEDIUM")
        low = sum(1 for i in issues if i.get("severity") in {"LOW", "UNKNOWN"})
        secrets = sum(1 for i in issues if i.get("category") == "exposed_secret")
        affected_resources = {r for issue in issues for r in issue["affected_resources"]}
        affected_namespaces = {r.split("/")[1] for r in affected_resources if r.count("/") >= 2}
        priority = self._priority_ten(issues)

        summary = {
            "status": "AVAILABLE",
            "reason": None,
            "cluster_security_score": None,
            "score_basis": "Not used. Findings are classified directly as CRITICAL, HIGH, MEDIUM, LOW, or UNKNOWN.",
            "score_explanation": "No composite risk score is calculated. Severity is based on the security impact of each verified finding.",
            "score_breakdown": [],
            "scored_vulnerabilities": sum(1 for i in issues if i.get("category") == "vulnerability"),
            "unscored_unknown_vulnerabilities": sum(1 for i in issues if i.get("category") == "vulnerability" and i.get("severity") == "UNKNOWN"),
            "total_vulnerabilities": sum(1 for i in issues if i.get("category") == "vulnerability"),
            "critical_vulnerabilities": sum(1 for i in issues if i.get("category") == "vulnerability" and i.get("severity") == "CRITICAL"),
            "high_vulnerabilities": sum(1 for i in issues if i.get("category") == "vulnerability" and i.get("severity") == "HIGH"),
            "medium_vulnerabilities": sum(1 for i in issues if i.get("category") == "vulnerability" and i.get("severity") == "MEDIUM"),
            "low_vulnerabilities": sum(1 for i in issues if i.get("category") == "vulnerability" and i.get("severity") == "LOW"),
            "unknown_vulnerabilities": sum(1 for i in issues if i.get("category") == "vulnerability" and i.get("severity") == "UNKNOWN"),
            "total_misconfigurations": sum(1 for i in issues if i.get("category") not in {"vulnerability", "exposed_secret"}),
            "total_exposed_secrets": secrets,
            "affected_workloads": len(affected_resources),
            "affected_namespaces": len(affected_namespaces),
            "top_10_risks": [],
            "top_recommendations": [i["fix"] for i in priority[:5]],
            "priority_issues": priority,
            "total_unique_issues": len(issues),
            "coverage": dict(self.coverage),
            "source_status": source_status,
            "severity_counts": {"CRITICAL": critical, "HIGH": high, "MEDIUM": medium, "LOW": low},
        }
        diagnostics = {
            "mode": "live-layered",
            "security_evidence_created": len(self.evidence),
            "priority_issues": len(priority),
            "trivy_rows_aggregated": sum(i["occurrences"] for i in issues if i["source"] == "trivy-operator"),
            "mongo_evidence_cap": self._evidence_limit,
            "source_status": source_status,
            "falco_alerts": source_status["falco"]["alerts"],
            "kubescape_failed_controls": source_status["kubescape"]["failed_controls"],
        }
        return {"evidence": self.evidence, "summary": summary, "diagnostics": diagnostics}


SecurityEvidenceCollector = LayeredSecurityEvidenceCollector
