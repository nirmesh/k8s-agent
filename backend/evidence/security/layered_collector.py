from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from backend.ai.security_explainer import enrich_security_issues
from backend.evidence.security.additional_sources import collect_additional_sources
from backend.evidence.security.fast_collector import FastSecurityEvidenceCollector


class LayeredSecurityEvidenceCollector(FastSecurityEvidenceCollector):
    """Collect native Kubernetes, Trivy and Falco evidence.

    Provider detections remain deterministic and evidence-grounded. The LLM is
    used only to explain and classify the operator-visible priority findings.
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
        trivy_status = self._trivy_status()
        self._scan_trivy()
        trivy_status["findings"] = sum(1 for i in self.issues.values() if i.get("source") == "trivy-operator")
        source_status["trivy"] = trivy_status

        issues = list(self.issues.values())
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        issues.sort(key=lambda x: (severity_order.get(str(x.get("severity", "UNKNOWN")).upper(), 4), x.get("title", "")))
        priority_seed = self._priority_ten(issues)
        enrich_security_issues(priority_seed, limit=10)
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
        observed_at = datetime.now(timezone.utc).isoformat()

        summary = {
            "status": "AVAILABLE",
            "reason": None,
            "observed_at": observed_at,
            "cluster_security_score": None,
            "score_basis": "Not used. Findings are classified directly as CRITICAL, HIGH, MEDIUM, LOW, or UNKNOWN.",
            "score_explanation": "No composite risk score is calculated. Severity is based on verified evidence and the security impact classification.",
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
            "falco_alerts": source_status.get("falco", {}).get("alerts", 0),
            "llm_explanations": sum(1 for i in priority if i.get("explanation_source") == "llm"),
        }
        return {"evidence": self.evidence, "summary": summary, "diagnostics": diagnostics}


SecurityEvidenceCollector = LayeredSecurityEvidenceCollector
