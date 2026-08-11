from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from backend.core.logging import logger
from backend.evidence.security.model import SecurityEvidence, SecurityFinding
from backend.kubernetes.toolkit import K8sToolkit


TRIVY_GROUP = "aquasecurity.github.io"
TRIVY_CRDS = [
    "vulnerabilityreports",
    "configauditreports",
    "exposedsecretreports",
    "sbomreports",
]
TRIVY_PLURAL_TO_CATEGORY: dict[str, str] = {
    "vulnerabilityreports": "vulnerability",
    "configauditreports": "misconfiguration",
    "exposedsecretreports": "exposed_secret",
    "sbomreports": "sbom",
}

SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 5,
    "MEDIUM": 2,
    "LOW": 1,
    "UNKNOWN": 1,
}

ROOT_WORKLOADS = {"Deployment", "DaemonSet", "StatefulSet", "CronJob"}
FOLLOWABLE_WORKLOADS = {"Pod", "ReplicaSet", "Job"}


def _severity(value: Any) -> str:
    s = str(value or "UNKNOWN").upper()
    return s if s in SEVERITY_WEIGHTS else "UNKNOWN"


def _references(item: dict[str, Any]) -> list[str] | None:
    refs: list[str] = []
    for key in ("primaryLink", "links", "references"):
        val = item.get(key)
        if isinstance(val, str) and val:
            refs.append(val)
        elif isinstance(val, list):
            refs.extend([v for v in val if isinstance(v, str) and v])
    return refs or None


def _title(item: dict[str, Any]) -> str:
    return (
        item.get("title")
        or item.get("vulnerabilityID")
        or item.get("id")
        or item.get("checkID")
        or item.get("ruleID")
        or "Unknown"
    )


def _description(item: dict[str, Any]) -> str:
    return item.get("description") or item.get("message") or item.get("details") or ""


def _recommendation(item: dict[str, Any]) -> str | None:
    if item.get("fixedVersion"):
        return f"Upgrade to {item['fixedVersion']}"
    return item.get("remediation") or item.get("resolution") or None


def _resource_from_crd(crd: dict[str, Any]) -> tuple[str, str, str]:
    """Return (kind, namespace, name) from the Trivy Operator resource labels."""
    metadata = crd.get("metadata") or {}
    labels = metadata.get("labels") or {}
    kind = labels.get("trivy-operator.resource.kind") or "Workload"
    ns = labels.get("trivy-operator.resource.namespace") or metadata.get("namespace") or "cluster"
    name = labels.get("trivy-operator.resource.name") or metadata.get("name") or "unknown"
    return str(kind), str(ns), str(name)


def _summary_counts(report: dict[str, Any], prefix: str) -> dict[str, int]:
    """Extract severity counts from a Trivy report summary."""
    summary = report.get("summary") or {}
    return {
        "CRITICAL": summary.get(f"{prefix}CriticalCount", summary.get("criticalCount", 0)) or 0,
        "HIGH": summary.get(f"{prefix}HighCount", summary.get("highCount", 0)) or 0,
        "MEDIUM": summary.get(f"{prefix}MediumCount", summary.get("mediumCount", 0)) or 0,
        "LOW": summary.get(f"{prefix}LowCount", summary.get("lowCount", 0)) or 0,
        "UNKNOWN": summary.get(f"{prefix}UnknownCount", summary.get("unknownCount", 0)) or 0,
    }


class SecurityEvidenceCollector:
    """Read Trivy Operator CRDs from Kubernetes and normalize to SecurityEvidence."""

    def __init__(self, toolkit: K8sToolkit):
        self.toolkit = toolkit

    def collect(self) -> dict[str, Any]:
        evidence: list[SecurityEvidence] = []
        errors: list[str] = []
        reports_found = 0

        for plural in TRIVY_CRDS:
            result = self.toolkit.get_custom_resources(TRIVY_GROUP, None, plural)
            if not result.get("success"):
                msg = f"Failed to collect {plural}: {result.get('error', {}).get('message')}"
                logger.warning(msg)
                errors.append(msg)
                continue
            items = (result.get("data") or {}).get("items") or []
            reports_found += len(items)
            for item in items:
                evidence.extend(self._normalize(item, plural))

        available = reports_found > 0 or not errors or (len(errors) < len(TRIVY_CRDS))
        # If any CRD type succeeded we have a working connection, even if empty.
        available = available and (len(errors) < len(TRIVY_CRDS))

        diagnostics = {
            "trivy_reports_found": reports_found,
            "security_evidence_created": len(evidence),
            "vulnerability_findings": sum(1 for e in evidence if e.category == "vulnerability"),
            "misconfiguration_findings": sum(1 for e in evidence if e.category == "misconfiguration"),
            "secret_findings": sum(1 for e in evidence if e.category == "exposed_secret"),
            "workloads_with_security_findings": 0,
            "errors": errors,
        }

        summary = SecuritySummarizer(self.toolkit, evidence, available=available, errors=errors).summarize()
        diagnostics["workloads_with_security_findings"] = summary.get("affected_workloads", 0)

        logger.info(
            "SecurityEvidenceCollector diagnostics: "
            f"trivy_reports_found={diagnostics['trivy_reports_found']}, "
            f"security_evidence_created={diagnostics['security_evidence_created']}, "
            f"vulnerability_findings={diagnostics['vulnerability_findings']}, "
            f"misconfiguration_findings={diagnostics['misconfiguration_findings']}, "
            f"secret_findings={diagnostics['secret_findings']}, "
            f"workloads_with_security_findings={diagnostics['workloads_with_security_findings']}"
        )

        return {"evidence": evidence, "summary": summary, "diagnostics": diagnostics}

    def _normalize(self, crd: dict[str, Any], plural: str) -> list[SecurityEvidence]:
        kind, ns, name = _resource_from_crd(crd)
        resource = f"{kind}/{ns}/{name}"
        report = crd.get("report") or {}
        category = TRIVY_PLURAL_TO_CATEGORY.get(plural, "security")

        if category == "vulnerability":
            return self._vulnerabilities(resource, ns, report)
        if category == "misconfiguration":
            return self._misconfigurations(resource, ns, report)
        if category == "exposed_secret":
            return self._exposed_secrets(resource, ns, report)
        if category == "sbom":
            return [self._sbom(resource, ns, report, crd.get("metadata") or {})]
        return []

    def _security_evidence(
        self,
        resource: str,
        namespace: str,
        category: str,
        finding: SecurityFinding,
    ) -> SecurityEvidence:
        return SecurityEvidence(
            provider="trivy-operator",
            resource=resource,
            namespace=namespace,
            category=category,
            title=finding.title,
            description=finding.description,
            severity=finding.severity,
            recommendation=finding.recommendation,
            references=finding.references,
            confidence=1.0,
            timestamp=datetime.now(timezone.utc),
            payload=finding,
        )

    def _vulnerabilities(self, resource: str, namespace: str, report: dict[str, Any]) -> list[SecurityEvidence]:
        items: list[SecurityEvidence] = []
        vulns = report.get("vulnerabilities")
        if vulns:
            for vuln in vulns:
                title = _title(vuln)
                finding = SecurityFinding(
                    category="vulnerability",
                    resource=resource,
                    namespace=namespace,
                    title=title,
                    finding=title,
                    description=_description(vuln),
                    severity=_severity(vuln.get("severity")),
                    remediation=_recommendation(vuln),
                    recommendation=_recommendation(vuln),
                    references=_references(vuln),
                    cve_id=vuln.get("vulnerabilityID") or vuln.get("id"),
                    rule_id=vuln.get("vulnerabilityID") or vuln.get("id"),
                )
                items.append(self._security_evidence(resource, namespace, "vulnerability", finding))
            return items

        # Fallback to summary counts when the detailed list is absent.
        for severity, count in _summary_counts(report, "").items():
            for _ in range(count):
                finding = SecurityFinding(
                    category="vulnerability",
                    resource=resource,
                    namespace=namespace,
                    title=f"{severity} vulnerability summary finding",
                    finding=f"{severity} vulnerability summary finding",
                    description="Vulnerability detail list not available; count taken from report summary.",
                    severity=severity,
                    remediation="Review the image and upgrade packages if a fixed version is available.",
                    recommendation="Review the image and upgrade packages if a fixed version is available.",
                    references=None,
                    cve_id=None,
                    rule_id=None,
                )
                items.append(self._security_evidence(resource, namespace, "vulnerability", finding))
        return items

    def _misconfigurations(self, resource: str, namespace: str, report: dict[str, Any]) -> list[SecurityEvidence]:
        items: list[SecurityEvidence] = []
        checks = report.get("checks")
        if checks:
            for check in checks:
                title = _title(check)
                finding = SecurityFinding(
                    category="misconfiguration",
                    resource=resource,
                    namespace=namespace,
                    title=title,
                    finding=title,
                    description=_description(check),
                    severity=_severity(check.get("severity")),
                    remediation=_recommendation(check),
                    recommendation=_recommendation(check),
                    references=_references(check),
                    rule_id=check.get("id") or check.get("checkID") or check.get("ruleID"),
                )
                items.append(self._security_evidence(resource, namespace, "misconfiguration", finding))
            return items

        for severity, count in _summary_counts(report, "").items():
            for _ in range(count):
                finding = SecurityFinding(
                    category="misconfiguration",
                    resource=resource,
                    namespace=namespace,
                    title=f"{severity} misconfiguration summary finding",
                    finding=f"{severity} misconfiguration summary finding",
                    description="Detailed check list not available; count taken from report summary.",
                    severity=severity,
                    remediation="Review the resource configuration against the reported issue.",
                    recommendation="Review the resource configuration against the reported issue.",
                    references=None,
                    rule_id=None,
                )
                items.append(self._security_evidence(resource, namespace, "misconfiguration", finding))
        return items

    def _exposed_secrets(self, resource: str, namespace: str, report: dict[str, Any]) -> list[SecurityEvidence]:
        items: list[SecurityEvidence] = []
        secrets = report.get("secrets")
        if secrets:
            for secret in secrets:
                title = _title(secret)
                finding = SecurityFinding(
                    category="exposed_secret",
                    resource=resource,
                    namespace=namespace,
                    title=title,
                    finding=title,
                    description=_description(secret),
                    severity=_severity(secret.get("severity")),
                    remediation="Rotate the exposed secret and remove it from the image or configuration.",
                    recommendation="Rotate the exposed secret and remove it from the image or configuration.",
                    references=_references(secret),
                    rule_id=secret.get("ruleID") or secret.get("id"),
                    cve_id=None,
                )
                items.append(self._security_evidence(resource, namespace, "exposed_secret", finding))
            return items

        for severity, count in _summary_counts(report, "").items():
            for _ in range(count):
                finding = SecurityFinding(
                    category="exposed_secret",
                    resource=resource,
                    namespace=namespace,
                    title=f"{severity} exposed secret summary finding",
                    finding=f"{severity} exposed secret summary finding",
                    description="Detailed secret list not available; count taken from report summary.",
                    severity=severity,
                    remediation="Rotate exposed secrets and remove them from images or configuration.",
                    recommendation="Rotate exposed secrets and remove them from images or configuration.",
                    references=None,
                    rule_id=None,
                    cve_id=None,
                )
                items.append(self._security_evidence(resource, namespace, "exposed_secret", finding))
        return items

    def _sbom(
        self,
        resource: str,
        namespace: str,
        report: dict[str, Any],
        metadata: dict[str, Any],
    ) -> SecurityEvidence:
        return SecurityEvidence(
            provider="trivy-operator",
            resource=resource,
            namespace=namespace,
            category="sbom",
            title="SBOM report",
            description="Software Bill of Materials collected by the Trivy operator.",
            confidence=1.0,
            timestamp=datetime.now(timezone.utc),
            payload={"sbom": report, "metadata": metadata},
        )


class SecuritySummarizer:
    """Group normalized security evidence by workload and compute a deterministic risk summary.

    Score formula (documented and reproducible):
        score = 100 - sum(finding severity weight)
        where CRITICAL = 10, HIGH = 5, MEDIUM = 2, LOW = 1, UNKNOWN = 1
    The result is clamped to [0, 100]. If no security data can be collected the score is null.
    """

    def __init__(
        self,
        toolkit: K8sToolkit,
        evidence: list[SecurityEvidence],
        available: bool = True,
        errors: list[str] | None = None,
    ):
        self.toolkit = toolkit
        self.evidence = evidence
        self.available = available
        self.errors = errors or []

    def _api_items(self, kind: str, namespace: str | None = None) -> list[dict[str, Any]]:
        result = self.toolkit.get_resources(kind, namespace)
        if not result.get("success"):
            return []
        return (result.get("data") or {}).get("items") or []

    def _resolve_workload(self, kind: str, namespace: str, name: str) -> tuple[str, str, str]:
        """Follow owner references up to a root workload. Never invent names."""
        seen: set[tuple[str, str, str]] = set()
        current_kind, current_ns, current_name = kind, namespace, name
        while True:
            key = (current_kind, current_ns, current_name)
            if key in seen:
                break
            seen.add(key)
            if current_kind in ROOT_WORKLOADS:
                break
            if current_kind not in FOLLOWABLE_WORKLOADS:
                break
            owner_result = self.toolkit.get_owner(current_kind, current_ns, current_name)
            if not owner_result.get("success"):
                break
            owners = (owner_result.get("data") or {}).get("owners") or []
            if not owners:
                break
            owner = owners[0]
            meta = owner.get("metadata") or {}
            current_kind = owner.get("kind") or current_kind
            current_ns = meta.get("namespace") or current_ns
            current_name = meta.get("name") or current_name
            if not current_kind or not current_name:
                break
        return f"{current_kind}/{current_ns}/{current_name}", current_kind, current_ns

    def summarize(self) -> dict[str, Any]:
        if not self.available:
            return {
                "status": "UNAVAILABLE",
                "reason": "; ".join(self.errors) if self.errors else "Security CRDs could not be read from the cluster.",
                "cluster_security_score": None,
                "total_vulnerabilities": 0,
                "critical_vulnerabilities": 0,
                "high_vulnerabilities": 0,
                "medium_vulnerabilities": 0,
                "low_vulnerabilities": 0,
                "unknown_vulnerabilities": 0,
                "total_misconfigurations": 0,
                "total_exposed_secrets": 0,
                "affected_workloads": 0,
                "affected_namespaces": 0,
                "top_10_risks": [],
                "top_recommendations": [],
            }

        services = self._api_items("service")
        deployments = self._api_items("deployment")
        pods = self._api_items("pod")

        deployment_by_key: dict[tuple[str, str], dict[str, Any]] = {}
        for dep in deployments:
            meta = dep.get("metadata") or {}
            spec = dep.get("spec") or {}
            template = (spec.get("template") or {}).get("spec") or {}
            pod_meta = (spec.get("template") or {}).get("metadata") or {}
            key = (str(meta.get("namespace", "default")), str(meta.get("name", "")))
            deployment_by_key[key] = {
                "labels": pod_meta.get("labels") or {},
                "replicas": spec.get("replicas", 1) or 1,
                "host_network": bool(template.get("hostNetwork")),
                "privileged": any(
                    (c.get("securityContext") or {}).get("privileged")
                    for c in (template.get("containers") or [])
                ),
            }

        internet_keys: set[tuple[str, str]] = set()
        for svc in services:
            meta = svc.get("metadata") or {}
            spec = svc.get("spec") or {}
            if spec.get("type") not in ("LoadBalancer", "NodePort"):
                continue
            selector = spec.get("selector") or {}
            ns = str(meta.get("namespace", "default"))
            if not selector:
                continue
            for (dns, dname), dep in deployment_by_key.items():
                if dns != ns:
                    continue
                labels = dep.get("labels") or {}
                if all(labels.get(k) == v for k, v in selector.items()):
                    internet_keys.add((dns, dname))

        running_pods: dict[tuple[str, str], int] = defaultdict(int)
        for pod in pods:
            meta = pod.get("metadata") or {}
            status = pod.get("status") or {}
            refs = meta.get("ownerReferences") or []
            if status.get("phase") != "Running":
                continue
            for ref in refs:
                rkind = str(ref.get("kind", "")).lower()
                rname = str(ref.get("name", ""))
                if rkind == "replicaset":
                    base = rname.rsplit("-", 1)[0]
                    if base:
                        running_pods[(meta.get("namespace", "default"), base)] += 1
                elif rkind in ("deployment", "statefulset", "daemonset"):
                    running_pods[(meta.get("namespace", "default"), rname)] += 1

        workloads: dict[tuple[str, str], dict[str, Any]] = defaultdict(
            lambda: {
                "name": "",
                "namespace": "",
                "kind": "Workload",
                "risk_score": 0,
                "counts": defaultdict(int),
                "findings": [],
                "internet_facing": False,
                "privileged": False,
                "host_network": False,
                "replicas": 1,
                "running": 0,
                "recommendation": "",
            }
        )

        for ev in self.evidence:
            if ev.category not in ("vulnerability", "misconfiguration", "exposed_secret"):
                continue
            payload = ev.payload
            if isinstance(payload, dict):
                continue
            finding: SecurityFinding = payload
            res = finding.resource or ""
            rparts = res.split("/")
            if len(rparts) == 3:
                rkind, rns, rname = rparts
            elif len(rparts) == 1 and rparts[0]:
                rkind, rns, rname = "Workload", finding.namespace or ev.namespace or "cluster", rparts[0]
            else:
                rkind, rns, rname = "Workload", finding.namespace or ev.namespace or "cluster", "unknown"
            workload_resource, kind, ns = self._resolve_workload(rkind, rns, rname)
            parts = workload_resource.split("/")
            if len(parts) == 3:
                _, _, wname = parts
            else:
                wname = finding.resource or "unknown"
                ns = finding.namespace or ev.namespace or "cluster"
            key = (ns, wname)
            entry = workloads[key]
            entry["name"] = wname
            entry["namespace"] = ns
            entry["kind"] = kind or "Workload"
            entry["counts"][finding.severity] += 1
            entry["findings"].append(
                {
                    "title": finding.title,
                    "severity": finding.severity,
                    "category": finding.category,
                    "cve_id": finding.cve_id,
                    "recommendation": finding.recommendation,
                }
            )
            dep = deployment_by_key.get((ns, wname), {})
            entry["replicas"] = dep.get("replicas", 1) or 1
            entry["host_network"] = bool(dep.get("host_network"))
            entry["privileged"] = bool(dep.get("privileged"))
            entry["running"] = running_pods.get((ns, wname), 0)
            if key in internet_keys:
                entry["internet_facing"] = True

        workload_list: list[dict[str, Any]] = []
        for (ns, name), entry in workloads.items():
            score = 0
            for sev, weight in SEVERITY_WEIGHTS.items():
                score += entry["counts"][sev] * weight
            if entry["internet_facing"]:
                score = int(score * 1.5)
            if entry["privileged"]:
                score = int(score * 1.3)
            if entry["host_network"]:
                score = int(score * 1.3)
            if entry["running"] > 0:
                score = int(score * 1.2)
            score = int(score * min(entry["replicas"], 5))
            entry["risk_score"] = min(100, score)
            entry["recommendation"] = self._recommend(entry)
            workload_list.append(dict(entry))

        workload_list.sort(key=lambda w: w["risk_score"], reverse=True)

        severity_counts: dict[str, int] = defaultdict(int)
        for ev in self.evidence:
            if ev.category == "vulnerability":
                severity_counts[ev.severity] += 1

        total_vulns = sum(severity_counts[s] for s in SEVERITY_WEIGHTS)
        total_misconfigs = sum(1 for e in self.evidence if e.category == "misconfiguration")
        total_secrets = sum(1 for e in self.evidence if e.category == "exposed_secret")

        ns_set = set()
        for w in workload_list:
            ns_set.add(w["namespace"])

        high_risk_namespaces = sorted(
            [
                {"namespace": ns, "average_score": 0}
                for ns in ns_set
            ],
            key=lambda x: x["namespace"],
        )
        # Recompute average scores per namespace
        ns_scores: dict[str, list[int]] = defaultdict(list)
        for w in workload_list:
            ns_scores[w["namespace"]].append(w["risk_score"])
        high_risk_namespaces = sorted(
            [
                {"namespace": ns, "average_score": int(sum(scores) / max(1, len(scores)))}
                for ns, scores in ns_scores.items()
            ],
            key=lambda x: x["average_score"],
            reverse=True,
        )[:5]

        deduction = (
            severity_counts["CRITICAL"] * 10
            + severity_counts["HIGH"] * 5
            + severity_counts["MEDIUM"] * 2
            + severity_counts["LOW"] * 1
            + severity_counts["UNKNOWN"] * 1
            + total_misconfigs * 2
            + total_secrets * 3
        )
        cluster_score = max(0, 100 - deduction)

        return {
            "status": "AVAILABLE",
            "reason": None,
            "cluster_security_score": cluster_score,
            "total_vulnerabilities": total_vulns,
            "critical_vulnerabilities": severity_counts["CRITICAL"],
            "high_vulnerabilities": severity_counts["HIGH"],
            "medium_vulnerabilities": severity_counts["MEDIUM"],
            "low_vulnerabilities": severity_counts["LOW"],
            "unknown_vulnerabilities": severity_counts["UNKNOWN"],
            "total_misconfigurations": total_misconfigs,
            "total_exposed_secrets": total_secrets,
            "affected_workloads": len(workload_list),
            "affected_namespaces": len(ns_set),
            "top_10_risks": workload_list[:10],
            "top_recommendations": [w["recommendation"] for w in workload_list if w["recommendation"]][:5],
        }

    @staticmethod
    def _recommend(entry: dict[str, Any]) -> str:
        if entry["risk_score"] >= 80:
            return (
                f"Upgrade/patch the '{entry['name']}' image immediately; "
                f"{entry['counts'].get('CRITICAL', 0)} critical and "
                f"{entry['counts'].get('HIGH', 0)} high issues are exposed."
            )
        if entry["risk_score"] >= 50:
            return (
                f"Plan remediation for '{entry['name']}' during the next maintenance window; "
                f"risk is elevated by {entry['counts'].get('HIGH', 0)} high-severity findings."
            )
        if entry["counts"].get("MEDIUM", 0):
            return f"Monitor '{entry['name']}'; {entry['counts'].get('MEDIUM', 0)} medium findings present."
        return "No immediate action required."
