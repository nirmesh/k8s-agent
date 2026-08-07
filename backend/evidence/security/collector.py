from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from backend.core.logging import logger
from backend.evidence.security.model import SecurityEvidence, SecurityFinding
from backend.kubernetes.toolkit import K8sToolkit


TRIVY_GROUP = "aquasecurity.github.io"
TRIVY_VERSION = "v1alpha1"
TRIVY_CRDS: dict[str, str] = {
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
    "UNKNOWN": 0,
}


def _severity(value: Any) -> str:
    return str(value or "UNKNOWN").upper()


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
        or item.get("ruleID")
        or "Unknown"
    )


def _description(item: dict[str, Any]) -> str:
    return item.get("description") or item.get("message") or item.get("details") or ""


def _recommendation(item: dict[str, Any]) -> str | None:
    if item.get("fixedVersion"):
        return f"Upgrade to {item['fixedVersion']}"
    return item.get("remediation") or item.get("resolution") or None


def _resource_labels(crd: dict[str, Any]) -> tuple[str, str, str]:
    metadata = crd.get("metadata") or {}
    labels = metadata.get("labels") or {}
    kind = (
        labels.get("trivy-operator.resource.kind")
        or (metadata.get("ownerReferences") or [{}])[0].get("kind")
        or "Workload"
    )
    ns = labels.get("trivy-operator.resource.namespace") or metadata.get("namespace") or "cluster"
    name = labels.get("trivy-operator.resource.name") or metadata.get("name") or "unknown"
    return str(kind), str(ns), str(name)


def _workload_key(resource: str) -> tuple[str, str, str]:
    """Map a Trivy resource label to a top-level workload key.

    ReplicaSet names are reduced to their owning Deployment by stripping the
    trailing hash segment.
    """
    parts = resource.split("/")
    if len(parts) != 3:
        return resource, "Workload", "cluster"
    kind, ns, name = parts
    if kind.lower() == "replicaset":
        base = name.rsplit("-", 1)[0]
        if base and base != name:
            return f"Deployment/{ns}/{base}", "Deployment", ns
    return resource, kind, ns


class SecurityEvidenceCollector:
    """Read Trivy Operator CRDs from Kubernetes and normalize to SecurityEvidence."""

    def __init__(self, toolkit: K8sToolkit):
        self.toolkit = toolkit

    def collect(self) -> dict[str, Any]:
        evidence: list[SecurityEvidence] = []
        for plural, category in TRIVY_CRDS.items():
            result = self.toolkit.get_custom_resources(TRIVY_GROUP, TRIVY_VERSION, plural)
            if not result.get("success"):
                logger.warning(
                    f"Failed to collect {plural}: {result.get('error', {}).get('message')}"
                )
                continue
            for item in (result.get("data") or {}).get("items") or []:
                evidence.extend(self._normalize(item, category))

        summary = SecuritySummarizer(self.toolkit, evidence).summarize()
        return {"evidence": evidence, "summary": summary}

    def _normalize(self, crd: dict[str, Any], category: str) -> list[SecurityEvidence]:
        kind, ns, name = _resource_labels(crd)
        resource = f"{kind}/{ns}/{name}"
        metadata = crd.get("metadata") or {}
        report = (
            crd.get("report")
            or (crd.get("status") or {}).get("report")
            or (crd.get("spec") or {}).get("report")
            or {}
        )
        timestamp = metadata.get("creationTimestamp")
        if timestamp:
            # Keep the original report timestamp if parseable.
            pass

        if category == "vulnerability":
            return self._vulnerabilities(resource, ns, report)
        if category == "misconfiguration":
            return self._misconfigurations(resource, ns, report)
        if category == "exposed_secret":
            return self._exposed_secrets(resource, ns, report)
        if category == "sbom":
            return [self._sbom(resource, ns, report, metadata)]
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
        for vuln in report.get("vulnerabilities") or []:
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

    def _misconfigurations(self, resource: str, namespace: str, report: dict[str, Any]) -> list[SecurityEvidence]:
        items: list[SecurityEvidence] = []
        for check in report.get("checks") or []:
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

    def _exposed_secrets(self, resource: str, namespace: str, report: dict[str, Any]) -> list[SecurityEvidence]:
        items: list[SecurityEvidence] = []
        for secret in report.get("secrets") or []:
            title = _title(secret)
            finding = SecurityFinding(
                category="exposed_secret",
                resource=resource,
                namespace=namespace,
                title=title,
                finding=title,
                description=_description(secret),
                severity=_severity(secret.get("severity")),
                remediation="Rotate the exposed secret and remove it from image or config.",
                recommendation="Rotate the exposed secret and remove it from image or config.",
                references=_references(secret),
                rule_id=secret.get("ruleID") or secret.get("id"),
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
    """Group normalized security evidence by workload and compute risk scores."""

    def __init__(self, toolkit: K8sToolkit, evidence: list[SecurityEvidence]):
        self.toolkit = toolkit
        self.evidence = evidence

    def _items(self, kind: str, namespace: str | None = None) -> list[dict[str, Any]]:
        result = self.toolkit.get_resources(kind, namespace)
        if not result.get("success"):
            return []
        return (result.get("data") or {}).get("items") or []

    def summarize(self) -> dict[str, Any]:
        services = self._items("service")
        deployments = self._items("deployment")
        pods = self._items("pod")

        deployment_by_key: dict[tuple[str, str], dict[str, Any]] = {}
        for dep in deployments:
            meta = dep.get("metadata") or {}
            spec = dep.get("spec") or {}
            key = (str(meta.get("namespace", "default")), str(meta.get("name", "")))
            template = (spec.get("template") or {}).get("spec") or {}
            pod_meta = (spec.get("template") or {}).get("metadata") or {}
            deployment_by_key[key] = {
                "labels": pod_meta.get("labels") or {},
                "replicas": spec.get("replicas", 1) or 1,
                "host_network": bool(template.get("hostNetwork")),
                "privileged": any(
                    (c.get("securityContext") or {}).get("privileged")
                    for c in (template.get("containers") or [])
                ),
            }

        # Internet-facing workloads based on LoadBalancer/NodePort services.
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

        # Running pod counts per deployment.
        running_pods: dict[tuple[str, str], int] = defaultdict(int)
        for pod in pods:
            meta = pod.get("metadata") or {}
            status = pod.get("status") or {}
            refs = meta.get("ownerReferences") or []
            if status.get("phase") != "Running":
                continue
            for ref in refs:
                if str(ref.get("kind", "")).lower() == "replicaset":
                    rs_name = str(ref.get("name", ""))
                    base = rs_name.rsplit("-", 1)[0]
                    if base:
                        running_pods[(meta.get("namespace", "default"), base)] += 1

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
            resource = finding.resource
            workload_resource, kind, ns = _workload_key(resource)
            parts = workload_resource.split("/")
            if len(parts) == 3:
                _, _, wname = parts
            else:
                wname = resource
                ns = ev.namespace or "cluster"
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

            # Scale with replicas, but cap so a single huge workload does not drown others.
            score = int(score * min(entry["replicas"], 5))
            entry["risk_score"] = min(100, score)
            entry["recommendation"] = self._recommend(entry)
            workload_list.append(dict(entry))

        workload_list.sort(key=lambda w: w["risk_score"], reverse=True)

        total_vulns = sum(1 for e in self.evidence if e.category == "vulnerability")
        total_misconfigs = sum(1 for e in self.evidence if e.category == "misconfiguration")
        total_secrets = sum(1 for e in self.evidence if e.category == "exposed_secret")

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

        cluster_score = max(
            0,
            100
            - int(
                sum(w["risk_score"] for w in workload_list)
                / max(1, len(workload_list))
            ),
        )

        critical = [w for w in workload_list if w["risk_score"] >= 80]
        top_recommendations = [w["recommendation"] for w in workload_list if w["recommendation"]][:5]

        return {
            "cluster_security_score": cluster_score,
            "critical_workloads": critical,
            "high_risk_namespaces": high_risk_namespaces,
            "top_10_risks": workload_list[:10],
            "top_recommendations": top_recommendations,
            "total_vulnerabilities": total_vulns,
            "total_misconfigurations": total_misconfigs,
            "total_exposed_secrets": total_secrets,
            "workload_count": len(workload_list),
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
