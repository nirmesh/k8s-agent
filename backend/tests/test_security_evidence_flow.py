"""Integration-style tests for the Trivy security evidence flow."""

from backend.evidence.security.collector import SecurityEvidenceCollector
from backend.evidence.security.model import SecurityFinding


class FakeToolkit:
    """Minimal stand-in for K8sToolkit so the collector can be tested without a cluster."""

    def __init__(self, reports_by_plural=None, owner_chain=None, deployments=None, services=None, pods=None):
        self.reports_by_plural = reports_by_plural or {}
        self.owner_chain = owner_chain or {}
        self.deployments = deployments or []
        self.services = services or []
        self.pods = pods or []

    def get_custom_resources(self, group, version, plural, namespace=None):
        items = self.reports_by_plural.get(plural, [])
        return {
            "success": True,
            "data": {"group": group, "version": version, "plural": plural, "items": items},
        }

    def get_resources(self, kind, namespace=None):
        if kind == "deployment":
            items = self.deployments
        elif kind == "service":
            items = self.services
        elif kind == "pod":
            items = self.pods
        elif kind == "namespace":
            items = [{"metadata": {"name": n}} for n in {"default", "kube-system"}]
        else:
            items = []
        return {"success": True, "data": {"items": items}}

    def get_owner(self, kind, namespace, name):
        key = (kind, namespace, name)
        owner = self.owner_chain.get(key)
        if owner:
            return {"success": True, "data": {"owners": [owner]}}
        return {"success": True, "data": {"owners": []}}


def _vul_report(name, namespace, resource_name, resource_kind="ReplicaSet", vulnerabilities=None, summary=None):
    report = {
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {
                "trivy-operator.resource.kind": resource_kind,
                "trivy-operator.resource.namespace": namespace,
                "trivy-operator.resource.name": resource_name,
            },
        },
        "report": {},
    }
    if vulnerabilities is not None:
        report["report"]["vulnerabilities"] = vulnerabilities
    if summary is not None:
        report["report"]["summary"] = summary
    return report


def test_real_vulnerability_reports_produce_non_zero_counts():
    """A VulnerabilityReport with CRITICAL and HIGH findings becomes security evidence with non-zero counts."""
    reports = {
        "vulnerabilityreports": [
            _vul_report(
                "nginx-7d8f-1234",
                "default",
                "nginx-7d8f",
                "ReplicaSet",
                vulnerabilities=[
                    {
                        "vulnerabilityID": "CVE-2024-1111",
                        "title": "Heap overflow",
                        "severity": "CRITICAL",
                        "primaryLink": "https://avd.aquasec.com/nvd/cve-2024-1111",
                    },
                    {
                        "vulnerabilityID": "CVE-2024-2222",
                        "title": "Information leak",
                        "severity": "HIGH",
                    },
                ],
            )
        ]
    }
    owner_chain = {
        ("ReplicaSet", "default", "nginx-7d8f"): {
            "kind": "Deployment",
            "metadata": {"name": "nginx", "namespace": "default"},
        }
    }
    deployments = [
        {
            "metadata": {"name": "nginx", "namespace": "default"},
            "spec": {"replicas": 2},
        }
    ]
    toolkit = FakeToolkit(reports_by_plural=reports, owner_chain=owner_chain, deployments=deployments)

    result = SecurityEvidenceCollector(toolkit).collect()

    summary = result["summary"]
    assert summary["status"] == "AVAILABLE"
    assert summary["total_vulnerabilities"] == 2
    assert summary["critical_vulnerabilities"] == 1
    assert summary["high_vulnerabilities"] == 1
    assert summary["affected_workloads"] == 1
    assert summary["affected_namespaces"] == 1
    assert summary["cluster_security_score"] is not None
    assert summary["cluster_security_score"] < 100
    assert result["diagnostics"]["security_evidence_created"] == 2
    evidence = result["evidence"]
    assert all(isinstance(e.payload, SecurityFinding) for e in evidence)


def test_no_reports_available_status_zero_counts():
    """When no Trivy reports exist, status is AVAILABLE with zero findings and a perfect score."""
    toolkit = FakeToolkit(reports_by_plural={})
    result = SecurityEvidenceCollector(toolkit).collect()
    summary = result["summary"]
    assert summary["status"] == "AVAILABLE"
    assert summary["total_vulnerabilities"] == 0
    assert summary["cluster_security_score"] == 100


def test_kubernetes_api_failure_unavailable_not_100():
    """A complete failure to read CRDs results in UNAVAILABLE status, not a default 100/100."""

    class FailingToolkit(FakeToolkit):
        def get_custom_resources(self, group, version, plural, namespace=None):
            return {
                "success": False,
                "error": {"message": "connection refused"},
            }

    toolkit = FailingToolkit()
    result = SecurityEvidenceCollector(toolkit).collect()
    summary = result["summary"]
    assert summary["status"] == "UNAVAILABLE"
    assert summary["cluster_security_score"] is None
    assert summary["total_vulnerabilities"] == 0
    assert summary["reason"]


def test_summary_counts_fallback_when_detail_list_missing():
    """Trivy report.summary counts are used when the detailed vulnerability array is missing."""
    reports = {
        "vulnerabilityreports": [
            _vul_report(
                "app-abc-5678",
                "kube-system",
                "app-abc",
                "ReplicaSet",
                summary={
                    "criticalCount": 2,
                    "highCount": 1,
                },
            )
        ]
    }
    toolkit = FakeToolkit(reports_by_plural=reports)
    result = SecurityEvidenceCollector(toolkit).collect()
    summary = result["summary"]
    assert summary["status"] == "AVAILABLE"
    assert summary["total_vulnerabilities"] == 3
    assert summary["critical_vulnerabilities"] == 2
    assert summary["high_vulnerabilities"] == 1
