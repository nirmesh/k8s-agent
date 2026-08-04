import json

import pytest

from backend.evidence.security import SecurityEvidence, SecurityRegistry, get_security_registry
from backend.evidence.security.adapters.falco import FalcoAdapter
from backend.evidence.security.adapters.kubescape import KubescapeAdapter
from backend.evidence.security.adapters.trivy import TrivyAdapter
from backend.evidence.security.provider import SecurityProvider
from backend.providers.security_provider import SecurityEvidenceProvider


def test_trivy_adapter_normalizes_vulnerabilities():
    report = {
        "Results": [
            {
                "Target": "nginx:1.21",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2021-23017",
                        "Title": "nginx DNS resolver vulnerability",
                        "Description": "A flaw in the resolver.",
                        "Severity": "High",
                        "FixedVersion": "1.21.1",
                        "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-23017",
                    }
                ],
            }
        ]
    }
    adapter = TrivyAdapter(source=json.dumps(report))
    evidence = adapter.collect()
    assert len(evidence) == 1
    item = evidence[0]
    assert isinstance(item, SecurityEvidence)
    assert item.provider == "trivy"
    assert item.payload.category == "vulnerability"
    assert item.payload.resource == "image/nginx:1.21"
    assert item.payload.cve_id == "CVE-2021-23017"
    assert "1.21.1" in (item.payload.remediation or "")


def test_falco_adapter_normalizes_events():
    events = [
        {
            "rule": "Unexpected outbound connection",
            "priority": "Warning",
            "output": "Outbound connection from nginx",
            "output_fields": {"pod.name": "nginx-pod"},
        },
        {
            "rule": "Write below /etc",
            "priority": "Error",
            "output": "File created under /etc",
            "output_fields": {"proc.name": "setup.sh"},
        },
    ]
    adapter = FalcoAdapter(source=json.dumps(events))
    evidence = adapter.collect()
    assert len(evidence) == 2
    assert evidence[0].payload.category == "threat"
    assert evidence[0].payload.resource == "nginx-pod"
    assert evidence[1].payload.severity == "ERROR"


def test_kubescape_adapter_normalizes_controls():
    data = {
        "results": [
            {
                "resourceID": "Deployment/sre-lab/nginx",
                "controls": [
                    {
                        "name": "Allow privilege escalation",
                        "description": "Containers should not allow privilege escalation.",
                        "controlID": "C-0019",
                        "severity": "High",
                        "remediation": "Set allowPrivilegeEscalation to false.",
                        "status": {"status": "failed"},
                    }
                ],
            }
        ]
    }
    adapter = KubescapeAdapter(source=json.dumps(data))
    evidence = adapter.collect()
    assert len(evidence) == 1
    assert evidence[0].payload.category == "misconfiguration"
    assert evidence[0].payload.resource == "Deployment/sre-lab/nginx"
    assert evidence[0].payload.rule_id == "C-0019"


def test_security_registry_collects_from_all_registered_providers():
    registry = SecurityRegistry()
    registry.register(TrivyAdapter(source=json.dumps({"Results": []})))
    registry.register(FalcoAdapter(source=json.dumps([])))
    assert registry.list() == ["trivy", "falco"]
    assert registry.collect_all() == []


def test_security_registry_tool_execution_returns_evidence():
    report = {
        "Results": [
            {
                "Target": "app:latest",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2022-1234",
                        "Title": "Test",
                        "Description": "Desc",
                        "Severity": "Critical",
                    }
                ],
            }
        ]
    }
    registry = SecurityRegistry()
    registry.register(TrivyAdapter(source=json.dumps(report)))
    result = registry.execute("collect_security_evidence")
    assert result.type == "security"
    assert result.provider == "security"
    assert len(result.payload) == 1
    assert result.payload[0]["payload"]["cve_id"] == "CVE-2022-1234"


def test_security_evidence_provider_exposes_generic_tool():
    provider = SecurityEvidenceProvider()
    tool_names = [t["function"]["name"] for t in provider.tools()]
    assert "collect_security_evidence" in tool_names


def test_default_security_registry_registers_builtin_adapters():
    # Use no sources so adapters return empty lists deterministically.
    registry = get_security_registry(trivy_source=None, falco_source=None, kubescape_source=None)
    assert "trivy" in registry.list()
    assert "falco" in registry.list()
    assert "kubescape" in registry.list()


def test_security_provider_is_abstract():
    with pytest.raises(TypeError):
        SecurityProvider()  # type: ignore[abstract]
