from backend.evidence.correlation import CorrelationEngine
from backend.evidence.model import Evidence
from backend.evidence.security import SecurityEvidence, SecurityFinding


def test_empty_engine_returns_low_risk():
    engine = CorrelationEngine()
    result = engine.correlate()
    assert result["confidence"] == 0.0
    assert result["blast_radius"] == 0
    assert result["risk"] == "LOW"
    assert result["evidence_trail"] == []


def test_correlates_security_evidence():
    engine = CorrelationEngine()
    finding = SecurityFinding(
        category="vulnerability",
        resource="image/nginx:1.21",
        finding="CVE-2021-23017",
        description="A flaw in the resolver.",
        severity="CRITICAL",
    )
    evidence = SecurityEvidence(
        provider="trivy",
        type="security",
        resource="image/nginx:1.21",
        payload=finding,
    )
    engine.add(evidence)
    result = engine.correlate()
    assert result["blast_radius"] == 1
    assert result["risk"] == "HIGH"
    assert result["confidence"] == 0.5
    assert "image/nginx:1.21" in result["recommendation"]
    assert len(result["evidence_trail"]) == 1


def test_multiple_providers_raise_confidence():
    engine = CorrelationEngine()
    engine.add(
        SecurityEvidence(
            provider="trivy",
            type="security",
            resource="image/nginx:1.21",
            payload=SecurityFinding(
                category="vulnerability",
                resource="image/nginx:1.21",
                finding="CVE-2021-23017",
                description="desc",
                severity="HIGH",
            ),
        )
    )
    engine.add(
        Evidence(
            provider="kubernetes",
            type="event",
            resource="Pod/sre-lab/nginx-abc",
            payload={"reason": "BackOff", "message": "CrashLoopBackOff"},
        )
    )
    engine.add(
        SecurityEvidence(
            provider="falco",
            type="security",
            resource="Pod/sre-lab/nginx-abc",
            payload=SecurityFinding(
                category="shell_execution",
                resource="Pod/sre-lab/nginx-abc",
                finding="Shell execution",
                description="bash executed",
                severity="HIGH",
            ),
        )
    )
    result = engine.correlate()
    assert result["blast_radius"] == 2
    assert result["confidence"] == 0.9
    assert result["risk"] == "HIGH"
    assert len(result["evidence_trail"]) == 3


def test_seed_resource_limits_correlation():
    engine = CorrelationEngine()
    engine.add(
        SecurityEvidence(
            provider="trivy",
            type="security",
            resource="image/app:1.0",
            payload=SecurityFinding(
                category="vulnerability",
                resource="image/app:1.0",
                finding="CVE-1",
                description="desc",
                severity="HIGH",
            ),
        )
    )
    engine.add(
        SecurityEvidence(
            provider="kubescape",
            type="security",
            resource="Deployment/sre-lab/app",
            payload=SecurityFinding(
                category="pod_security",
                resource="Deployment/sre-lab/app",
                finding="Privileged container",
                description="desc",
                severity="HIGH",
            ),
        )
    )
    # Seed on deployment; image evidence is not related unless we add edges.
    result = engine.correlate(seed_resource="Deployment/sre-lab/app")
    assert result["blast_radius"] == 1
    assert result["confidence"] == 0.5
