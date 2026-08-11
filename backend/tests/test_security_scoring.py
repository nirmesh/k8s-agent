from backend.evidence.security.scoring import score_security_posture


def test_unknown_findings_do_not_reduce_score():
    summary = {
        "status": "AVAILABLE",
        "critical_vulnerabilities": 0,
        "high_vulnerabilities": 0,
        "medium_vulnerabilities": 0,
        "low_vulnerabilities": 0,
        "unknown_vulnerabilities": 1794,
        "total_misconfigurations": 0,
        "total_exposed_secrets": 0,
        "affected_workloads": 10,
    }
    result = score_security_posture(summary)
    assert result["cluster_security_score"] == 100
    assert result["unscored_unknown_vulnerabilities"] == 1794


def test_known_risk_score_is_not_raw_count_subtraction():
    summary = {
        "status": "AVAILABLE",
        "critical_vulnerabilities": 5,
        "high_vulnerabilities": 20,
        "medium_vulnerabilities": 30,
        "low_vulnerabilities": 40,
        "unknown_vulnerabilities": 1000,
        "total_misconfigurations": 10,
        "total_exposed_secrets": 0,
        "affected_workloads": 20,
    }
    result = score_security_posture(summary)
    assert 5 <= result["cluster_security_score"] < 100
    assert "UNKNOWN findings excluded" in result["score_basis"]


def test_unavailable_security_score_is_unknown():
    result = score_security_posture({"status": "UNAVAILABLE"})
    assert result["cluster_security_score"] is None
