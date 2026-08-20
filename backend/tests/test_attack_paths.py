from backend.evidence.security.attack_paths import build_attack_paths


def test_internet_facing_privileged_workload_creates_critical_path():
    summary = {
        "affected_workloads": 1,
        "affected_namespaces": 1,
        "top_10_risks": [{
            "name": "web", "namespace": "default", "privileged": True, "internet_facing": True,
        }],
        "native_posture_findings": [{
            "rule_id": "K8S-POSTURE-PRIVILEGED",
            "resource": "Pod/default/web",
        }],
        "native_posture_checks": [],
    }
    result = build_attack_paths(summary)
    assert result["count"] == 1
    assert result["highest_impact"]["severity"] == "CRITICAL"
    assert result["highest_impact"]["risk_score"] == 95


def test_cluster_admin_and_encryption_gap_create_secret_path():
    summary = {
        "affected_workloads": 10,
        "affected_namespaces": 3,
        "top_10_risks": [],
        "native_posture_findings": [{
            "rule_id": "K8S-POSTURE-RBAC-CLUSTERADMIN",
            "resource": "ClusterRoleBinding/cluster/app-admin",
        }],
        "native_posture_checks": [{
            "id": "K8S-DATASTORE-ENCRYPTION", "status": "FAIL",
        }],
    }
    result = build_attack_paths(summary)
    assert result["count"] == 1
    assert result["paths"][0]["id"] == "AP-RBAC-SECRETS-ETCD"
    assert result["paths"][0]["severity"] == "HIGH"


def test_no_verified_relationships_means_no_attack_path():
    result = build_attack_paths({"top_10_risks": [], "native_posture_findings": [], "native_posture_checks": []})
    assert result["count"] == 0
    assert result["highest_impact"] is None
