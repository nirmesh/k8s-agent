from backend.evidence.security.attack_paths import build_attack_paths


def test_internet_facing_privileged_workload_creates_critical_path():
    summary = {
        "affected_workloads": 1,
        "affected_namespaces": 1,
        "top_10_risks": [{"name": "web", "namespace": "default", "privileged": True, "internet_facing": True}],
        "native_posture_findings": [{"rule_id": "K8S-POSTURE-PRIVILEGED", "resource": "Pod/default/web"}],
        "native_posture_checks": [],
    }
    result = build_attack_paths(summary)
    assert result["count"] == 1
    assert result["highest_impact"]["severity"] == "CRITICAL"
    assert result["highest_impact"]["risk_score"] == 100


def test_cluster_admin_binding_without_workload_identity_is_not_correlated():
    summary = {
        "affected_workloads": 10,
        "affected_namespaces": 3,
        "top_10_risks": [{"name": "web", "namespace": "default", "privileged": True}],
        "native_posture_findings": [
            {"rule_id": "K8S-POSTURE-PRIVILEGED", "resource": "Pod/default/web"},
            {"rule_id": "K8S-POSTURE-RBAC-CLUSTERADMIN", "resource": "ClusterRoleBinding/cluster/cluster-admin"},
        ],
        "native_posture_checks": [{"id": "K8S-DATASTORE-ENCRYPTION", "status": "FAIL"}],
    }
    result = build_attack_paths(summary)
    assert all("cluster-admin" not in p["title"].lower() for p in result["paths"])
    assert all(p["id"] != "AP-RBAC-SECRETS-ETCD" for p in result["paths"])


def test_direct_application_service_account_cluster_admin_can_form_datastore_path():
    summary = {
        "affected_workloads": 10,
        "affected_namespaces": 3,
        "top_10_risks": [],
        "native_posture_findings": [{"rule_id": "K8S-POSTURE-RBAC-NAMESPACE-CLUSTERADMIN", "resource": "ServiceAccount/default/app"}],
        "native_posture_checks": [{"id": "K8S-DATASTORE-ENCRYPTION", "status": "FAIL"}],
    }
    result = build_attack_paths(summary)
    assert any(p["id"] == "AP-RBAC-SECRETS-ETCD" for p in result["paths"])


def test_no_verified_relationships_means_no_attack_path():
    result = build_attack_paths({"top_10_risks": [], "native_posture_findings": [], "native_posture_checks": []})
    assert result["count"] == 0
    assert result["highest_impact"] is None
