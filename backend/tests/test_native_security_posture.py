from backend.evidence.security.posture import evaluate_cluster_posture


class FakeToolkit:
    def get_resources(self, kind, namespace=None):
        if kind == "nodes":
            return {"success": True, "data": {"items": [{"metadata": {"name": "node-1"}}]}}
        if kind == "pods" and namespace == "kube-system":
            return {
                "success": True,
                "data": {
                    "items": [
                        {
                            "metadata": {"name": "security-test-privileged", "namespace": "kube-system"},
                            "spec": {
                                "containers": [
                                    {
                                        "name": "test",
                                        "securityContext": {"privileged": True},
                                    }
                                ]
                            },
                        }
                    ]
                },
            }
        return {"success": True, "data": {"items": []}}


def test_privileged_container_is_detected_as_native_posture_finding():
    findings = evaluate_cluster_posture(FakeToolkit())

    assert len(findings) == 1
    finding = findings[0]
    assert finding.source == "kubernetes-native"
    assert finding.layer.value == "posture"
    assert finding.domain.value == "workload"
    assert finding.severity == "CRITICAL"
    assert finding.category == "misconfiguration"
    assert finding.payload.rule_id == "K8S-POSTURE-PRIVILEGED"
    assert finding.resource == "Pod/kube-system/security-test-privileged"
