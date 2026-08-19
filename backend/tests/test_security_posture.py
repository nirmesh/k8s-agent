from backend.evidence.security.posture import evaluate_cluster_posture


class FakeToolkit:
    def __init__(self, nodes=None, pods=None):
        self.nodes = nodes if nodes is not None else [{"metadata": {"name": "node-1"}}]
        self.pods = pods if pods is not None else []

    def get_resources(self, kind, namespace=None):
        if kind == "node":
            return {"success": True, "data": {"items": self.nodes}}
        if kind == "pod":
            return {"success": True, "data": {"items": self.pods}}
        return {"success": True, "data": {"items": []}}


def test_privileged_pod_is_detected_across_all_namespaces():
    toolkit = FakeToolkit(
        pods=[
            {
                "metadata": {"name": "security-test-privileged", "namespace": "default"},
                "spec": {
                    "containers": [
                        {
                            "name": "privileged",
                            "securityContext": {"privileged": True},
                        }
                    ]
                },
            }
        ]
    )

    findings = evaluate_cluster_posture(toolkit)

    privileged = [f for f in findings if f.payload.rule_id == "K8S-POSTURE-PRIVILEGED"]
    assert len(privileged) == 1
    assert privileged[0].severity == "CRITICAL"
    assert privileged[0].resource == "Pod/default/security-test-privileged"
    assert privileged[0].payload.title == "Privileged container detected"


def test_normal_pod_has_no_privileged_finding():
    toolkit = FakeToolkit(
        pods=[
            {
                "metadata": {"name": "normal", "namespace": "default"},
                "spec": {
                    "containers": [
                        {
                            "name": "app",
                            "securityContext": {"privileged": False},
                        }
                    ]
                },
            }
        ]
    )

    findings = evaluate_cluster_posture(toolkit)
    assert not [f for f in findings if f.payload.rule_id == "K8S-POSTURE-PRIVILEGED"]
