from backend.evidence.security.posture import evaluate_cluster_posture


class FakeToolkit:
    def __init__(self, resources=None):
        self.resources = resources or {}
        self.api_client = None

    def get_resources(self, kind, namespace=None):
        return {"success": True, "data": {"items": self.resources.get((kind, namespace), self.resources.get((kind, None), []))}}


def test_privileged_pod_is_detected_across_all_namespaces():
    toolkit = FakeToolkit({
        ("node", None): [{"metadata": {"name": "node-1"}}],
        ("pod", None): [{"metadata": {"name": "security-test-privileged", "namespace": "default"}, "spec": {"containers": [{"name": "privileged", "securityContext": {"privileged": True}}]}}],
    })
    findings = evaluate_cluster_posture(toolkit)
    privileged = [f for f in findings if f.payload.rule_id == "K8S-POSTURE-PRIVILEGED"]
    assert len(privileged) == 1
    assert privileged[0].severity == "CRITICAL"
    assert privileged[0].resource == "Pod/default/security-test-privileged"


def test_privileged_infrastructure_is_contextually_lower_risk():
    toolkit = FakeToolkit({
        ("node", None): [{}],
        ("pod", None): [{"metadata": {"name": "nvidia-device-plugin-daemonset", "namespace": "gpu-operator", "labels": {"app.kubernetes.io/component": "nvidia-device-plugin"}}, "spec": {"containers": [{"name": "plugin", "securityContext": {"privileged": True}}]}}],
    })
    findings = evaluate_cluster_posture(toolkit)
    privileged = [f for f in findings if f.payload.rule_id == "K8S-POSTURE-PRIVILEGED-EXPECTED"]
    assert len(privileged) == 1
    assert privileged[0].severity == "LOW"


def test_normal_pod_has_no_privileged_finding():
    toolkit = FakeToolkit({
        ("node", None): [{}],
        ("pod", None): [{"metadata": {"name": "normal", "namespace": "default"}, "spec": {"containers": [{"name": "app", "securityContext": {"privileged": False}}]}}],
    })
    findings = evaluate_cluster_posture(toolkit)
    assert not [f for f in findings if f.payload.rule_id == "K8S-POSTURE-PRIVILEGED"]


def test_apiserver_and_etcd_posture_is_collected():
    apiserver = {"metadata": {"name": "kube-apiserver-node"}, "spec": {"containers": [{"command": ["kube-apiserver", "--anonymous-auth=true"]}]}}
    etcd = {"metadata": {"name": "etcd-node"}, "spec": {"containers": [{"command": ["etcd"]}]}}
    toolkit = FakeToolkit({
        ("node", None): [{}],
        ("pod", None): [],
        ("pod", "kube-system"): [apiserver, etcd],
        ("networkpolicy", None): [],
        ("namespace", None): [],
    })
    findings = evaluate_cluster_posture(toolkit)
    rule_ids = {f.payload.rule_id for f in findings}
    assert "K8S-POSTURE-ANONYMOUS-AUTH" in rule_ids
    assert "K8S-POSTURE-ETCD-ENCRYPTION" in rule_ids
    assert "K8S-POSTURE-ETCD-CLIENT-CERT" in rule_ids
    assert "K8S-POSTURE-ETCD-PEER-CERT" in rule_ids
