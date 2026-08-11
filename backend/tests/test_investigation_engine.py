from backend.kubernetes.investigation_engine import collect_operational_evidence


class FakeToolkit:
    def __init__(self, data): self.data = data
    def list_resources(self, kind, namespace=None, api_version=None, label_selector=None, field_selector=None):
        if kind == "pod":
            return {"success": True, "data": {"items": self.data.get("matching_pods", []) if label_selector else self.data.get("pods", [])}}
        return {"success": True, "data": {"items": self.data.get(kind, [])}}
    def get_events(self, namespace=None, resource_name=None, event_type=None):
        return {"success": True, "data": {"items": self.data.get("events", {}).get(resource_name, [])}}
    def get_owner(self, kind, namespace, name):
        return {"success": True, "data": {"owners": self.data.get("owners", {}).get(name, [])}}
    def get_resource(self, kind, namespace, name):
        return {"success": True, "data": {"resource": self.data.get("resources", {}).get(name, {})}}


def test_readiness_failure_keeps_probe_and_image_evidence_separate():
    toolkit = FakeToolkit({
        "pods": [{"metadata": {"namespace": "ai-test", "name": "readiness-pod"}, "status": {"phase": "Running", "containerStatuses": [{"name": "nginx", "state": {"running": {}}}]}}],
        "deployments": [{"metadata": {"namespace": "ai-test", "name": "readiness-app"}, "spec": {"replicas": 1, "template": {"spec": {"containers": [{"name": "nginx", "image": "nginx:1.29", "readinessProbe": {"httpGet": {"path": "/this-path-does-not-exist", "port": 80}}}]}}}, "status": {"replicas": 1, "readyReplicas": 0, "availableReplicas": 0}}],
        "events": {"readiness-pod": [{"reason": "Unhealthy", "message": "Readiness probe failed: HTTP probe failed with statuscode: 404"}]},
        "owners": {"readiness-pod": [{"kind": "Deployment", "metadata": {"namespace": "ai-test", "name": "readiness-app"}}]},
        "resources": {"readiness-app": {"metadata": {"namespace": "ai-test", "name": "readiness-app"}, "spec": {"template": {"spec": {"containers": [{"name": "nginx", "image": "nginx:1.29", "readinessProbe": {"httpGet": {"path": "/this-path-does-not-exist", "port": 80}}}]}}}}},
    })
    evidence = collect_operational_evidence(toolkit)
    assert "probe_failure" in {e["signal"] for e in evidence}
    assert "image_pull_failure" not in {e["signal"] for e in evidence}
    assert next(e for e in evidence if e["signal"] == "probe_configuration")["payload"]["containers"][0]["readiness"]["httpGet"]["path"] == "/this-path-does-not-exist"


def test_image_pull_failure_requires_image_pull_evidence():
    toolkit = FakeToolkit({"pods": [{"metadata": {"namespace": "default", "name": "broken"}, "status": {"phase": "Pending", "containerStatuses": [{"name": "nginx", "image": "nginx:99.99", "state": {"waiting": {"reason": "ImagePullBackOff"}}}]}}], "events": {"broken": [{"reason": "Failed", "message": 'Failed to pull image "nginx:99.99": manifest unknown'}]}, "deployments": [], "services": [], "persistentvolumeclaim": []})
    evidence = collect_operational_evidence(toolkit)
    assert any(e["signal"] == "image_pull_failure" for e in evidence)


def test_service_evidence_records_selector_and_matches():
    toolkit = FakeToolkit({"pods": [], "matching_pods": [], "deployments": [], "services": [{"metadata": {"namespace": "sre-lab", "name": "web-service"}, "spec": {"selector": {"app": "WRONG"}}}], "endpoints": [{"metadata": {"namespace": "sre-lab", "name": "web-service"}, "subsets": []}], "persistentvolumeclaim": []})
    finding = next(e for e in collect_operational_evidence(toolkit) if e["signal"] == "service_routing_failure")
    assert finding["payload"]["selector"] == {"app": "WRONG"}
    assert finding["payload"]["matching_pods"] == []
