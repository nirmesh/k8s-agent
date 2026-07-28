import pytest
from unittest.mock import MagicMock

from backend.kubernetes.toolkit import ApiException, K8sToolkit, client


@pytest.fixture
def toolkit(monkeypatch):
    t = K8sToolkit(_api_client=MagicMock())
    monkeypatch.setattr(t, "_call", MagicMock())
    return t


@pytest.fixture
def fake_pod():
    m = MagicMock()
    m.to_dict.return_value = {"metadata": {"name": "pod-1"}}
    return m


@pytest.fixture
def fake_list():
    m = MagicMock()
    m.items = []
    return m


def test_get_resources_unsupported_kind(toolkit):
    result = toolkit.get_resources("unknown")
    assert result["success"] is False
    assert result["error"]["code"] == "UNSUPPORTED_KIND"


def test_get_resources_pods(toolkit, fake_pod):
    fake_list = MagicMock()
    fake_list.items = [fake_pod]
    toolkit._call.return_value = fake_list

    result = toolkit.get_resources("pod", namespace="default")

    assert result["success"] is True
    assert result["tool"] == "get_resources"
    assert result["data"]["items"][0]["metadata"]["name"] == "pod-1"

    args = toolkit._call.call_args[0]
    kwargs = toolkit._call.call_args[1]
    assert args[0] is client.CoreV1Api
    assert args[1] == "list_namespaced_pod"
    assert kwargs["namespace"] == "default"


def test_get_resources_all_namespaces(toolkit, fake_pod):
    fake_list = MagicMock()
    fake_list.items = [fake_pod]
    toolkit._call.return_value = fake_list

    result = toolkit.get_resources("deployment")

    args = toolkit._call.call_args[0]
    assert args[0] is client.AppsV1Api
    assert args[1] == "list_deployment_for_all_namespaces"
    assert result["data"]["items"][0]["metadata"]["name"] == "pod-1"


def test_get_resource_validation(toolkit):
    result = toolkit.get_resource("pod", None, "pod-1")
    assert result["success"] is False
    assert result["error"]["code"] == "VALIDATION_ERROR"


def test_get_resource_pod(toolkit, fake_pod):
    toolkit._call.return_value = fake_pod

    result = toolkit.get_resource("pod", "default", "pod-1")

    assert result["success"] is True
    assert result["data"]["resource"]["metadata"]["name"] == "pod-1"
    args = toolkit._call.call_args[0]
    kwargs = toolkit._call.call_args[1]
    assert args[0] is client.CoreV1Api
    assert args[1] == "read_namespaced_pod"
    assert kwargs["namespace"] == "default"
    assert kwargs["name"] == "pod-1"


def test_get_events_with_field_selector(toolkit, fake_pod):
    fake_list = MagicMock()
    fake_list.items = [fake_pod]
    toolkit._call.return_value = fake_list

    result = toolkit.get_events("default", resource_name="pod-1")

    assert result["success"] is True
    kwargs = toolkit._call.call_args[1]
    assert kwargs["field_selector"] == "involvedObject.name=pod-1"
    assert kwargs["namespace"] == "default"


def test_get_logs(toolkit):
    toolkit._call.return_value = "log line one\nlog line two\n"

    result = toolkit.get_logs("default", "pod-1", container="app", tail_lines=50)

    assert result["success"] is True
    assert result["data"]["logs"] == "log line one\nlog line two\n"
    args = toolkit._call.call_args[0]
    kwargs = toolkit._call.call_args[1]
    assert args[0] is client.CoreV1Api
    assert args[1] == "read_namespaced_pod_log"
    assert kwargs["namespace"] == "default"
    assert kwargs["name"] == "pod-1"
    assert kwargs["container"] == "app"
    assert kwargs["tail_lines"] == 50


def test_get_owner_follows_references(toolkit):
    pod = MagicMock()
    pod.to_dict.return_value = {
        "metadata": {
            "name": "pod-1",
            "owner_references": [{"kind": "ReplicaSet", "name": "rs-1"}],
        }
    }
    rs = MagicMock()
    rs.to_dict.return_value = {"metadata": {"name": "rs-1"}}
    toolkit._call.side_effect = [pod, rs]

    result = toolkit.get_owner("pod", "default", "pod-1")

    assert result["success"] is True
    assert len(result["data"]["owners"]) == 1
    assert result["data"]["owners"][0]["metadata"]["name"] == "rs-1"


def test_get_rollout_status_deployment(toolkit):
    dep = MagicMock()
    dep.to_dict.return_value = {
        "spec": {"replicas": 3},
        "status": {
            "ready_replicas": 2,
            "updated_replicas": 3,
            "available_replicas": 2,
            "unavailable_replicas": 1,
        },
    }
    toolkit._call.return_value = dep

    result = toolkit.get_rollout_status("deployment", "default", "app")

    assert result["success"] is True
    assert result["data"]["desired"] == 3
    assert result["data"]["ready"] == 2
    assert result["data"]["updated"] == 3
    assert result["data"]["available"] == 2
    assert result["data"]["unavailable"] == 1


def test_patch_resource_dry_run(toolkit, fake_pod):
    toolkit._call.return_value = fake_pod
    patch = {"metadata": {"labels": {"x": "y"}}}

    result = toolkit.patch_resource("pod", "default", "pod-1", patch, dry_run=True)

    assert result["success"] is True
    assert result["tool"] == "patch_resource"
    kwargs = toolkit._call.call_args[1]
    assert kwargs["dry_run"] == ["All"]
    assert kwargs["body"] == patch
    assert kwargs["namespace"] == "default"
    assert kwargs["name"] == "pod-1"


def test_apply_resource_creates_when_missing(toolkit, fake_pod):
    exc = ApiException(status=404, reason="Not Found")
    toolkit._call.side_effect = [exc, fake_pod]

    manifest = {
        "kind": "Deployment",
        "apiVersion": "apps/v1",
        "metadata": {"name": "app", "namespace": "default"},
    }
    result = toolkit.apply_resource(manifest, dry_run=True)

    assert result["success"] is True
    assert result["data"]["action"] == "created"
    assert result["data"]["dry_run"] is True
    kwargs = toolkit._call.call_args[1]
    assert kwargs["dry_run"] == ["All"]
    assert kwargs["namespace"] == "default"
    assert kwargs["body"] == manifest


def test_apply_resource_patches_when_exists(toolkit, fake_pod):
    patched = MagicMock()
    patched.to_dict.return_value = {"metadata": {"name": "app", "labels": {"x": "y"}}}
    toolkit._call.side_effect = [fake_pod, patched]

    manifest = {
        "kind": "Deployment",
        "metadata": {"name": "app", "namespace": "default"},
    }
    result = toolkit.apply_resource(manifest)

    assert result["success"] is True
    assert result["data"]["action"] == "patched"
    assert result["data"]["resource"]["metadata"]["labels"]["x"] == "y"


def test_restart_workload(toolkit, fake_pod):
    toolkit._call.return_value = fake_pod

    result = toolkit.restart_workload("deployment", "default", "app", dry_run=True)

    assert result["success"] is True
    assert result["data"]["restarted_at"] is not None
    kwargs = toolkit._call.call_args[1]
    assert "kubectl.kubernetes.io/restartedAt" in kwargs["body"]["spec"]["template"]["metadata"]["annotations"]
    assert kwargs["dry_run"] == ["All"]


def test_rollback_workload(toolkit, fake_pod):
    toolkit._call.return_value = fake_pod

    result = toolkit.rollback_workload("deployment", "default", "app", dry_run=True)

    assert result["success"] is True
    args = toolkit._call.call_args[0]
    kwargs = toolkit._call.call_args[1]
    assert args[0] is client.AppsV1Api
    assert args[1] == "create_namespaced_deployment_rollback"
    assert args[2] == "app"
    assert args[3] == "default"
    assert kwargs["body"]["name"] == "app"
    assert kwargs["dry_run"] == ["All"]


def test_scale_workload(toolkit, fake_pod):
    toolkit._call.return_value = fake_pod

    result = toolkit.scale_workload("deployment", "default", "app", replicas=5, dry_run=True)

    assert result["success"] is True
    assert result["data"]["replicas"] == 5
    kwargs = toolkit._call.call_args[1]
    assert kwargs["body"]["spec"]["replicas"] == 5
    assert kwargs["dry_run"] == ["All"]


def test_scale_workload_unsupported_kind(toolkit):
    result = toolkit.scale_workload("pod", "default", "pod-1", replicas=1)
    assert result["success"] is False
    assert result["error"]["code"] == "UNSUPPORTED_KIND"


def test_restart_workload_unsupported_kind(toolkit):
    result = toolkit.restart_workload("namespace", "default", "ns-1")
    assert result["success"] is False
    assert result["error"]["code"] == "UNSUPPORTED_KIND"
