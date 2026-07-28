import pytest

from backend.core.policy_engine import PolicyEngine


@pytest.fixture
def engine():
    return PolicyEngine()


@pytest.fixture
def fake_toolkit():
    class FakeToolkit:
        def get_resource(self, kind, namespace, name):
            exists = {
                ("namespace", None, "default"),
                ("deployment", "default", "app"),
                ("deployment", "default", "web"),
            }
            if (kind, namespace, name) in exists:
                return {"success": True, "data": {}}
            return {"success": False, "error": {"message": "not found"}}

    return FakeToolkit()


def _plan(tool, arguments, target):
    return {
        "tool": tool,
        "arguments": arguments,
        "target": target,
        "changes": arguments.get("changes", []),
    }


def test_restart_deployment_low_risk_requires_approval(engine, fake_toolkit):
    plan = _plan(
        "restart_workload",
        {},
        {"kind": "Deployment", "namespace": "default", "name": "app"},
    )
    diagnosis = {"affectedResources": ["Deployment/default/app"]}
    result = engine.validate(plan, diagnosis=diagnosis, toolkit=fake_toolkit)

    assert result["allowed"] is True
    assert result["risk"] == "LOW"
    assert result["approvalRequired"] is True
    assert result["violations"] == []


def test_scale_workload_medium_risk(engine, fake_toolkit):
    plan = _plan(
        "scale_workload",
        {"replicas": 3},
        {"kind": "Deployment", "namespace": "default", "name": "app"},
    )
    diagnosis = {"affectedResources": ["Deployment/default/app"]}
    result = engine.validate(plan, diagnosis=diagnosis, toolkit=fake_toolkit)

    assert result["allowed"] is True
    assert result["risk"] == "MEDIUM"
    assert result["approvalRequired"] is True


def test_patch_image_declared_field_allows(engine, fake_toolkit):
    plan = _plan(
        "patch_resource",
        {
            "patch": {
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                {"image": "nginx:1.25"}
                            ]
                        }
                    }
                }
            }
        },
        {"kind": "Deployment", "namespace": "default", "name": "app"},
    )
    plan["changes"] = [
        {"path": "spec.template.spec.containers.*.image"}
    ]
    diagnosis = {"affectedResources": ["Deployment/default/app"]}
    result = engine.validate(plan, diagnosis=diagnosis, toolkit=fake_toolkit)

    assert result["allowed"] is True
    assert result["risk"] == "MEDIUM"


def test_patch_undeclared_field_blocked(engine, fake_toolkit):
    plan = _plan(
        "patch_resource",
        {"patch": {"spec": {"replicas": 5}}},
        {"kind": "Deployment", "namespace": "default", "name": "app"},
    )
    plan["changes"] = [
        {"path": "spec.template.spec.containers.*.image"}
    ]
    diagnosis = {"affectedResources": ["Deployment/default/app"]}
    result = engine.validate(plan, diagnosis=diagnosis, toolkit=fake_toolkit)

    assert result["allowed"] is False
    assert any("undeclared field" in v for v in result["violations"])


def test_arbitrary_shell_blocked(engine):
    plan = _plan(
        "execute_shell",
        {"command": "rm -rf /"},
        {"kind": "Pod", "namespace": "default", "name": "x"},
    )
    result = engine.validate(plan)

    assert result["allowed"] is False
    assert result["risk"] == "CRITICAL"


def test_cluster_admin_modification_blocked(engine):
    plan = _plan(
        "patch_resource",
        {"patch": {"rules": []}},
        {"kind": "ClusterRole", "name": "cluster-admin"},
    )
    result = engine.validate(plan)

    assert result["allowed"] is False
    assert result["risk"] == "CRITICAL"


def test_namespace_missing_blocked(engine, fake_toolkit):
    plan = _plan(
        "restart_workload",
        {},
        {"kind": "Deployment", "namespace": "missing", "name": "app"},
    )
    diagnosis = {"affectedResources": ["Deployment/missing/app"]}
    result = engine.validate(plan, diagnosis=diagnosis, toolkit=fake_toolkit)

    assert result["allowed"] is False
    assert any("Namespace" in v for v in result["violations"])


def test_target_not_in_diagnosis_blocked(engine, fake_toolkit):
    plan = _plan(
        "restart_workload",
        {},
        {"kind": "Deployment", "namespace": "default", "name": "app"},
    )
    diagnosis = {"affectedResources": ["Deployment/default/web"]}
    result = engine.validate(plan, diagnosis=diagnosis, toolkit=fake_toolkit)

    assert result["allowed"] is False
    assert any("affected resources" in v for v in result["violations"])
