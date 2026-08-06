import json
from unittest.mock import MagicMock

import pytest

from backend.ai.remediation_planner import RemediationPlanner, ALLOWED_TOOLS


@pytest.fixture
def planner():
    p = RemediationPlanner(_api_client=MagicMock())
    p.toolkit.get_resource = MagicMock(
        return_value={
            "success": True,
            "data": {
                "metadata": {"name": "app", "namespace": "default"},
                "spec": {"replicas": 1},
            },
        }
    )
    return p


def _ready_plan():
    return {
        "status": "READY",
        "summary": "Scale deployment",
        "risk": "LOW",
        "tool": "scale_workload",
        "arguments": {
            "kind": "deployment",
            "namespace": "default",
            "name": "app",
            "replicas": 1,
        },
        "target": {
            "kind": "deployment",
            "namespace": "default",
            "name": "app",
        },
        "changes": [
            {"path": "spec.replicas", "before": "1", "after": "3"}
        ],
        "reason": "Scale to handle load",
        "verification": {"type": "rollout_status", "expected": "ready"},
        "rollback": {"available": True, "strategy": "scale back to 1"},
    }


def test_ready_plan(planner, monkeypatch):
    monkeypatch.setattr(
        "backend.ai.remediation_planner.generate",
        lambda *args, **kwargs: json.dumps(_ready_plan()),
    )
    diagnosis = {
        "status": "DIAGNOSED",
        "rootCause": "Under-provisioned",
        "affectedResources": ["Deployment/default/app"],
        "evidence": [],
    }
    plan = planner.plan(diagnosis)
    assert plan["status"] == "READY"
    assert plan["tool"] == "scale_workload"
    assert plan["target"]["name"] == "app"


def test_need_user_input_rejected(planner, monkeypatch):
    monkeypatch.setattr(
        "backend.ai.remediation_planner.generate",
        lambda *args, **kwargs: json.dumps({
            "status": "NEED_USER_INPUT",
            "question": "Please provide the correct image tag",
        }),
    )
    diagnosis = {
        "status": "DIAGNOSED",
        "rootCause": "ImagePullBackOff",
        "affectedResources": ["Deployment/default/app"],
        "evidence": [],
    }
    plan = planner.plan(diagnosis)
    assert plan["status"] == "NO_SAFE_REMEDIATION"


def test_no_affected_resources(planner):
    diagnosis = {
        "status": "DIAGNOSED",
        "rootCause": "Unknown",
        "affectedResources": [],
        "evidence": [],
    }
    plan = planner.plan(diagnosis)
    assert plan["status"] == "NO_SAFE_REMEDIATION"


def test_invalid_tool(planner, monkeypatch):
    bad = _ready_plan()
    bad["tool"] = "run_shell"
    monkeypatch.setattr(
        "backend.ai.remediation_planner.generate",
        lambda *args, **kwargs: json.dumps(bad),
    )
    diagnosis = {
        "status": "DIAGNOSED",
        "rootCause": "x",
        "affectedResources": ["Deployment/default/app"],
        "evidence": [],
    }
    plan = planner.plan(diagnosis)
    assert plan["status"] == "NO_SAFE_REMEDIATION"


def test_invalid_arguments(planner, monkeypatch):
    bad = _ready_plan()
    bad["tool"] = "patch_resource"
    bad["arguments"] = {
        "kind": "deployment",
        "namespace": "default",
        "name": "app",
    }
    monkeypatch.setattr(
        "backend.ai.remediation_planner.generate",
        lambda *args, **kwargs: json.dumps(bad),
    )
    diagnosis = {
        "status": "DIAGNOSED",
        "rootCause": "x",
        "affectedResources": ["Deployment/default/app"],
        "evidence": [],
    }
    plan = planner.plan(diagnosis)
    assert plan["status"] == "NO_SAFE_REMEDIATION"


def test_invalid_json(planner, monkeypatch):
    monkeypatch.setattr(
        "backend.ai.remediation_planner.generate",
        lambda *args, **kwargs: "not json",
    )
    diagnosis = {
        "status": "DIAGNOSED",
        "rootCause": "x",
        "affectedResources": ["Deployment/default/app"],
        "evidence": [],
    }
    plan = planner.plan(diagnosis)
    assert plan["status"] == "NO_SAFE_REMEDIATION"


def test_unparseable_affected(planner):
    diagnosis = {
        "status": "DIAGNOSED",
        "rootCause": "x",
        "affectedResources": ["garbage"],
        "evidence": [],
    }
    plan = planner.plan(diagnosis)
    assert plan["status"] == "NO_SAFE_REMEDIATION"


def test_image_tag_fallback(planner, monkeypatch):
    planner.toolkit.get_resource = MagicMock(
        return_value={
            "success": True,
            "data": {
                "metadata": {"name": "web-app", "namespace": "default"},
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                {"name": "nginx", "image": "nginx:99.99"}
                            ]
                        }
                    }
                },
            },
        }
    )
    monkeypatch.setattr(
        "backend.ai.remediation_planner.generate",
        lambda *args, **kwargs: json.dumps({"status": "NO_SAFE_REMEDIATION"}),
    )
    diagnosis = {
        "status": "DIAGNOSED",
        "rootCause": "ImagePullBackOff: container image nginx:99.99 cannot be pulled",
        "affectedResources": ["Deployment/default/web-app"],
        "evidence": [],
    }
    plan = planner.plan(diagnosis)
    assert plan["status"] == "READY"
    assert plan["tool"] == "patch_resource"
    assert plan["arguments"]["patch"]["spec"]["template"]["spec"]["containers"][0]["image"] == "nginx"


def test_allowed_tools_list():
    assert "patch_resource" in ALLOWED_TOOLS
    assert "scale_workload" in ALLOWED_TOOLS
    assert "run_shell" not in ALLOWED_TOOLS
