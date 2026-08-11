from unittest.mock import MagicMock

import pytest

from backend.ai.remediation_planner import RemediationPlanner


@pytest.fixture
def planner():
    p = RemediationPlanner(_api_client=MagicMock())

    def _get_resource(kind, namespace, name):
        if name == "readiness-app":
            return {
                "success": True,
                "data": {
                    "resource": {
                        "metadata": {"name": "readiness-app", "namespace": "default"},
                        "spec": {
                            "replicas": 1,
                            "template": {
                                "spec": {
                                    "containers": [
                                        {
                                            "name": "nginx",
                                            "image": "nginx:1.29",
                                            "readinessProbe": {
                                                "httpGet": {
                                                    "path": "/this-path-does-not-exist",
                                                    "port": 80,
                                                }
                                            },
                                        }
                                    ]
                                }
                            },
                        },
                    }
                },
            }
        if name == "web-app":
            return {
                "success": True,
                "data": {
                    "resource": {
                        "metadata": {"name": "web-app", "namespace": "default"},
                        "spec": {
                            "replicas": 1,
                            "template": {
                                "spec": {
                                    "containers": [
                                        {"name": "nginx", "image": "nginx:99.99"}
                                    ]
                                }
                            },
                        },
                    }
                },
            }
        return {"success": False, "error": {"message": "not found"}}

    p.toolkit.get_resource = _get_resource
    p.toolkit.get_events = MagicMock(return_value={"success": True, "data": {"items": []}})
    return p


def _diagnosis():
    return {
        "status": "DIAGNOSED",
        "rootCauses": [
            {
                "id": "rc-readiness",
                "type": "READINESS_PROBE_FAILURE",
                "resource": "Deployment/default/readiness-app",
                "description": "Readiness probe failure",
                "evidence": [
                    {
                        "id": "ev-1",
                        "source": "get_events",
                        "description": "Readiness probe failed with HTTP 404",
                        "value": "Readiness probe failed: HTTP 404 on /this-path-does-not-exist:80",
                    }
                ],
            },
            {
                "id": "rc-image",
                "type": "IMAGE_PULL_FAILURE",
                "resource": "Deployment/default/web-app",
                "description": "ImagePullBackOff: container image nginx:99.99 does not exist",
                "evidence": [
                    {
                        "id": "ev-2",
                        "source": "get_events",
                        "description": "Back-off pulling image",
                        "value": "Back-off pulling image 'nginx:99.99'",
                    }
                ],
            },
        ],
    }


def test_two_independent_root_causes(planner):
    plan = planner.plan(_diagnosis())

    assert plan["status"] == "READY"
    candidates = plan["remediation_candidates"]
    assert len(candidates) == 2

    by_target = {
        c["target"]["name"]: c
        for c in candidates
    }

    assert "readiness-app" in by_target
    assert "web-app" in by_target

    readiness = by_target["readiness-app"]
    assert readiness["tool"] == "patch_resource"
    assert readiness["field_path"].endswith("readinessProbe.httpGet.path")
    assert readiness["current_value"] == "/this-path-does-not-exist"
    assert readiness["proposed_value"] == "/"
    assert "evidence_ids" in readiness
    assert "ev-1" in readiness["evidence_ids"]
    # The readiness-app image must never be changed.
    for change in readiness["changes"]:
        assert "image" not in change["path"]

    image = by_target["web-app"]
    assert image["tool"] == "patch_resource"
    assert image["field_path"].endswith(".image")
    assert image["proposed_value"] == "nginx:1.27"
    assert "ev-2" in image["evidence_ids"]
    # The web-app must not suggest a readiness probe change.
    for change in image["changes"]:
        assert "readinessProbe" not in change["path"]


def test_readiness_app_image_is_never_changed(planner):
    plan = planner.plan(_diagnosis())
    readiness = next(
        c for c in plan["remediation_candidates"] if c["target"]["name"] == "readiness-app"
    )
    assert all("image" not in c["path"] for c in readiness["changes"])
    assert readiness["proposed_value"] == "/"
