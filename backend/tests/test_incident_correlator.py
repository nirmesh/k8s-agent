from backend.kubernetes.incident_correlator import correlate_incidents


def test_two_workloads_become_two_incidents_and_rollouts_are_consequences():
    evidence = [
        {
            "id": "probe-1",
            "signal": "probe_failure",
            "resource": "Pod/ai-test/readiness-pod",
            "related_resources": ["ReplicaSet/ai-test/readiness-rs"],
            "payload": {"probe_events": [{"message": "404"}]},
        },
        {
            "id": "probe-config-1",
            "signal": "probe_configuration",
            "resource": "ReplicaSet/ai-test/readiness-rs",
            "related_resources": ["Pod/ai-test/readiness-pod"],
            "payload": {"containers": [{"name": "nginx", "readiness": {"http_get": {"path": "/bad"}}}]},
        },
        {
            "id": "image-1",
            "signal": "image_pull_failure",
            "resource": "Pod/default/web-1",
            "related_resources": ["ReplicaSet/default/web-rs"],
            "payload": {"images": ["nginx:99.99"]},
        },
        {
            "id": "image-2",
            "signal": "image_pull_failure",
            "resource": "Pod/default/web-2",
            "related_resources": ["ReplicaSet/default/web-rs"],
            "payload": {"images": ["nginx:99.99"]},
        },
        {
            "id": "image-ref",
            "signal": "image_reference",
            "resource": "ReplicaSet/default/web-rs",
            "related_resources": ["Pod/default/web-1", "Pod/default/web-2"],
            "payload": {"containers": [{"name": "nginx", "image": "nginx:99.99"}]},
        },
        {
            "id": "rollout-readiness",
            "signal": "deployment_rollout_failure",
            "resource": "Deployment/ai-test/readiness-app",
            "related_resources": [],
            "payload": {"desired": 1, "ready": 0, "available": 0},
        },
        {
            "id": "rollout-web",
            "signal": "deployment_rollout_failure",
            "resource": "Deployment/default/web-app",
            "related_resources": ["ReplicaSet/default/web-rs"],
            "payload": {"desired": 2, "ready": 0, "available": 0},
        },
    ]

    incidents = correlate_incidents(evidence)
    assert len(incidents) == 2

    by_type = {item["type"]: item for item in incidents}
    assert set(by_type) == {"probe_failure", "image_pull_failure"}
    assert "rollout-readiness" in by_type["probe_failure"]["evidence_ids"]
    assert "rollout-web" in by_type["image_pull_failure"]["evidence_ids"]
    assert len([eid for eid in by_type["image_pull_failure"]["evidence_ids"] if eid.startswith("image-")]) == 3


def test_unrelated_rollout_is_kept_as_independent_incident():
    evidence = [
        {
            "id": "rollout-1",
            "signal": "deployment_rollout_failure",
            "resource": "Deployment/sre-lab/other-app",
            "related_resources": [],
            "payload": {"desired": 2, "ready": 0, "available": 0},
        }
    ]
    incidents = correlate_incidents(evidence)
    assert len(incidents) == 1
    assert incidents[0]["type"] == "deployment_rollout_failure"
