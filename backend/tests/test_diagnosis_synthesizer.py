from backend.ai.diagnosis_synthesizer import ensure_complete_findings, validate_diagnosis


def _evidence(signal, resource, related=None):
    return {"id": f"{signal}-1", "signal": signal, "resource": resource, "related_resources": related or []}


def test_readiness_cannot_use_image_evidence():
    evidence = [_evidence("probe_failure", "Pod/ai-test/readiness-pod"), _evidence("probe_configuration", "Deployment/ai-test/readiness-app", ["Pod/ai-test/readiness-pod"])]
    result = {"findings": [{"incident_type": "image_pull_failure", "root_cause": "Image is wrong", "affected_resources": ["Deployment/ai-test/readiness-app"], "evidence_ids": ["probe_configuration-1"], "confidence": 0.99}]}
    validated = validate_diagnosis(result, evidence)
    assert validated["findings"] == []
    assert validated["status"] == "NEED_MORE_EVIDENCE"


def test_service_diagnosis_must_be_resource_grounded():
    evidence = [_evidence("service_routing_failure", "Service/sre-lab/web-service")]
    result = {"findings": [{"incident_type": "service_selector_mismatch", "root_cause": "Selector has no matching pods", "affected_resources": ["Service/sre-lab/other-service"], "evidence_ids": ["service_routing_failure-1"], "confidence": 0.95}]}
    assert validate_diagnosis(result, evidence)["findings"] == []


def test_multiple_independent_findings_are_preserved():
    evidence = [_evidence("probe_failure", "Pod/ai-test/readiness-pod"), _evidence("image_pull_failure", "Pod/default/broken-pod")]
    result = {"findings": [
        {"incident_type": "readiness_probe_failure", "root_cause": "Probe returned 404", "affected_resources": ["Pod/ai-test/readiness-pod"], "evidence_ids": ["probe_failure-1"], "confidence": 0.96},
        {"incident_type": "image_pull_failure", "root_cause": "Image pull failed", "affected_resources": ["Pod/default/broken-pod"], "evidence_ids": ["image_pull_failure-1"], "confidence": 0.97},
    ]}
    validated = validate_diagnosis(result, evidence)
    assert len(validated["findings"]) == 2
    assert validated["status"] == "DIAGNOSED"


def test_missing_independent_deployment_incident_is_added_deterministically():
    evidence = [
        _evidence("probe_failure", "Pod/ai-test/readiness-pod"),
        _evidence("probe_configuration", "Deployment/ai-test/readiness-app", ["Pod/ai-test/readiness-pod"]),
        _evidence("image_pull_failure", "Pod/default/broken-pod", ["Deployment/default/web-app"]),
        _evidence("image_reference", "Deployment/default/web-app", ["Pod/default/broken-pod"]),
        _evidence("deployment_rollout_failure", "Deployment/default/web-app"),
    ]
    llm_result = {
        "status": "DIAGNOSED",
        "findings": [{
            "incident_type": "readiness_probe_failure",
            "root_cause": "Probe returned 404",
            "affected_resources": ["Pod/ai-test/readiness-pod"],
            "evidence_ids": ["probe_failure-1"],
            "confidence": 0.96,
        }],
    }
    validated = validate_diagnosis(llm_result, evidence)
    complete = ensure_complete_findings(validated, evidence)
    assert len(complete["findings"]) == 2
    assert any(f["incident_type"] == "image_pull_failure" for f in complete["findings"])
    assert not any(f["incident_type"] == "deployment_rollout_failure" for f in complete["findings"])
    image_finding = next(f for f in complete["findings"] if f["incident_type"] == "image_pull_failure")
    assert image_finding["affected_resources"] == ["Deployment/default/web-app"]
