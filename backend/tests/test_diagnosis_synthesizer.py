from backend.ai.diagnosis_synthesizer import validate_diagnosis


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
