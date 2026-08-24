from backend.evidence.security.additional_sources import CLASSIC_FALCO_LINE, _control_items, _kubescape_failed


def test_classic_falco_warning_line_is_parsed():
    line = "13:14:27.811647863: Warning Sensitive file opened for reading (file=/etc/shadow k8s_ns=security-demo k8s_pod_name=privileged-demo)"
    match = CLASSIC_FALCO_LINE.match(line)
    assert match
    assert match.group("priority").upper() == "WARNING"
    assert "/etc/shadow" in match.group("output")


def test_kubescape_supports_status_controls_list():
    report = {
        "status": {
            "controls": [
                {"id": "C-001", "name": "Secrets encrypted", "status": "Failed"},
                {"id": "C-002", "name": "Something good", "status": "Passed"},
            ]
        }
    }
    controls = _control_items(report)
    assert len(controls) == 2
    assert _kubescape_failed(controls[0][1])
    assert not _kubescape_failed(controls[1][1])


def test_kubescape_supports_spec_controls_dict():
    report = {
        "spec": {
            "controls": {
                "C-001": {"name": "Privileged", "status": {"status": "failed"}},
            }
        }
    }
    controls = _control_items(report)
    assert controls[0][0] == "C-001"
    assert _kubescape_failed(controls[0][1])
