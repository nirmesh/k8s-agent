from backend.evidence.security.additional_sources import (
    CLASSIC_FALCO_LINE,
    _control_items,
    _kubescape_failed,
    _parse_falco_line,
)


def test_classic_falco_warning_line_is_parsed():
    line = "13:14:27.811647863: Warning Sensitive file opened for reading (file=/etc/shadow k8s_ns=security-demo k8s_pod_name=privileged-demo)"
    match = CLASSIC_FALCO_LINE.match(line)
    assert match
    assert match.group("priority").upper() == "WARNING"
    assert "/etc/shadow" in match.group("output")


def test_falco_json_output_with_embedded_warning_is_parsed():
    line = '{"hostname":"nirmesh","output":"06:37:43.346545985: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=systemd evt_type=open user=root process=cat container_name=app"}'
    rule, output, priority, resource, classic = _parse_falco_line(line, "falco", "falco-abc")
    assert priority == "WARNING"
    assert rule.startswith("Sensitive file opened for reading by non-trusted program")
    assert "/etc/shadow" in output
    assert resource == "Pod/falco/falco-abc"
    assert classic


def test_falco_embedded_warning_is_parsed_even_when_line_is_not_valid_json():
    line = 'prefix: {"hostname":"nirmesh","output":"06:37:43.346545985: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow container_id=8b8675d6efc1"}'
    rule, output, priority, resource, classic = _parse_falco_line(line, "falco", "falco-abc")
    assert priority == "WARNING"
    assert rule.startswith("Sensitive file opened for reading by non-trusted program")
    assert "/etc/shadow" in output
    assert classic


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
