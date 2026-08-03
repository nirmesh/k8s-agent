from backend.observability.alertmanager import build_incident_description, parse_alerts


def test_parse_alerts():
    payload = {
        "alerts": [
            {"labels": {"alertname": "HighCPU"}, "annotations": {"summary": "cpu high"}}
        ]
    }
    alerts = parse_alerts(payload)
    assert len(alerts) == 1
    assert alerts[0]["labels"]["alertname"] == "HighCPU"


def test_build_incident_description():
    alert = {
        "labels": {"alertname": "HighCPU", "pod": "nginx"},
        "annotations": {"summary": "cpu high", "description": "usage > 80%"},
    }
    desc = build_incident_description(alert)
    assert "HighCPU" in desc
    assert "nginx" in desc
    assert "usage > 80%" in desc
