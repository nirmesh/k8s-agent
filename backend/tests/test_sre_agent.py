import json
from unittest.mock import MagicMock

import pytest

from backend.ai.sre_agent import SREAgent, normalize_diagnosis


@pytest.fixture
def fake_generate():
    responses = []

    def _generate(*args, **kwargs):
        if not responses:
            return json.dumps({
                "action": "diagnose",
                "diagnosis": {
                    "status": "DIAGNOSED",
                    "incidentType": "ImagePullBackOff",
                    "rootCause": "Wrong image tag",
                    "explanation": "The deployment references a non-existent image tag.",
                    "confidence": 0.95,
                    "affectedResources": ["Deployment/app"],
                    "evidence": [],
                },
            })
        return responses.pop(0)

    _generate.responses = responses
    return _generate


@pytest.fixture
def toolkit():
    return SREAgent(_api_client=MagicMock())


def _make_pod_list():
    fake_item = MagicMock()
    fake_item.to_dict.return_value = {"metadata": {"name": "pod-1"}}
    fake_list = MagicMock()
    fake_list.items = [fake_item]
    return fake_list


def test_diagnose_on_first_turn(toolkit, fake_generate, monkeypatch):
    monkeypatch.setattr("backend.ai.sre_agent.generate", fake_generate)
    progress = MagicMock()

    result = toolkit.run(incident_description="nginx is down", progress_callback=progress)

    assert result["status"] == "DIAGNOSED"
    assert result["rootCause"] == "Wrong image tag"
    progress.assert_any_call("AI Reasoning")
    progress.assert_any_call("Root Cause Found")


def test_max_iterations(toolkit, monkeypatch):
    namespace_iter = iter(f"ns-{i}" for i in range(20))

    def _fake(*args, **kwargs):
        return json.dumps({
            "action": "tool_call",
            "tool": "get_resources",
            "arguments": {
                "kind": "pod",
                "namespace": next(namespace_iter),
            },
        })

    monkeypatch.setattr("backend.ai.sre_agent.generate", _fake)
    toolkit.toolkit._call = MagicMock(return_value=_make_pod_list())
    progress = MagicMock()

    result = toolkit.run(progress_callback=progress)

    assert result["status"] == "UNKNOWN"
    assert toolkit.toolkit._call.call_count == 10


def test_invalid_tool_name(toolkit, fake_generate, monkeypatch):
    fake_generate.responses.append(json.dumps({
        "action": "tool_call",
        "tool": "run_shell",
        "arguments": {"command": "ls"},
    }))
    monkeypatch.setattr("backend.ai.sre_agent.generate", fake_generate)
    toolkit.toolkit._call = MagicMock(return_value=_make_pod_list())

    result = toolkit.run()

    assert result["status"] == "DIAGNOSED"
    assert toolkit.toolkit._call.call_count == 0


def test_repeated_call_blocked(toolkit, fake_generate, monkeypatch):
    same_call = json.dumps({
        "action": "tool_call",
        "tool": "get_resources",
        "arguments": {"kind": "pod", "namespace": "default"},
    })
    fake_generate.responses.append(same_call)
    fake_generate.responses.append(same_call)
    monkeypatch.setattr("backend.ai.sre_agent.generate", fake_generate)
    toolkit.toolkit._call = MagicMock(return_value=_make_pod_list())

    result = toolkit.run()

    assert result["status"] == "DIAGNOSED"
    # First call executes, second identical call is blocked before _call.
    assert toolkit.toolkit._call.call_count == 1


def test_invalid_json_then_diagnose(toolkit, fake_generate, monkeypatch):
    fake_generate.responses.append("not valid json")
    monkeypatch.setattr("backend.ai.sre_agent.generate", fake_generate)

    result = toolkit.run()

    assert result["status"] == "DIAGNOSED"


def test_normalize_diagnosis():
    camel = {
        "status": "DIAGNOSED",
        "incidentType": "CrashLoopBackOff",
        "rootCause": "bad cmd",
        "explanation": "x",
        "confidence": 0.8,
        "affectedResources": ["Pod/a"],
        "evidence": [{"source": "log", "description": "x", "value": "y"}],
    }
    norm = normalize_diagnosis(camel)
    assert norm["root_cause"] == "bad cmd"
    assert norm["incident_type"] == "CrashLoopBackOff"
    assert norm["confidence"] == 0.8
    assert norm["affected_resources"] == ["Pod/a"]
