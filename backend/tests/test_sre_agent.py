import json
from unittest.mock import MagicMock

import pytest
from backend.evidence.model import Evidence

from backend.ai.sre_agent import SREAgent, normalize_diagnosis


@pytest.fixture
def fake_chat():
    responses = []

    def _chat(*args, **kwargs):
        if not responses:
            return {
                "content": json.dumps({
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
            }
        return {"content": responses.pop(0)}

    _chat.responses = responses
    return _chat


@pytest.fixture
def toolkit():
    agent = SREAgent(_api_client=MagicMock())
    agent.registry.execute_tool = MagicMock(return_value=_make_evidence())
    return agent


def _make_evidence():
    return Evidence(
        provider="kubernetes",
        type="resource",
        resource="Pod/default/pod-1",
        payload={
            "kind": "pod",
            "namespace": "default",
            "items": [{"metadata": {"name": "pod-1"}}],
        },
    )


def test_diagnose_on_first_turn(toolkit, fake_chat, monkeypatch):
    monkeypatch.setattr("backend.ai.sre_agent.chat", fake_chat)
    progress = MagicMock()

    result = toolkit.run(incident_description="nginx is down", progress_callback=progress)

    assert result["status"] == "DIAGNOSED"
    assert result["rootCause"] == "Wrong image tag"
    progress.assert_any_call("AI Reasoning")
    progress.assert_any_call("Root Cause Found")


def test_max_iterations(toolkit, monkeypatch):
    namespace_iter = iter(f"ns-{i}" for i in range(20))

    def _fake(*args, **kwargs):
        return {
            "content": json.dumps({
                "action": "tool_call",
                "tool": "list_resources",
                "arguments": {
                    "kind": "pod",
                    "namespace": next(namespace_iter),
                },
            })
        }

    monkeypatch.setattr("backend.ai.sre_agent.chat", _fake)
    toolkit.registry.execute_tool = MagicMock(return_value=_make_evidence())
    progress = MagicMock()

    result = toolkit.run(progress_callback=progress)

    assert result["status"] == "UNKNOWN"
    assert toolkit.registry.execute_tool.call_count == 10


def test_invalid_tool_name(toolkit, fake_chat, monkeypatch):
    fake_chat.responses.append(json.dumps({
        "action": "tool_call",
        "tool": "run_shell",
        "arguments": {"command": "ls"},
    }))
    monkeypatch.setattr("backend.ai.sre_agent.chat", fake_chat)
    toolkit.registry.execute_tool = MagicMock(return_value=_make_evidence())

    result = toolkit.run()

    assert result["status"] == "DIAGNOSED"
    assert toolkit.registry.execute_tool.call_count == 0


def test_repeated_call_blocked(toolkit, fake_chat, monkeypatch):
    same_call = json.dumps({
        "action": "tool_call",
        "tool": "list_resources",
        "arguments": {"kind": "pod", "namespace": "default"},
    })
    fake_chat.responses.append(same_call)
    fake_chat.responses.append(same_call)
    monkeypatch.setattr("backend.ai.sre_agent.chat", fake_chat)
    toolkit.registry.execute_tool = MagicMock(return_value=_make_evidence())

    result = toolkit.run()

    assert result["status"] == "DIAGNOSED"
    # First call executes, second identical call is blocked before _call.
    assert toolkit.registry.execute_tool.call_count == 1


def test_invalid_json_then_diagnose(toolkit, fake_chat, monkeypatch):
    fake_chat.responses.append("not valid json")
    monkeypatch.setattr("backend.ai.sre_agent.chat", fake_chat)

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
