from typing import Any

import pytest

from backend.evidence.model import Evidence
from backend.providers.base import EvidenceProvider
from backend.providers.registry import ProviderRegistry


class FakeProvider(EvidenceProvider):
    def __init__(self, name: str):
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    def collect(self, query=None) -> list[Evidence]:
        return [Evidence(provider=self._name, type="test", resource="x", payload={})]

    def health(self) -> dict[str, Any]:
        return {"healthy": True}

    def capabilities(self) -> list[str]:
        return ["test"]

    def tools(self) -> list[dict[str, Any]]:
        return [
            {"type": "function", "function": {"name": "fake_tool", "description": "x", "parameters": {"type": "object"}}}
        ]

    def execute(self, tool: str, **kwargs) -> Evidence:
        if tool == "fake_tool":
            return Evidence(provider=self._name, type="tool_result", resource="x", payload={"tool": tool})
        raise NotImplementedError(tool)


def test_registry_register_and_list():
    registry = ProviderRegistry()
    registry.register(FakeProvider("a"))
    registry.register(FakeProvider("b"))
    assert registry.list() == ["a", "b"]


def test_registry_collect_all():
    registry = ProviderRegistry()
    registry.register(FakeProvider("a"))
    evidence = registry.collect_all()
    assert len(evidence) == 1
    assert evidence[0].provider == "a"


def test_registry_tools_and_execute():
    registry = ProviderRegistry()
    registry.register(FakeProvider("a"))
    assert "fake_tool" in registry.tool_names()
    result = registry.execute_tool("fake_tool")
    assert result.provider == "a"
    assert result.payload["tool"] == "fake_tool"


def test_registry_unknown_tool_raises():
    registry = ProviderRegistry()
    with pytest.raises(NotImplementedError):
        registry.execute_tool("missing")
