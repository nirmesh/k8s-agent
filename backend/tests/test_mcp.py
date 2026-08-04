import json

import pytest

from backend.mcp.server import MCPHandler
from backend.providers.base import EvidenceProvider
from backend.providers.registry import ProviderRegistry


class FakeProvider(EvidenceProvider):
    @property
    def name(self):
        return "fake"

    def collect(self, query=None):
        return []

    def health(self):
        return {"healthy": True}

    def capabilities(self):
        return ["fake"]

    def tools(self):
        return [
            {
                "type": "function",
                "function": {
                    "name": "fake_tool",
                    "description": "A fake tool",
                    "parameters": {"type": "object"},
                },
            }
        ]

    def execute(self, tool, **kwargs):
        if tool == "fake_tool":
            return {"result": "ok"}
        raise NotImplementedError()


def test_initialize():
    registry = ProviderRegistry()
    handler = MCPHandler(registry)
    response = handler.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert response["id"] == 1
    assert "protocolVersion" in response["result"]


def test_tools_list():
    registry = ProviderRegistry()
    registry.register(FakeProvider())
    handler = MCPHandler(registry)
    response = handler.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert response["id"] == 2
    assert any(t["name"] == "fake_tool" for t in response["result"]["tools"])


def test_tools_call():
    registry = ProviderRegistry()
    registry.register(FakeProvider())
    handler = MCPHandler(registry)
    response = handler.handle(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "fake_tool", "arguments": {}},
        }
    )
    assert response["id"] == 3
    assert "content" in response["result"]


def test_handles_json_string():
    registry = ProviderRegistry()
    handler = MCPHandler(registry)
    response = handler.handle(json.dumps({"jsonrpc": "2.0", "id": 4, "method": "initialize"}))
    assert response["id"] == 4


def test_unknown_method():
    handler = MCPHandler(ProviderRegistry())
    response = handler.handle({"jsonrpc": "2.0", "id": 5, "method": "unknown"})
    assert "error" in response
    assert response["error"]["code"] == -32601
