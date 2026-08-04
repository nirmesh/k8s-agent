import json
from datetime import datetime, timezone
from typing import Any

from backend.core.logging import logger
from backend.evidence.model import Evidence
from backend.providers.registry import ProviderRegistry, get_registry


class MCPHandler:
    """Minimal Model Context Protocol (MCP) JSON-RPC handler over any transport.

    Exposes all registered providers as MCP tools without changing investigator
    logic. Future providers are automatically available once registered.
    """

    PROTOCOL_VERSION = "2024-11-05"

    def __init__(self, registry: ProviderRegistry | None = None):
        self._registry = registry or get_registry()

    def handle(self, request: dict[str, Any] | str) -> dict[str, Any]:
        if isinstance(request, str):
            try:
                request = json.loads(request)
            except json.JSONDecodeError as exc:
                return self._error(None, -32700, f"Parse error: {exc}")

        req_id = request.get("id")
        method = request.get("method")
        params = request.get("params") or {}

        try:
            if method == "initialize":
                result = self._initialize()
            elif method == "tools/list":
                result = self._tools_list()
            elif method == "tools/call":
                result = self._tools_call(params)
            else:
                return self._error(req_id, -32601, f"Method not found: {method}")
        except Exception as exc:
            logger.exception("MCP handler error")
            return self._error(req_id, -32603, f"Internal error: {exc}")

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": result,
        }

    def _initialize(self) -> dict[str, Any]:
        return {
            "protocolVersion": self.PROTOCOL_VERSION,
            "serverInfo": {"name": "sre-agent-mcp", "version": "1.0.0"},
            "capabilities": {
                "tools": {},
                "logging": {},
            },
        }

    def _tools_list(self) -> dict[str, Any]:
        tools: list[dict[str, Any]] = []
        for tool in self._registry.tools():
            fn = tool.get("function") or {}
            tools.append(
                {
                    "type": "function",
                    "name": fn.get("name", "unknown"),
                    "description": fn.get("description", ""),
                    "inputSchema": fn.get("parameters", {"type": "object"}),
                }
            )
        return {"tools": tools}

    def _tools_call(self, params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if not name:
            raise ValueError("Missing tool name")
        result = self._registry.execute_tool(name, **arguments)
        text = self._serialize_result(result)
        return {
            "content": [
                {"type": "text", "text": text},
            ],
            "isError": False,
        }

    @staticmethod
    def _serialize_result(result: Any) -> str:
        if isinstance(result, Evidence):
            return json.dumps(
                {
                    "provider": result.provider,
                    "type": result.type,
                    "resource": result.resource,
                    "timestamp": (
                        result.timestamp.isoformat()
                        if isinstance(result.timestamp, datetime)
                        else result.timestamp
                    ),
                    "severity": result.severity,
                    "confidence": result.confidence,
                    "payload": _serialize_payload(result.payload),
                },
                default=str,
                ensure_ascii=False,
            )
        return json.dumps({"result": result}, default=str, ensure_ascii=False)

    def _error(self, req_id: Any, code: int, message: str) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": code, "message": message},
        }


def _serialize_payload(payload: Any) -> Any:
    if hasattr(payload, "model_dump"):
        return payload.model_dump(mode="json")
    if isinstance(payload, (dict, list, str, int, float, bool, type(None))):
        return payload
    return str(payload)
