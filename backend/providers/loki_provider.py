from datetime import datetime, timezone
from typing import Any

import httpx

from backend.core.logging import logger
from backend.evidence.model import Evidence
from backend.providers.base import EvidenceProvider


_LOKI_TOOLS_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "query_logs",
            "description": "Query Grafana Loki for log lines matching a LogQL expression over a time range.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "LogQL query, e.g. {namespace=\"sre-lab\"} |= \"error\"."},
                    "start": {"type": ["string", "number", "null"], "description": "ISO timestamp or Unix seconds. Defaults to 1 hour ago."},
                    "end": {"type": ["string", "number", "null"], "description": "ISO timestamp or Unix seconds. Defaults to now."},
                    "limit": {"type": "integer", "default": 100},
                },
                "required": ["query"],
            },
        },
    },
]


class LokiClient:
    """Thin HTTP client for Grafana Loki."""

    def __init__(self, base_url: str = "http://localhost:3100"):
        self._base_url = base_url.rstrip("/")
        self._client = httpx.Client(base_url=self._base_url, timeout=20.0)

    def query_range(
        self,
        query: str,
        start: str | int | float | None = None,
        end: str | int | float | None = None,
        limit: int = 100,
    ) -> dict[str, Any] | None:
        if end is None:
            end_ns = int(datetime.now(timezone.utc).timestamp() * 1e9)
        else:
            end_ns = _to_ns(end)
        if start is None:
            start_ns = end_ns - int(3_600 * 1e9)
        else:
            start_ns = _to_ns(start)
        params = {
            "query": query,
            "start": str(start_ns),
            "end": str(end_ns),
            "limit": limit,
            "direction": "BACKWARD",
        }
        try:
            resp = self._client.get("/loki/api/v1/query_range", params=params)
            if resp.status_code == 200:
                return resp.json()
            logger.warning(f"Loki query returned {resp.status_code}: {resp.text[:200]}")
        except Exception as exc:
            logger.warning(f"Loki request failed: {exc}")
        return None

    def health(self) -> dict[str, Any]:
        try:
            resp = self._client.get("/ready")
            return {"healthy": resp.status_code == 200, "status": resp.status_code}
        except Exception as exc:
            return {"healthy": False, "error": str(exc)}


class LokiProvider(EvidenceProvider):
    """Provider that surfaces Loki log lines as evidence."""

    def __init__(self, client: LokiClient | None = None):
        self._client = client or LokiClient()

    @property
    def name(self) -> str:
        return "loki"

    def health(self) -> dict[str, Any]:
        return self._client.health()

    def capabilities(self) -> list[str]:
        return ["logs", "loki"]

    def tools(self) -> list[dict[str, Any]]:
        return _LOKI_TOOLS_SCHEMA

    def execute(self, tool: str, **kwargs) -> Evidence:
        if tool != "query_logs":
            raise NotImplementedError(f"Tool '{tool}' is not supported by the Loki provider")
        result = self._client.query_range(
            kwargs["query"],
            start=kwargs.get("start"),
            end=kwargs.get("end"),
            limit=kwargs.get("limit", 100),
        )
        return Evidence(
            provider=self.name,
            type="logs",
            resource=kwargs["query"],
            payload={"tool": tool, "arguments": kwargs, "result": result},
        )

    def collect(self, query: dict[str, Any] | None = None) -> list[Evidence]:
        query = query or {}
        logql = query.get("query") or "{namespace=~\".+\"}"
        data = self._client.query_range(
            logql,
            start=query.get("start"),
            end=query.get("end"),
            limit=query.get("limit", 100),
        )
        return self._normalize(data, logql)

    def _normalize(self, data: dict[str, Any] | None, query: str) -> list[Evidence]:
        if not data or not isinstance(data, dict):
            return []
        result = data.get("data", {}).get("result") or []
        evidence: list[Evidence] = []
        for stream in result:
            labels = stream.get("stream", {})
            resource = self._resource(labels, query)
            for ts_ns, line in stream.get("values") or []:
                try:
                    timestamp = datetime.fromtimestamp(int(ts_ns) / 1e9, tz=timezone.utc)
                except Exception:
                    timestamp = None
                evidence.append(
                    Evidence(
                        provider=self.name,
                        type="log",
                        resource=resource,
                        timestamp=timestamp,
                        payload={"labels": labels, "line": line, "query": query},
                    )
                )
        return evidence

    @staticmethod
    def _resource(labels: dict[str, str], query: str) -> str:
        namespace = labels.get("namespace") or "-"
        pod = labels.get("pod") or labels.get("instance") or "-"
        container = labels.get("container") or "-"
        if pod != "-":
            return f"Pod/{namespace}/{pod}/{container}"
        return f"logs/{query}"


def _to_ns(value: str | int | float | datetime) -> int:
    if isinstance(value, datetime):
        return int(value.timestamp() * 1e9)
    if isinstance(value, (int, float)):
        # Assume seconds if small, nanoseconds if very large.
        return int(value) if value > 1e12 else int(value * 1e9)
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return int(dt.timestamp() * 1e9)
        except Exception:
            try:
                num = float(value)
                return int(num) if num > 1e12 else int(num * 1e9)
            except Exception:
                return 0
    return 0
