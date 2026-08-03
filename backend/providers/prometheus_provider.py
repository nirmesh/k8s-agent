from typing import Any

from backend.core.logging import logger
from backend.evidence.model import Evidence
from backend.observability.prometheus_client import PrometheusClient
from backend.providers.base import EvidenceProvider


_PROMETHEUS_TOOLS_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "query_metrics",
            "description": "Execute an arbitrary PromQL query against Prometheus and return vector/range results.",
            "parameters": {
                "type": "object",
                "properties": {
                    "promql": {"type": "string", "description": "The PromQL expression to evaluate."},
                    "time": {"type": ["string", "number", "null"], "description": "Optional evaluation timestamp."},
                },
                "required": ["promql"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_metric",
            "description": "Query a single metric name with optional label filters. Shorthand for a simple PromQL query.",
            "parameters": {
                "type": "object",
                "properties": {
                    "metric": {"type": "string", "description": "The metric name, e.g. container_cpu_usage_seconds_total."},
                    "filters": {"type": "object", "description": "Optional label matchers, e.g. {\"pod\":\"nginx\"}."},
                    "time": {"type": ["string", "number", "null"], "description": "Optional evaluation timestamp."},
                },
                "required": ["metric"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_range",
            "description": "Execute a PromQL range query over a time window.",
            "parameters": {
                "type": "object",
                "properties": {
                    "promql": {"type": "string"},
                    "start": {"type": "number"},
                    "end": {"type": "number"},
                    "step": {"type": ["string", "number"]},
                },
                "required": ["promql", "start", "end", "step"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_alerts",
            "description": "List current active alerts from Prometheus (not Alertmanager).",
            "parameters": {"type": "object", "properties": {}},
        },
    },
]


class PrometheusProvider(EvidenceProvider):
    """Provider that surfaces Prometheus metrics and alerts as evidence."""

    def __init__(self, client: PrometheusClient | None = None):
        self._client = client or PrometheusClient()

    @property
    def name(self) -> str:
        return "prometheus"

    def health(self) -> dict[str, Any]:
        return self._client.health()

    def capabilities(self) -> list[str]:
        return ["metrics", "alerts", "promql"]

    def tools(self) -> list[dict[str, Any]]:
        return _PROMETHEUS_TOOLS_SCHEMA

    def _promql_with_filters(self, metric: str, filters: dict[str, Any] | None) -> str:
        if not filters:
            return metric
        matchers = ",".join(f'{k}="{v}"' for k, v in filters.items())
        return f"{metric}{{{matchers}}}"

    def execute(self, tool: str, **kwargs) -> Evidence:
        if tool == "query_metrics":
            result = self._client.query(kwargs["promql"], time=kwargs.get("time"))
        elif tool == "query_metric":
            promql = self._promql_with_filters(kwargs["metric"], kwargs.get("filters"))
            result = self._client.query(promql, time=kwargs.get("time"))
        elif tool == "query_range":
            result = self._client.query_range(
                kwargs["promql"],
                kwargs["start"],
                kwargs["end"],
                kwargs["step"],
            )
        elif tool == "get_alerts":
            result = self._client.alerts()
        else:
            raise NotImplementedError(f"Tool '{tool}' is not supported by the Prometheus provider")

        return Evidence(
            provider=self.name,
            type="metric",
            resource=kwargs.get("metric") or kwargs.get("promql", "prometheus"),
            payload={"tool": tool, "arguments": kwargs, "result": result},
        )

    def collect(self, query: dict[str, Any] | None = None) -> list[Evidence]:
        """Collect active Prometheus alerts as evidence by default."""
        try:
            alerts = self._client.alerts()
            data = alerts.get("data", {})
            alert_list = data.get("alerts") if isinstance(data, dict) else []
            evidence = []
            for alert in alert_list or []:
                labels = alert.get("labels", {})
                resource = f"Alert/{labels.get('alertname', 'unknown')}"
                evidence.append(
                    Evidence(
                        provider=self.name,
                        type="alert",
                        resource=resource,
                        confidence=1.0 if alert.get("state") == "firing" else 0.8,
                        severity=labels.get("severity"),
                        payload=alert,
                    )
                )
            return evidence
        except Exception as exc:
            logger.warning(f"Prometheus collection failed: {exc}")
            return []
