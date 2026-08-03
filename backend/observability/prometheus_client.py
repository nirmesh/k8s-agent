from typing import Any

import httpx

from backend.core.config import settings
from backend.core.logging import logger


class PrometheusClient:
    """Thin HTTP client for the Prometheus API."""

    def __init__(self, base_url: str | None = None, timeout: float = 10.0):
        self.base_url = (base_url or settings.prometheus_url).rstrip("/")
        self.timeout = timeout

    def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        try:
            response = httpx.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except Exception as exc:
            logger.warning(f"Prometheus request failed: {url} - {exc}")
            raise

    def query(self, promql: str, time: str | float | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {"query": promql}
        if time is not None:
            params["time"] = time
        return self._get("/api/v1/query", params=params)

    def query_range(
        self,
        promql: str,
        start: float,
        end: float,
        step: str | float,
    ) -> dict[str, Any]:
        return self._get(
            "/api/v1/query_range",
            params={"query": promql, "start": start, "end": end, "step": step},
        )

    def alerts(self) -> dict[str, Any]:
        return self._get("/api/v1/alerts")

    def targets(self) -> dict[str, Any]:
        return self._get("/api/v1/targets")

    def health(self) -> dict[str, Any]:
        try:
            response = httpx.get(f"{self.base_url}/-/healthy", timeout=self.timeout)
            response.raise_for_status()
            return {"healthy": True, "status": response.text.strip()}
        except Exception as exc:
            return {"healthy": False, "error": str(exc)}
