from fastapi import APIRouter, HTTPException, Query

from backend.core.logging import logger
from backend.observability.prometheus_client import PrometheusClient

router = APIRouter(prefix="/metrics", tags=["metrics"])


def _safe_query(client: PrometheusClient, promql: str):
    try:
        return client.query(promql)
    except Exception as exc:
        logger.warning(f"Prometheus query failed: {promql} - {exc}")
        return None


@router.get("")
def get_metrics(
    namespace: str | None = Query(default=None),
    pod: str | None = Query(default=None),
):
    """Return a structured metrics snapshot for a namespace/pod or the whole cluster.

    The endpoint queries Prometheus but does not hardcode any specific investigation.
    """
    client = PrometheusClient()
    labels = ""
    if namespace and pod:
        labels = f'namespace="{namespace}",pod="{pod}"'
    elif namespace:
        labels = f'namespace="{namespace}"'
    elif pod:
        labels = f'pod="{pod}"'

    label_filter = f"{{{labels}}}" if labels else ""

    cpu = _safe_query(client, f"rate(container_cpu_usage_seconds_total{label_filter}[5m])")
    memory = _safe_query(client, f"container_memory_usage_bytes{label_filter}")
    restart = _safe_query(client, f"increase(kube_pod_container_status_restarts_total{label_filter}[1h])")
    alerts = _safe_query(client, "ALERTS")

    return {
        "cpu": cpu,
        "memory": memory,
        "latency": None,
        "error_rate": None,
        "restart_count": restart,
        "alert_state": alerts,
        "timeline": [],
    }
