# Migration Notes - Iteration 3 (Provider Framework + Prometheus)

## What changed

- New `backend/evidence/` package with `Evidence` model and `EvidenceGraph`.
- New `backend/providers/` package with `EvidenceProvider`, `ProviderRegistry`,
  `KubernetesProvider`, and `PrometheusProvider`.
- New `backend/observability/` package with `PrometheusClient` and `alertmanager`.
- `backend/ai/sre_agent.py` now builds its tool list from the `ProviderRegistry`
  and receives `Evidence` objects from tool execution.
- New `/metrics` API endpoint and `MetricsPanel` UI component.
- New `/alerts` API endpoint to receive Alertmanager webhooks.

## What did NOT change

- Planner, remediation, executor, approval, and verification logic are untouched.
- Kubernetes toolkit behavior is preserved.

## Configuration

- `PROMETHEUS_URL` (env or `.env`) defaults to `http://localhost:9090`.

## Running tests

```bash
docker compose run --rm backend python3 -B -m pytest tests -q
```

## Frontend

The Dashboard now renders a `MetricsPanel` section that calls `/metrics`.
