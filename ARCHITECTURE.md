# AI SRE Decision Engine - Architecture

## Overview

The AI SRE Decision Engine is an incremental, provider-based reasoning system.

```text
             Investigator
                    │
          Provider Registry
    ┌──────────────┴──────────────┐
 Kubernetes Provider     Prometheus Provider
    │                               │
 Evidence[]                   Evidence[]
    └──────────────┬──────────────┘
                   │
           Evidence Graph
                   │
              Root Cause
```

## Core Components

### Evidence (`backend/evidence/`)

- `model.py`: `Evidence` Pydantic model normalizes every observation.
- `graph.py`: `EvidenceGraph` relates Evidence by shared resources.

### Providers (`backend/providers/`)

- `base.py`: `EvidenceProvider` interface.
- `registry.py`: `ProviderRegistry` discovers and routes tool calls.
- `kubernetes_provider.py`: Wraps `K8sToolkit` for Kubernetes evidence/tools.
- `prometheus_provider.py`: Wraps `PrometheusClient` for metrics/alerts.

### Observability (`backend/observability/`)

- `prometheus_client.py`: HTTP client for Prometheus API.
- `alertmanager.py`: Parses Alertmanager webhooks into incident descriptions.

### Investigator (`backend/ai/sre_agent.py`)

The `SREAgent` consumes `Evidence` objects and no longer directly depends on
Kubernetes. It routes tool calls through the `ProviderRegistry`, so Prometheus
queries are treated the same as Kubernetes read tools.

### API (`backend/api/routes/`)

- `metrics.py`: Native metrics endpoint that queries Prometheus on demand.
- `alertmanager.py`: Webhook receiver that creates investigations.

### UI (`frontend/components/`)

- `MetricsPanel.tsx`: Native metrics cards (CPU, Memory, etc.) and refresh.

## Design Rules

- No hardcoded Prometheus logic.
- No hardcoded latency/CPU investigation.
- All evidence flows through providers.
- Existing planner, remediation, approval, and verification are unchanged.
