# LangGraph Investigation Backend

## Architecture

The investigation path is now orchestrated by LangGraph:

```text
START
  |
collect_operational
  |
normalize_and_correlate
  |
collect_security
  |
diagnose
  |
END
```

The LLM is a synthesis layer only. It receives correlated operational incidents, not the raw cluster evidence list, and it cannot navigate Kubernetes or execute remediation.

## Why correlation is a separate stage

Raw Kubernetes observations are noisy. A single workload can produce several low-level observations:

- multiple Pods with the same ImagePullBackOff
- an image reference observation
- a readiness probe failure and its probe configuration
- a Deployment rollout condition caused by the same underlying failure

`normalize_and_correlate` turns these into one workload-level incident. A Deployment rollout failure is retained under `consequences` when a more-specific probe, image-pull, or scheduling incident exists for the same canonical workload. Otherwise the rollout failure remains an independent incident.

The LLM receives a compact `VERIFIED_INCIDENTS` payload. Raw operational evidence remains in graph state and is used to validate the model output and preserve auditability.

## Example

Raw evidence:

```text
readiness Pod -> probe_failure
readiness ReplicaSet -> probe_configuration
readiness Deployment -> deployment_rollout_failure
web Pod 1 -> image_pull_failure
web Pod 2 -> image_pull_failure
web ReplicaSet -> image_reference
web Deployment -> deployment_rollout_failure
```

LLM input:

```text
1. probe_failure: Deployment/ai-test/readiness-app
2. image_pull_failure: Deployment/default/web-app
```

The rollout signals and duplicate Pod observations remain attached to the relevant incident instead of becoming extra root causes.

## Runtime rule

All Kubernetes observations must come through `K8sToolkit` and the official Kubernetes Python client/API. The LangGraph LLM node has no Kubernetes tools and cannot call `kubectl`.

## Local development

The project is normally run with Docker Compose. A host-side Python installation is not required for the Compose deployment.

The LangGraph development server is exposed on port `2024` by the Compose `langgraph` service.

## Studio / tracing

LangGraph Studio connects to:

`https://smith.langchain.com/studio/?baseUrl=http://127.0.0.1:2024`

API docs:

`http://127.0.0.1:2024/docs`

For LangSmith traces, configure `LANGSMITH_API_KEY` and enable tracing in the environment used by the server.

## Graph registration

`langgraph.json` registers:

- graph id: `sre_investigation`
- implementation: `backend/agentic/graph.py:graph`
