# LangGraph Investigation Backend

## Architecture

The investigation path is now orchestrated by LangGraph:

`Kubernetes API evidence -> security evidence (separate) -> diagnosis synthesis -> evidence validation -> optional one-pass evidence expansion -> finish`

The LLM is a synthesis layer only. It does not navigate Kubernetes and it does not execute remediation.

Operational evidence is collected by `backend/kubernetes/investigation_engine.py`, using `K8sToolkit`. `K8sToolkit` is backed by the official Python Kubernetes client and Kubernetes API classes; this backend does not shell out to `kubectl`.

## Local development

From the repository root:

```bash
pip install -r backend/requirements.txt
export PYTHONPATH=.
langgraph dev
```

The LangGraph development server defaults to port `2024`.

## Studio / tracing

With `langgraph dev`, LangGraph prints the API, API docs, and Studio URL. The Studio URL for the default local server is:

`https://smith.langchain.com/studio/?baseUrl=http://127.0.0.1:2024`

API docs:

`http://127.0.0.1:2024/docs`

For LangSmith traces, configure `LANGSMITH_API_KEY` and enable tracing in the environment used by the server.

## Graph registration

`langgraph.json` registers:

- graph id: `sre_investigation`
- implementation: `backend/agentic/graph.py:graph`

## Kubernetes transport rule

All Kubernetes reads/writes must go through `K8sToolkit` and the Kubernetes API client. Do not add subprocess, shell, or `kubectl` execution to the backend Kubernetes layer.
