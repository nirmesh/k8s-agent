You are working on an existing project called AI SRE Decision Engine.

IMPORTANT

This is NOT a rewrite.

Do NOT replace existing architecture.

Build incrementally.

Current architecture already contains:

- Kubernetes investigation
- Investigation loop
- Planner
- Executor
- Approval
- Verification
- UI

We are entering Iteration 3.

=====================================================
GOAL
=====================================================

The agent currently reasons only over Kubernetes.

We need to extend it so that it can reason over:

- Kubernetes
- Metrics (Prometheus)

WITHOUT changing investigation logic.

The investigator should never know where evidence came from.

Instead it consumes Evidence objects.

=====================================================
PART 1
Evidence Provider Framework
=====================================================

Create

backend/providers/

base.py

registry.py

kubernetes_provider.py

EvidenceProvider interface

class EvidenceProvider

Methods

collect()

health()

capabilities()

All providers implement this.

=====================================================
PART 2
Evidence Model
=====================================================

Create

backend/evidence/model.py

Implement

Evidence

Fields

provider

type

resource

timestamp

confidence

severity

payload

Example

Evidence(
 provider="kubernetes",
 type="event",
 resource="Pod/nginx",
 confidence=1.0,
 payload={}
)

=====================================================
PART 3
Evidence Registry
=====================================================

Create

ProviderRegistry

Functions

register()

get()

list()

collect_all()

Investigator asks registry.

Registry asks providers.

=====================================================
PART 4
Refactor Kubernetes
=====================================================

Move existing Kubernetes collection

into

KubernetesProvider

No behaviour change.

No remediation change.

No UI change.

=====================================================
PART 5
Prometheus
=====================================================

Create

backend/providers/prometheus_provider.py

backend/observability/prometheus_client.py

Use Prometheus HTTP API

Support

query()

query_range()

alerts()

targets()

Return structured JSON only.

=====================================================
PART 6
Prometheus Tools
=====================================================

Expose investigator tools

query_metrics(promql)

query_metric(metric)

query_range()

get_alerts()

Do not auto query.

LLM decides.

=====================================================
PART 7
Investigator
=====================================================

Refactor investigator

Instead of

kubernetes.get()

events.get()

logs.get()

Use

ProviderRegistry

↓

collect evidence

↓

Evidence[]

↓

reason

No incident-specific code.

=====================================================
PART 8
Evidence Graph
=====================================================

Create

backend/evidence/graph.py

Initial implementation

Nodes

Evidence

Edges

resource relationships

No fancy graph DB.

Simple Python object graph.

=====================================================
PART 9
Metrics UI
=====================================================

Add Metrics tab

NOT Grafana iframe.

Native UI.

Cards

CPU

Memory

Latency

Error Rate

Restart Count

Alert State

Timeline

=====================================================
PART 10
Alertmanager
=====================================================

Create

backend/observability/alertmanager.py

Support

Receive Alert

↓

Create Incident

↓

Start Investigation

=====================================================
PART 11
Tests
=====================================================

Create tests

Mock Prometheus

Verify

Provider registration

Evidence creation

Registry

Metrics tools

Investigator

No Kubernetes regression.

=====================================================
RULES
=====================================================

DO NOT

Hardcode Prometheus logic.

Hardcode latency investigation.

Hardcode CPU investigation.

Everything goes through providers.

=====================================================
EXPECTED ARCHITECTURE
=====================================================

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

=====================================================
OUTPUT
=====================================================

Create commits.

Small commits.

Each commit compiles.

Run tests after every commit.

Update README.

Update ARCHITECTURE.md.

Generate migration notes.

Do not modify planner/remediation.

No breaking changes.