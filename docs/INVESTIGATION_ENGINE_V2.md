# Investigation Engine v2

This document defines the investigation-only architecture.

## Principle

Kubernetes providers discover and normalize verified facts. The LLM explains relationships between verified facts. The LLM is not the primary Kubernetes API navigator and must not invent a fix, resource, image tag, selector, or configuration value.

## Pipeline

1. Collect deterministic operational signals.
2. For every signal, collect the smallest evidence set needed to verify it.
3. Normalize evidence with stable resource identity and signal metadata.
4. Correlate only evidence that shares an explicit workload/resource relationship.
5. Ask the LLM for diagnosis synthesis from the verified evidence bundle.
6. Validate the returned diagnosis against the evidence before exposing it.

## Investigation scope

The first implementation covers:

- image pull failures / invalid image references
- readiness and liveness probe failures
- scheduling failures
- deployment rollout failures
- service selector / endpoint failures
- PVC binding failures
- unhealthy pod/container states
- warning events associated with the affected resource

Security scanner findings remain a separate evidence domain. A security finding must not become an operational root cause merely because it exists in the same cluster.

## No remediation

This pipeline does not execute remediation. It also does not generate an automatic remediation plan as part of investigation. Remediation is a later, explicitly approved phase.

## LLM contract

The model receives verified evidence and returns a diagnosis. It must:

- use only evidence in the bundle
- identify the exact affected workload/resource
- distinguish multiple independent incidents
- report NEED_MORE_EVIDENCE when facts conflict or are insufficient
- never invent a suggested image tag, selector, probe path, command, or patch

The backend validates affected resources and evidence references before accepting the diagnosis.
