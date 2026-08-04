# PR-001 Security Evidence Platform

## Objective
Introduce a generic Security Provider framework.

## Deliverables
- SecurityProvider interface
- SecurityRegistry
- SecurityEvidence model
- Evidence normalization
- No scanner-specific logic

## Acceptance
- Existing Kubernetes functionality unchanged.
- All providers return SecurityEvidence.
