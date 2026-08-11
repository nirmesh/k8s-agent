PR-012 – AI Security Investigation

Current state

- Trivy Operator is installed.
- VulnerabilityReport CRDs are populated.
- The backend has Kubernetes access.

The problem is NOT scanning.

The problem is consuming and presenting security evidence.

========================================================

GOAL

========================================================

The existing "Investigate Cluster" button must become a complete cluster investigation.

Investigation should include BOTH:

1. Operational investigation
2. Security investigation

The user should not run a separate Trivy scan.

========================================================

STEP 1

Create SecurityEvidenceCollector.

It should read from Kubernetes CRDs:

- VulnerabilityReport
- ConfigAuditReport
- SbomReport
- ExposedSecretReport

Do NOT execute the trivy CLI.

Use Kubernetes API only.

========================================================

STEP 2

Normalize every finding into:

SecurityEvidence

Fields

provider
resource
namespace
severity
category
title
description
recommendation
references
payload
timestamp

========================================================

STEP 3

Cluster Investigation

When "Investigate Cluster" is pressed:

Collect

- Pods
- Deployments
- Services
- Events
- Nodes
- PVCs
- SecurityEvidence

Create one InvestigationResult.

========================================================

STEP 4

Prioritize findings.

DO NOT display every CVE.

Group findings by workload.

Example

payment-api

Critical CVEs: 5

High CVEs: 12

Misconfigurations: 3

Risk Score: 94

Recommendation:
Upgrade image.

------------------------------------------------

gpu-operator

Critical CVEs: 4

Internet Facing: No

Risk Score: 38

Recommendation:
Monitor. Upgrade during maintenance.

========================================================

STEP 5

Implement AI prioritization.

The investigator should answer:

- Which workloads need attention first?
- Which findings can wait?
- Which findings are informational?

Never sort purely by CVSS.

Use:

- Criticality
- Namespace
- Internet exposure
- Privileged container
- HostNetwork
- Number of replicas
- Running status
- Workload type

========================================================

STEP 6

Security Summary

Return

Cluster Security Score

Critical Workloads

High Risk Namespaces

Top 10 Risks

Top Recommendations

Misconfiguration Count

Vulnerability Count

========================================================

STEP 7

UI

Investigate Cluster

↓

Overview

Operational Findings

Security Findings

Recommendations

Verification

Security Findings should show

- Risk Score
- Workload
- Summary
- Recommendation

NOT raw CVEs.

Users can expand a workload to view the underlying CVEs.

========================================================

STEP 8

LLM Prompt

The investigator should receive

OperationalEvidence

+

SecurityEvidence

Prompt:

You are an SRE and Kubernetes Security Engineer.

Prioritize findings.

Explain WHY a workload is risky.

Recommend only actionable remediation.

Never list CVEs unless specifically requested.

Focus on business impact.

========================================================

STEP 9

Acceptance Criteria

When the user clicks "Investigate Cluster":

- Security findings are automatically included.
- No separate security scan button.
- Top risks are prioritized.
- Recommendations are actionable.
- Raw CVEs are hidden by default.
- Investigation combines operational and security evidence.