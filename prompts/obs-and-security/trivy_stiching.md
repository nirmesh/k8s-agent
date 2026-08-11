PR-013 — FIX TRIVY EVIDENCE FLOW END-TO-END

IMPORTANT:

Do NOT add Falco.
Do NOT add Kubescape.
Do NOT change the LLM.
Do NOT add another AI agent.
Do NOT change the security UI design.

We already have Trivy Operator installed in Kubernetes.

The following command returns real reports:

kubectl get vulnerabilityreports -A

Therefore Trivy is producing security evidence successfully.

CURRENT BUG

The "Investigate Cluster" UI shows:

Cluster Score: 100/100
Vulnerabilities: 0
Misconfigs: 0
Exposed Secrets: 0
Workloads: 0
"No security findings collected."

This is incorrect.

The existing cluster contains VulnerabilityReport CRDs.

The task is to trace and FIX the complete data path.

==================================================
1. TRACE THE DATA FLOW
==================================================

Trace:

Trivy Operator
→ Kubernetes VulnerabilityReport CRDs
→ Trivy/Security Provider
→ SecurityEvidence
→ Security Registry
→ Cluster Investigation
→ backend API response
→ frontend Security Findings

Do not assume where the problem is.

Find the exact point where the real findings become zero.

==================================================
2. VERIFY KUBERNETES API ACCESS
==================================================

Use the Kubernetes Python client.

Verify the backend can read:

group:
aquasecurity.github.io

CRD resources:

vulnerabilityreports
configauditreports
sbomreports
exposedsecretreports

Discover the actual installed CRD versions from the cluster rather
than blindly assuming a version.

Support all namespaces.

Do NOT use subprocess or shell out to kubectl.

Do NOT invoke the trivy CLI.

==================================================
3. ADD TEMPORARY STRUCTURED DIAGNOSTICS
==================================================

During investigation log:

trivy_reports_found
security_evidence_created
vulnerability_findings
misconfiguration_findings
secret_findings
workloads_with_security_findings

Example:

Trivy reports found: 12
Security evidence created: 147
Vulnerability findings: 140
Misconfiguration findings: 7
Workloads affected: 8

Never log secrets or sensitive payloads.

==================================================
4. VERIFY NORMALIZATION
==================================================

Every VulnerabilityReport must be converted into SecurityEvidence.

Do not silently discard findings because:

- severity == UNKNOWN
- target is empty
- package is missing
- resource name is unusual
- namespace is missing

Unknown severity must remain UNKNOWN.

==================================================
5. VERIFY WORKLOAD CORRELATION
==================================================

A Trivy report may belong to:

Pod
ReplicaSet
Deployment
DaemonSet
StatefulSet
Job
CronJob

Resolve the owning workload where possible.

Do NOT invent workload names.

If ownership cannot be resolved:

resource = the actual Trivy resource

Do not fabricate a workload.

==================================================
6. VERIFY CLUSTER INVESTIGATION
==================================================

The existing "Investigate Cluster" operation MUST invoke the
SecurityEvidence collection.

It currently appears that Kubernetes operational evidence is being
collected while security evidence is empty.

Fix this.

The cluster investigation must contain:

operationalEvidence
securityEvidence
securitySummary

==================================================
7. SECURITY SUMMARY
==================================================

Return real calculated values:

totalVulnerabilities
criticalVulnerabilities
highVulnerabilities
mediumVulnerabilities
lowVulnerabilities
unknownVulnerabilities
totalMisconfigurations
totalExposedSecrets
affectedWorkloads
affectedNamespaces

Do NOT default these values to zero.

Do NOT default cluster security score to 100.

If security data cannot be collected, the UI must say:

SECURITY DATA UNAVAILABLE

and explain why.

It must NEVER represent "unable to collect security evidence" as
"100/100 secure."

==================================================
8. SECURITY SCORE
==================================================

Do not invent a sophisticated AI security score yet.

For this PR use a deterministic score based on actual findings.

Document the formula.

Example:

start = 100

deduct based on severity

Critical > High > Medium > Low

The score must be reproducible from the findings.

If no findings exist because the scan was not available:

score = UNKNOWN

NOT 100.

==================================================
9. API CONTRACT
==================================================

Show the exact JSON returned by the backend for a cluster
investigation.

Example:

{
  "security": {
    "status": "AVAILABLE",
    "totalVulnerabilities": 12,
    "critical": 2,
    "high": 5,
    "medium": 4,
    "low": 1,
    "affectedWorkloads": 4,
    "affectedNamespaces": 2,
    "topRisks": [...]
  }
}

Do not hardcode this response.

==================================================
10. FRONTEND
==================================================

Verify that the frontend consumes the actual API response.

Do not create mock security findings.

Do not hardcode zero values.

If:

security.status == "AVAILABLE"

display the actual results.

If:

security.status == "UNAVAILABLE"

display a clear unavailable state.

==================================================
11. TEST
==================================================

Create an integration test representing the real situation:

VulnerabilityReport exists

↓

backend reads it

↓

SecurityEvidence created

↓

cluster investigation includes it

↓

API returns it

↓

security summary contains non-zero values

Also test:

No VulnerabilityReports

↓

Security status AVAILABLE

↓

0 findings

And:

Kubernetes API failure

↓

Security status UNAVAILABLE

↓

NOT 100/100

==================================================
12. ACCEPTANCE TEST

After implementation I should be able to run:

kubectl get vulnerabilityreports -A

and see existing reports.

Then click:

Investigate Cluster

and the UI MUST show non-zero security findings corresponding to
the actual cluster.

The implementation is NOT complete until this works.

==================================================
DELIVERABLE

At the end report:

1. Root cause of the zero findings.
2. Files changed.
3. Exact API endpoint changed.
4. Number of Trivy reports discovered.
5. Number of SecurityEvidence objects generated.
6. Example API response.
7. Tests added.
8. Commands used to verify the fix.

Do not claim success without demonstrating the complete data path.