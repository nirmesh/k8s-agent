You are extending my existing Kubernetes SRE Investigator application.

CURRENT STATE

The application already:
- connects to a Kubernetes cluster
- investigates Kubernetes problems
- collects enough information to diagnose incidents
- sends evidence to a locally running Ollama instance
- uses llama3.2
- displays a Diagnosis UI containing:
  - root cause
  - explanation
  - suggested fix
  - kubectl command
  - prevention
  - confidence
  - recent investigations

DO NOT rebuild the existing application.

We are adding a controlled remediation system so the application evolves from:

DETECT -> INVESTIGATE -> DIAGNOSE

into:

DETECT
-> INVESTIGATE
-> DIAGNOSE
-> PROPOSE REMEDIATION
-> PREVIEW CHANGE
-> HUMAN APPROVAL
-> EXECUTE
-> VERIFY
-> ROLLBACK IF NEEDED
-> AUDIT

IMPORTANT ARCHITECTURE RULE:

Do NOT implement incident-specific functions such as:

fixImagePullBackOff()
fixCrashLoopBackOff()
fixOOMKilled()

We want generic Kubernetes capabilities that an LLM agent can use for many different incidents.

Implement generic read tools such as:

- get_resources
- get_resource
- get_events
- get_logs
- get_owner
- get_rollout_status

Implement controlled write tools such as:

- patch_resource
- apply_resource
- restart_workload
- rollback_workload
- scale_workload

The LLM must NEVER directly execute arbitrary shell commands.

The LLM may request a structured tool call.

Example:

{
  "tool": "patch_resource",
  "arguments": {
    "kind": "Deployment",
    "namespace": "default",
    "name": "broken-nginx",
    "patch": {}
  }
}

Read operations may execute automatically.

Write operations MUST go through:

LLM proposal
-> validation
-> risk classification
-> dry-run / preview
-> UI approval
-> execution
-> verification
-> audit

Use the Kubernetes client/library already appropriate for the project's backend language instead of shelling out to kubectl wherever practical.

Use the existing Ollama integration. Do not introduce Hermes, kagent, LangGraph, Trivy, kube-bench or another framework yet.

Before writing code:

1. inspect the existing repository
2. identify frontend/backend structure
3. identify existing Ollama integration
4. identify existing Kubernetes integration
5. identify diagnosis API and data model
6. propose the minimum files that need to change
7. preserve existing functionality

Then implement incrementally.

Do not create placeholder implementations.
Do not mock Kubernetes for the actual runtime.
Do not replace working existing functionality.

The first end-to-end target is:

broken Deployment
-> Investigator detects ImagePullBackOff
-> agent investigates using tools
-> proposes image change
-> UI shows before/after
-> user clicks Approve & Fix
-> backend patches Deployment
-> rollout is verified
-> UI shows RESOLVED

Do not start implementing other incident-specific fixes.