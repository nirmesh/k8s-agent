from __future__ import annotations

from typing import Any

from backend.evidence.security.model import SecurityDomain, SecurityLayer, SecurityEvidence, SecurityFinding


def _finding(
    *,
    rule_id: str,
    title: str,
    description: str,
    severity: str,
    resource: str = "cluster/-/-",
    domain: SecurityDomain = SecurityDomain.CLUSTER,
    recommendation: str,
    impact: str,
) -> SecurityEvidence:
    finding = SecurityFinding(
        category="misconfiguration",
        layer=SecurityLayer.POSTURE,
        domain=domain,
        source="kubernetes-posture",
        resource=resource,
        namespace=None,
        title=title,
        finding=title,
        description=description,
        severity=severity,
        recommendation=recommendation,
        remediation=recommendation,
        impact=impact,
        rule_id=rule_id,
        framework="Kubernetes Security Posture",
    )
    return SecurityEvidence(
        provider="kubernetes-posture",
        type="security",
        layer=SecurityLayer.POSTURE,
        domain=domain,
        source="kubernetes-posture",
        resource=resource,
        severity=severity,
        category="misconfiguration",
        title=title,
        description=description,
        recommendation=recommendation,
        impact=impact,
        payload=finding,
    )


def evaluate_cluster_posture(toolkit: Any) -> list[SecurityEvidence]:
    """Run deterministic, read-only Kubernetes security checks.

    This intentionally uses the Kubernetes API instead of a scanner binary so
    basic workload/control-plane risks remain available even when optional
    security tools are disabled.
    """
    findings: list[SecurityEvidence] = []

    # First prove that the Kubernetes API is reachable. Do not manufacture
    # posture findings when the cluster cannot be queried.
    try:
        api = toolkit.get_resources("node", None)
        if not api.get("success"):
            return findings
    except Exception:
        return findings

    # Inspect ALL pods across ALL namespaces. The previous implementation used
    # "pods" in kube-system, but K8sToolkit's canonical resource key is "pod".
    # That meant the API lookup returned nothing and a privileged workload such
    # as Pod/default/security-test-privileged was silently missed.
    try:
        pods = toolkit.get_resources("pod", None)
        if pods.get("success"):
            for pod in (pods.get("data") or {}).get("items") or []:
                meta = pod.get("metadata") or {}
                spec = pod.get("spec") or {}
                name = meta.get("name", "unknown")
                ns = meta.get("namespace", "default")
                resource = f"Pod/{ns}/{name}"

                if spec.get("hostNetwork"):
                    findings.append(_finding(
                        rule_id="K8S-POSTURE-HOSTNETWORK",
                        title="Pod uses hostNetwork",
                        description=f"{resource} shares the node network namespace.",
                        severity="HIGH",
                        resource=resource,
                        domain=SecurityDomain.NETWORK,
                        recommendation="Avoid hostNetwork unless the workload requires it; otherwise use normal pod networking.",
                        impact="A compromised workload can gain direct access to node-network services and bypass normal pod-network isolation.",
                    ))

                if spec.get("hostPID"):
                    findings.append(_finding(
                        rule_id="K8S-POSTURE-HOSTPID",
                        title="Pod uses hostPID",
                        description=f"{resource} shares the node process namespace.",
                        severity="HIGH",
                        resource=resource,
                        domain=SecurityDomain.RUNTIME,
                        recommendation="Remove hostPID unless explicitly required by the workload.",
                        impact="Process namespace sharing can expose host processes to a compromised workload.",
                    ))

                for container in spec.get("containers") or []:
                    security = container.get("securityContext") or {}
                    if security.get("privileged") is True:
                        cname = container.get("name", "unknown")
                        findings.append(_finding(
                            rule_id="K8S-POSTURE-PRIVILEGED",
                            title="Privileged container detected",
                            description=f"{resource} container {cname!r} runs with privileged=true.",
                            severity="CRITICAL",
                            resource=resource,
                            domain=SecurityDomain.WORKLOAD,
                            recommendation="Remove privileged=true and grant only the Linux capabilities actually required.",
                            impact="A privileged container can have near-host-level access and substantially increase container escape impact.",
                        ))
    except Exception:
        pass

    return findings
