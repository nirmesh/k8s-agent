from __future__ import annotations

from typing import Any

from backend.evidence.security.model import SecurityDomain, SecurityLayer, SecurityEvidence, SecurityFinding


def _field(obj: dict[str, Any], name: str, default: Any = None) -> Any:
    """Read Kubernetes Python-client dicts regardless of snake/camel casing."""
    if name in obj:
        return obj[name]
    aliases = {
        "hostNetwork": "host_network",
        "hostPID": "host_pid",
        "securityContext": "security_context",
        "privileged": "privileged",
    }
    alias = aliases.get(name)
    if alias and alias in obj:
        return obj[alias]
    return default


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
    """Run deterministic, read-only Kubernetes security checks."""
    findings: list[SecurityEvidence] = []

    try:
        api = toolkit.get_resources("node", None)
        if not api.get("success"):
            return findings
    except Exception:
        return findings

    try:
        pods = toolkit.get_resources("pod", None)
        if not pods.get("success"):
            return findings

        for pod in (pods.get("data") or {}).get("items") or []:
            meta = pod.get("metadata") or {}
            spec = pod.get("spec") or {}
            name = meta.get("name", "unknown")
            ns = meta.get("namespace", "default")
            resource = f"Pod/{ns}/{name}"

            if _field(spec, "hostNetwork", False):
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

            if _field(spec, "hostPID", False):
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
                security = _field(container, "securityContext", {}) or {}
                if _field(security, "privileged", False) is True:
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
        return findings

    return findings
