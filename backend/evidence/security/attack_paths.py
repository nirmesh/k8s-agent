from __future__ import annotations

from typing import Any


def _findings(summary: dict[str, Any]) -> list[dict[str, Any]]:
    return summary.get("native_posture_findings") or []


def _rules(summary: dict[str, Any]) -> set[str]:
    return {str(f.get("rule_id")) for f in _findings(summary) if f.get("rule_id")}


def _workload_findings(summary: dict[str, Any], namespace: str, name: str) -> list[dict[str, Any]]:
    return [f for f in _findings(summary) if f.get("resource") == f"Pod/{namespace}/{name}"]


def _path(path_id: str, title: str, severity: str, score: int, summary: str, steps: list[dict[str, str]], evidence: list[str], blast_radius: dict[str, int], recommendation: str) -> dict[str, Any]:
    return {
        "id": path_id,
        "title": title,
        "severity": severity,
        "risk_score": score,
        "summary": summary,
        "steps": steps,
        "evidence": evidence,
        "blast_radius": blast_radius,
        "recommendation": recommendation,
    }


def build_attack_paths(summary: dict[str, Any]) -> dict[str, Any]:
    """Correlate already-verified security evidence into deterministic attack paths.

    This intentionally does not claim exploitation. A path means that multiple
    independently verified conditions can combine to increase compromise impact.
    The LLM is not used to invent relationships.
    """
    findings = _findings(summary)
    rules = _rules(summary)
    workloads = summary.get("top_10_risks") or []
    paths: list[dict[str, Any]] = []

    # Workload -> node: privileged application workload exposed to the network.
    for workload in workloads:
        ns, name = str(workload.get("namespace") or "default"), str(workload.get("name") or "")
        if not name or not workload.get("internet_facing") or not workload.get("privileged"):
            continue
        resource_findings = _workload_findings(summary, ns, name)
        privileged = next((f for f in resource_findings if f.get("rule_id") == "K8S-POSTURE-PRIVILEGED"), None)
        if not privileged:
            continue
        paths.append(_path(
            f"AP-WORKLOAD-NODE-{ns}-{name}",
            "Internet-facing privileged workload can increase node compromise impact",
            "CRITICAL", 95,
            f"Pod/{ns}/{name} is internet-facing and runs a privileged container. These conditions can combine to make application compromise materially more dangerous.",
            [
                {"label": "Internet-facing workload", "resource": f"Pod/{ns}/{name}"},
                {"label": "Privileged container", "resource": f"Pod/{ns}/{name}"},
                {"label": "Potential node-level impact", "resource": "Node hosting the workload"},
            ],
            [privileged.get("rule_id", "K8S-POSTURE-PRIVILEGED")],
            {"workloads": 1, "namespaces": 1},
            "Remove privileged=true from the application workload and grant only the capabilities it actually requires.",
        ))

    # Workload -> cluster: privileged workload + excessive cluster-admin.
    if "K8S-POSTURE-RBAC-CLUSTERADMIN" in rules or "K8S-POSTURE-RBAC-NAMESPACE-CLUSTERADMIN" in rules:
        rbac = next((f for f in findings if f.get("rule_id") in {"K8S-POSTURE-RBAC-CLUSTERADMIN", "K8S-POSTURE-RBAC-NAMESPACE-CLUSTERADMIN"}), None)
        privileged_workloads = [w for w in workloads if w.get("privileged")]
        if privileged_workloads and rbac:
            paths.append(_path(
                "AP-PRIVILEGE-RBAC-CLUSTER",
                "Elevated workload access combined with cluster-admin exposure",
                "CRITICAL", 100,
                "A privileged application workload exists while a non-infrastructure identity has cluster-admin access. If the workload identity is compromised, the combination can materially increase cluster-wide blast radius.",
                [
                    {"label": "Privileged application workload", "resource": f"Pod/{privileged_workloads[0].get('namespace')}/{privileged_workloads[0].get('name')}"},
                    {"label": "Service identity with excessive RBAC", "resource": rbac.get("resource", "ClusterRoleBinding/cluster/unknown")},
                    {"label": "Cluster-wide control", "resource": "Kubernetes API"},
                ],
                ["K8S-POSTURE-PRIVILEGED", rbac.get("rule_id", "K8S-POSTURE-RBAC-CLUSTERADMIN")],
                {"workloads": max(1, len(privileged_workloads)), "namespaces": max(1, int(summary.get("affected_namespaces") or 1))},
                "Remove cluster-admin from application identities first, then remove unnecessary privileged access from application workloads.",
            ))

    # Cluster identity -> secrets: cluster-admin + missing encryption-at-rest evidence.
    encryption_failed = any(c.get("id") == "K8S-DATASTORE-ENCRYPTION" and c.get("status") == "FAIL" for c in (summary.get("native_posture_checks") or []))
    if ("K8S-POSTURE-RBAC-CLUSTERADMIN" in rules or "K8S-POSTURE-RBAC-NAMESPACE-CLUSTERADMIN" in rules) and encryption_failed:
        paths.append(_path(
            "AP-RBAC-SECRETS-ETCD",
            "Broad cluster identity access meets unencrypted-at-rest risk",
            "HIGH", 90,
            "Excessive cluster-admin access was verified while encryption at rest for Kubernetes API objects was not evidenced. A compromised broad identity could expose sensitive objects, while datastore compromise would have greater impact when encryption at rest is absent.",
            [
                {"label": "Excessive cluster-admin identity", "resource": "ClusterRoleBinding / ServiceAccount"},
                {"label": "Kubernetes Secrets and API objects", "resource": "Kubernetes API"},
                {"label": "Encryption at rest not evidenced", "resource": "kube-apiserver / etcd"},
            ],
            ["K8S-RBAC-CLUSTERADMIN", "K8S-DATASTORE-ENCRYPTION"],
            {"workloads": int(summary.get("affected_workloads") or summary.get("workload_count") or 0), "namespaces": int(summary.get("affected_namespaces") or 0)},
            "Reduce cluster-admin exposure, then configure and verify encryption at rest for sensitive Kubernetes resources.",
        ))

    # Network isolation: namespaces without policy + an affected workload.
    if "K8S-POSTURE-NETWORKPOLICY-ABSENT" in rules:
        no_policy = [f for f in findings if f.get("rule_id") == "K8S-POSTURE-NETWORKPOLICY-ABSENT"]
        if no_policy:
            path = _path(
                "AP-NETWORK-LATERAL-MOVEMENT",
                "Missing network isolation increases lateral-movement risk",
                "MEDIUM", 70,
                "One or more application namespaces have no NetworkPolicy. This does not prove lateral movement is possible, but it means pod-to-pod reachability may be broader than intended depending on the CNI configuration.",
                [
                    {"label": "Namespace without NetworkPolicy", "resource": no_policy[0].get("resource", "Namespace/cluster/unknown")},
                    {"label": "Pod-to-pod reachability", "resource": "Cluster network"},
                    {"label": "Potential lateral movement", "resource": "Adjacent workloads"},
                ],
                ["K8S-POSTURE-NETWORKPOLICY-ABSENT"],
                {"workloads": int(summary.get("affected_workloads") or summary.get("workload_count") or 0), "namespaces": len(no_policy)},
                "Define default-deny NetworkPolicies and explicitly allow required ingress and egress flows.",
            )
            paths.append(path)

    paths.sort(key=lambda item: (-int(item["risk_score"]), item["id"]))
    highest = paths[0] if paths else None
    return {
        "count": len(paths),
        "paths": paths,
        "highest_impact": highest,
        "method": "Deterministic correlation of verified native posture, RBAC, network and workload context; no exploitation is claimed.",
    }
