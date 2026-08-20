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


def _native_risk_paths(summary: dict[str, Any]) -> list[dict[str, Any]]:
    """Turn verified native posture findings into visible, bounded attack paths.

    These are risk chains, not exploit claims. The first step explicitly says that
    an initial compromise is not verified; the remaining steps describe the impact
    of the verified Kubernetes weakness.
    """
    paths: list[dict[str, Any]] = []
    mapping = {
        "K8S-POSTURE-PRIVILEGED": ("CRITICAL", 95, "Privileged application workload can cross the container isolation boundary", "A verified application pod runs privileged=true. If that workload is compromised, the elevated privileges materially increase the chance and impact of node compromise.", "Remove privileged=true and grant only the Linux capabilities actually required.", "Potential node-level control"),
        "K8S-POSTURE-HOSTPATH": ("HIGH", 85, "Application hostPath access can expose node filesystem resources", "A verified application pod mounts hostPath storage. If the workload is compromised, the host filesystem exposure can materially increase node-level impact.", "Replace hostPath with a PVC or dedicated interface unless host filesystem access is explicitly required.", "Potential node filesystem access"),
        "K8S-POSTURE-HOSTPID": ("HIGH", 82, "Host PID namespace sharing increases node compromise impact", "A verified application pod shares the host process namespace. A compromised process can gain visibility into host processes and weaken process isolation.", "Remove hostPID unless the workload has a documented host-level requirement.", "Potential host process visibility"),
        "K8S-POSTURE-DANGEROUS-CAPABILITIES": ("HIGH", 80, "Dangerous Linux capabilities weaken workload isolation", "A verified application pod adds powerful Linux capabilities. If the workload is compromised, those capabilities can expand the attacker's ability to interact with the node or kernel.", "Drop unnecessary capabilities and add back only the exact capability required.", "Potential node/kernel impact"),
        "K8S-POSTURE-RBAC-CLUSTERADMIN": ("CRITICAL", 98, "Compromised cluster-admin identity can control the cluster", "A non-infrastructure identity was verified with cluster-admin. If that identity is compromised, the Kubernetes API exposes cluster-wide control over workloads, RBAC and sensitive resources.", "Replace cluster-admin with a least-privilege role scoped to the required resources and verbs.", "Cluster-wide control"),
        "K8S-POSTURE-RBAC-NAMESPACE-CLUSTERADMIN": ("CRITICAL", 96, "Application service account has cluster-admin access", "A namespaced service account outside the expected infrastructure namespaces was verified with cluster-admin. Compromise of that workload identity can become a cluster-wide control path.", "Scope the service account to a namespaced Role with only required permissions.", "Cluster-wide control"),
        "K8S-POSTURE-RBAC-WILDCARD": ("HIGH", 88, "Wildcard RBAC permissions create a privilege-escalation path", "A non-cluster-admin ClusterRole was verified with wildcard verbs over wildcard resources. A compromised identity bound to it may have broader control than intended.", "Replace wildcard permissions with an explicit allow-list of required resources and verbs.", "Broad Kubernetes API control"),
        "K8S-POSTURE-NETWORKPOLICY-ABSENT": ("MEDIUM", 70, "Missing network isolation increases lateral-movement risk", "A verified application namespace has no NetworkPolicy. This does not prove lateral movement is possible, but pod-to-pod reachability may be broader than intended depending on the CNI configuration.", "Define a default-deny NetworkPolicy and explicitly allow required ingress and egress flows.", "Potential lateral movement"),
        "K8S-POSTURE-ANONYMOUS-AUTH": ("HIGH", 90, "Anonymous API authentication expands the control-plane attack surface", "The kube-apiserver was verified to allow anonymous authentication. This does not prove anonymous requests are authorized, but it creates an additional unauthenticated request path that must be tightly constrained.", "Disable anonymous authentication unless a documented endpoint or component requires it.", "Potential unauthenticated API access"),
        "K8S-POSTURE-APISERVER-RBAC": ("HIGH", 86, "API authorization hardening gap can weaken control-plane boundaries", "The kube-apiserver configuration did not evidence RBAC authorization mode. The effective authorization configuration needs verification before assuming least-privilege API access.", "Enable and verify RBAC authorization alongside the other required authorization modes.", "Potential authorization boundary weakness"),
        "K8S-POSTURE-ETCD-ENCRYPTION": ("HIGH", 88, "Unencrypted API data increases secret exposure after datastore compromise", "The kube-apiserver configuration did not evidence encryption at rest. Kubernetes documents that Secrets and other API objects may otherwise be stored in plaintext in etcd.", "Configure encryption at rest and verify that sensitive resources such as Secrets use an encryption provider.", "Potential sensitive-object disclosure"),
        "K8S-POSTURE-ETCD-CLIENT-CERT": ("HIGH", 92, "Weak etcd client authentication increases control-plane datastore risk", "The etcd configuration did not evidence client certificate authentication. Direct etcd access is highly sensitive because datastore access can expose or modify cluster state.", "Require client certificate authentication and restrict etcd network access to trusted clients.", "Potential etcd read/write control"),
        "K8S-POSTURE-ETCD-PEER-CERT": ("MEDIUM", 72, "Weak etcd peer authentication increases datastore trust risk", "The etcd configuration did not evidence peer client certificate authentication. This weakens the trust boundary between datastore members.", "Require peer certificate authentication and verify the peer CA configuration.", "Potential datastore peer compromise"),
    }

    for index, finding in enumerate(_findings(summary)):
        rule = str(finding.get("rule_id") or "")
        spec = mapping.get(rule)
        if not spec:
            continue
        severity, score, title, description, recommendation, impact = spec
        resource = str(finding.get("resource") or "cluster/-/-")
        namespace = str(finding.get("namespace") or "cluster")
        safe_id = resource.replace("/", "-").replace(" ", "-")
        paths.append(_path(
            f"AP-NATIVE-{rule}-{safe_id}-{index}",
            title,
            severity,
            score,
            description,
            [
                {"label": "Initial compromise not verified", "resource": resource},
                {"label": finding.get("title") or rule, "resource": resource},
                {"label": impact, "resource": "Kubernetes node / API / adjacent workloads"},
            ],
            [rule],
            {"workloads": 1, "namespaces": 1 if namespace != "cluster" else 0},
            recommendation,
        ))

    return paths


def build_attack_paths(summary: dict[str, Any]) -> dict[str, Any]:
    """Correlate verified security evidence into deterministic attack paths."""
    findings = _findings(summary)
    rules = _rules(summary)
    workloads = summary.get("top_10_risks") or []
    paths: list[dict[str, Any]] = _native_risk_paths(summary)

    # More specific multi-condition path: internet-facing application + verified privileged pod.
    for workload in workloads:
        ns, name = str(workload.get("namespace") or "default"), str(workload.get("name") or "")
        if not name or not workload.get("internet_facing"):
            continue
        resource_findings = _workload_findings(summary, ns, name)
        privileged = next((f for f in resource_findings if f.get("rule_id") == "K8S-POSTURE-PRIVILEGED"), None)
        if privileged:
            paths.append(_path(
                f"AP-WORKLOAD-NODE-{ns}-{name}",
                "Internet-facing privileged workload increases node compromise impact",
                "CRITICAL", 100,
                f"{workload.get('kind', 'Workload')}/{ns}/{name} is internet-facing and a privileged application finding was verified. These conditions can combine to make application compromise materially more dangerous.",
                [
                    {"label": "Internet-facing workload", "resource": f"{workload.get('kind', 'Workload')}/{ns}/{name}"},
                    {"label": "Privileged application container", "resource": privileged.get("resource", f"Pod/{ns}/{name}")},
                    {"label": "Potential node-level control", "resource": "Node hosting the workload"},
                ],
                ["K8S-POSTURE-PRIVILEGED"],
                {"workloads": 1, "namespaces": 1},
                "Remove privileged=true and reduce the workload's external exposure where possible.",
            ))

    # Multi-condition path: privileged application + excessive cluster-admin.
    if "K8S-POSTURE-RBAC-CLUSTERADMIN" in rules or "K8S-POSTURE-RBAC-NAMESPACE-CLUSTERADMIN" in rules:
        rbac = next((f for f in findings if f.get("rule_id") in {"K8S-POSTURE-RBAC-CLUSTERADMIN", "K8S-POSTURE-RBAC-NAMESPACE-CLUSTERADMIN"}), None)
        privileged_resources = {str(f.get("resource")) for f in findings if f.get("rule_id") == "K8S-POSTURE-PRIVILEGED"}
        privileged_workloads = [w for w in workloads if f"Pod/{w.get('namespace', 'default')}/{w.get('name', '')}" in privileged_resources]
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

    encryption_failed = any(c.get("id") == "K8S-DATASTORE-ENCRYPTION" and c.get("status") == "FAIL" for c in (summary.get("native_posture_checks") or []))
    if ("K8S-POSTURE-RBAC-CLUSTERADMIN" in rules or "K8S-POSTURE-RBAC-NAMESPACE-CLUSTERADMIN" in rules) and encryption_failed:
        paths.append(_path(
            "AP-RBAC-SECRETS-ETCD",
            "Broad cluster identity access meets unencrypted-at-rest risk",
            "HIGH", 90,
            "Excessive cluster-admin access was verified while encryption at rest for Kubernetes API objects was not evidenced.",
            [
                {"label": "Excessive cluster-admin identity", "resource": "ClusterRoleBinding / ServiceAccount"},
                {"label": "Kubernetes Secrets and API objects", "resource": "Kubernetes API"},
                {"label": "Encryption at rest not evidenced", "resource": "kube-apiserver / etcd"},
            ],
            ["K8S-RBAC-CLUSTERADMIN", "K8S-DATASTORE-ENCRYPTION"],
            {"workloads": int(summary.get("affected_workloads") or summary.get("workload_count") or 0), "namespaces": int(summary.get("affected_namespaces") or 0)},
            "Reduce cluster-admin exposure, then configure and verify encryption at rest for sensitive Kubernetes resources.",
        ))

    deduped: dict[str, dict[str, Any]] = {}
    for path in paths:
        key = (path.get("title"), path.get("evidence", [""])[0], path.get("blast_radius", {}).get("workloads"), path.get("blast_radius", {}).get("namespaces"))
        existing = deduped.get(str(key))
        if existing is None or int(path.get("risk_score", 0)) > int(existing.get("risk_score", 0)):
            deduped[str(key)] = path
    paths = list(deduped.values())
    paths.sort(key=lambda item: (-int(item["risk_score"]), item["id"]))
    highest = paths[0] if paths else None
    return {
        "count": len(paths),
        "paths": paths,
        "highest_impact": highest,
        "method": "Deterministic correlation of verified native posture, RBAC, network and workload context; no exploitation is claimed.",
    }
