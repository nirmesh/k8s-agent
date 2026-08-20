from __future__ import annotations

from typing import Any


def _findings(summary: dict[str, Any]) -> list[dict[str, Any]]:
    return summary.get("native_posture_findings") or []


def _rules(summary: dict[str, Any]) -> set[str]:
    return {str(f.get("rule_id")) for f in _findings(summary) if f.get("rule_id")}


def _workload_findings(summary: dict[str, Any], namespace: str, name: str) -> list[dict[str, Any]]:
    return [f for f in _findings(summary) if f.get("resource") == f"Pod/{namespace}/{name}"]


def _path(path_id: str, title: str, severity: str, score: int, summary: str, steps: list[dict[str, str]], evidence: list[str], blast_radius: dict[str, int], recommendation: str) -> dict[str, Any]:
    return {"id": path_id, "title": title, "severity": severity, "risk_score": score, "summary": summary, "steps": steps, "evidence": evidence, "blast_radius": blast_radius, "recommendation": recommendation}


def _native_risk_paths(summary: dict[str, Any]) -> list[dict[str, Any]]:
    """Create bounded paths from individually verified posture findings.

    A finding is shown as a potential path only when the evidence itself establishes
    the relationship. We never join an arbitrary pod to an arbitrary user/group RBAC
    binding. Multi-hop identity paths require an explicit workload identity mapping.
    """
    mapping = {
        "K8S-POSTURE-PRIVILEGED": ("CRITICAL", 95, "Privileged application workload can cross the container isolation boundary", "A verified application pod runs privileged=true. If that workload is compromised, elevated privileges materially increase node-compromise impact.", "Remove privileged=true and grant only the Linux capabilities actually required.", "Potential node-level control"),
        "K8S-POSTURE-HOSTPATH": ("HIGH", 85, "Application hostPath access can expose node filesystem resources", "A verified application pod mounts hostPath storage. If the workload is compromised, host filesystem exposure can materially increase node-level impact.", "Replace hostPath with a PVC or dedicated interface unless host filesystem access is explicitly required.", "Potential node filesystem access"),
        "K8S-POSTURE-HOSTPID": ("HIGH", 82, "Host PID namespace sharing increases node compromise impact", "A verified application pod shares the host process namespace. A compromised process can gain visibility into host processes and weaken process isolation.", "Remove hostPID unless the workload has a documented host-level requirement.", "Potential host process visibility"),
        "K8S-POSTURE-DANGEROUS-CAPABILITIES": ("HIGH", 80, "Dangerous Linux capabilities weaken workload isolation", "A verified application pod adds powerful Linux capabilities. If compromised, those capabilities can expand interaction with the node or kernel.", "Drop unnecessary capabilities and add back only the exact capability required.", "Potential node/kernel impact"),
        "K8S-POSTURE-RBAC-CLUSTERADMIN": ("CRITICAL", 98, "Compromised cluster-admin identity can control the cluster", "A non-infrastructure identity was verified with cluster-admin. If that identity is compromised, the Kubernetes API exposes cluster-wide control over workloads, RBAC and sensitive resources.", "Replace cluster-admin with a least-privilege role scoped to the required resources and verbs.", "Cluster-wide control"),
        "K8S-POSTURE-RBAC-NAMESPACE-CLUSTERADMIN": ("CRITICAL", 96, "Application service account has cluster-admin access", "A namespaced application service account was directly verified with cluster-admin. Compromise of that workload identity can become a cluster-wide control path.", "Scope the service account to a namespaced Role with only required permissions.", "Cluster-wide control"),
        "K8S-POSTURE-RBAC-WILDCARD": ("HIGH", 88, "Wildcard RBAC permissions create a privilege-escalation path", "A non-cluster-admin ClusterRole was verified with wildcard verbs over wildcard resources. An identity bound to it may have broader control than intended.", "Replace wildcard permissions with an explicit allow-list of required resources and verbs.", "Broad Kubernetes API control"),
        "K8S-POSTURE-NETWORKPOLICY-ABSENT": ("MEDIUM", 70, "Missing network isolation increases lateral-movement risk", "A verified application namespace has no NetworkPolicy. This does not prove lateral movement, but pod-to-pod reachability may be broader than intended depending on the CNI.", "Define a default-deny NetworkPolicy and explicitly allow required ingress and egress flows.", "Potential lateral movement"),
        "K8S-POSTURE-ANONYMOUS-AUTH": ("HIGH", 90, "Anonymous API authentication expands the control-plane attack surface", "The kube-apiserver was verified to allow anonymous authentication. This does not prove anonymous requests are authorized, but it creates an unauthenticated request path that must be constrained.", "Disable anonymous authentication unless a documented component requires it.", "Potential unauthenticated API access"),
        "K8S-POSTURE-APISERVER-RBAC": ("HIGH", 86, "API authorization hardening gap can weaken control-plane boundaries", "The kube-apiserver configuration did not evidence RBAC authorization mode. The effective authorization configuration needs verification before assuming least privilege.", "Enable and verify RBAC authorization alongside required authorization modes.", "Potential authorization boundary weakness"),
        "K8S-POSTURE-ETCD-ENCRYPTION": ("HIGH", 88, "Unencrypted API data increases secret exposure after datastore compromise", "The kube-apiserver configuration did not evidence encryption at rest for API objects in etcd.", "Configure encryption at rest and verify sensitive resources such as Secrets use an encryption provider.", "Potential sensitive-object disclosure"),
        "K8S-POSTURE-ETCD-CLIENT-CERT": ("HIGH", 92, "Weak etcd client authentication increases control-plane datastore risk", "The etcd configuration did not evidence client certificate authentication. Direct etcd access is highly sensitive because datastore access can expose or modify cluster state.", "Require client certificate authentication and restrict etcd network access to trusted clients.", "Potential etcd read/write control"),
        "K8S-POSTURE-ETCD-PEER-CERT": ("MEDIUM", 72, "Weak etcd peer authentication increases datastore trust risk", "The etcd configuration did not evidence peer client certificate authentication.", "Require peer certificate authentication and verify the peer CA configuration.", "Potential datastore peer compromise"),
    }
    paths: list[dict[str, Any]] = []
    for index, finding in enumerate(_findings(summary)):
        rule = str(finding.get("rule_id") or "")
        spec = mapping.get(rule)
        if not spec:
            continue
        severity, score, title, description, recommendation, impact = spec
        resource = str(finding.get("resource") or "cluster/-/-")
        namespace = str(finding.get("namespace") or "cluster")
        safe_id = resource.replace("/", "-").replace(" ", "-")
        paths.append(_path(f"AP-NATIVE-{rule}-{safe_id}-{index}", title, severity, score, description, [
            {"label": "Initial compromise not verified", "resource": resource},
            {"label": finding.get("title") or rule, "resource": resource},
            {"label": impact, "resource": "Kubernetes node / API / adjacent workloads"},
        ], [rule], {"workloads": 1, "namespaces": 1 if namespace != "cluster" else 0}, recommendation))
    return paths


def build_attack_paths(summary: dict[str, Any]) -> dict[str, Any]:
    """Correlate verified security evidence without inventing resource relationships."""
    findings = _findings(summary)
    workloads = summary.get("top_10_risks") or []
    paths = _native_risk_paths(summary)

    # This correlation is safe because both conditions are attached to the SAME pod.
    for workload in workloads:
        ns, name = str(workload.get("namespace") or "default"), str(workload.get("name") or "")
        if not name or not workload.get("internet_facing"):
            continue
        resource_findings = _workload_findings(summary, ns, name)
        privileged = next((f for f in resource_findings if f.get("rule_id") == "K8S-POSTURE-PRIVILEGED"), None)
        if privileged:
            paths.append(_path(f"AP-WORKLOAD-NODE-{ns}-{name}", "Internet-facing privileged workload increases node compromise impact", "CRITICAL", 100,
                f"{workload.get('kind', 'Workload')}/{ns}/{name} is internet-facing and a privileged application finding was verified. These conditions can combine to make application compromise materially more dangerous.",
                [{"label": "Internet-facing workload", "resource": f"{workload.get('kind', 'Workload')}/{ns}/{name}"}, {"label": "Privileged application container", "resource": privileged.get("resource", f"Pod/{ns}/{name}")}, {"label": "Potential node-level control", "resource": "Node hosting the workload"}],
                ["K8S-POSTURE-PRIVILEGED"], {"workloads": 1, "namespaces": 1}, "Remove privileged=true and reduce the workload's external exposure where possible."))

    # Deliberately DO NOT combine an arbitrary privileged pod with an arbitrary
    # cluster-admin binding. The RBAC finding must identify the workload's own
    # ServiceAccount before a multi-hop Pod -> SA -> RBAC path can be emitted.
    # That identity mapping is not yet present in the summary contract, so no
    # cross-resource RBAC path is generated here.

    encryption_failed = any(c.get("id") == "K8S-DATASTORE-ENCRYPTION" and c.get("status") == "FAIL" for c in (summary.get("native_posture_checks") or []))
    rbac_findings = [f for f in findings if f.get("rule_id") in {"K8S-POSTURE-RBAC-NAMESPACE-CLUSTERADMIN"} and str(f.get("resource", "")).startswith("ServiceAccount/")]
    if encryption_failed and rbac_findings:
        rbac = rbac_findings[0]
        paths.append(_path("AP-RBAC-SECRETS-ETCD", "Application service account with cluster-admin meets unencrypted-at-rest risk", "HIGH", 90,
            f"{rbac.get('resource')} was directly verified with cluster-admin while encryption at rest for Kubernetes API objects was not evidenced. This is a real identity-to-datastore risk chain.",
            [{"label": "Application ServiceAccount", "resource": rbac.get("resource", "ServiceAccount/unknown")}, {"label": "Cluster-wide control", "resource": "Kubernetes API"}, {"label": "Encryption at rest not evidenced", "resource": "kube-apiserver / etcd"}],
            [rbac.get("rule_id", "K8S-POSTURE-RBAC-NAMESPACE-CLUSTERADMIN"), "K8S-POSTURE-ETCD-ENCRYPTION"],
            {"workloads": int(summary.get("affected_workloads") or summary.get("workload_count") or 0), "namespaces": int(summary.get("affected_namespaces") or 0)},
            "Reduce the application service account to least privilege, then configure and verify encryption at rest for sensitive Kubernetes resources."))

    deduped: dict[str, dict[str, Any]] = {}
    for path in paths:
        key = (path.get("title"), tuple(path.get("evidence", [])), path.get("blast_radius", {}).get("workloads"), path.get("blast_radius", {}).get("namespaces"))
        existing = deduped.get(str(key))
        if existing is None or int(path.get("risk_score", 0)) > int(existing.get("risk_score", 0)):
            deduped[str(key)] = path
    paths = sorted(deduped.values(), key=lambda item: (-int(item["risk_score"]), item["id"]))
    return {"count": len(paths), "paths": paths, "highest_impact": paths[0] if paths else None, "method": "Deterministic correlation of verified native posture and explicit resource relationships; no exploitation is claimed."}
