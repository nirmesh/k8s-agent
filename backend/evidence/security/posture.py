from __future__ import annotations

from typing import Any

from backend.evidence.security.model import SecurityDomain, SecurityLayer, SecurityEvidence, SecurityFinding


def _field(obj: dict[str, Any], name: str, default: Any = None) -> Any:
    if name in obj:
        return obj[name]
    aliases = {"hostNetwork": "host_network", "hostPID": "host_pid", "securityContext": "security_context", "privileged": "privileged"}
    alias = aliases.get(name)
    return obj.get(alias, default) if alias else default


def _items(result: dict) -> list[dict]:
    return ((result.get("data") or {}).get("items") or []) if result.get("success") else []


def _finding(*, rule_id: str, title: str, description: str, severity: str, resource: str = "cluster/-/-", domain: SecurityDomain = SecurityDomain.CLUSTER, recommendation: str, impact: str) -> SecurityEvidence:
    finding = SecurityFinding(category="misconfiguration", layer=SecurityLayer.POSTURE, domain=domain, source="kubernetes-posture", resource=resource, namespace=None, title=title, finding=title, description=description, severity=severity, recommendation=recommendation, remediation=recommendation, impact=impact, rule_id=rule_id, framework="Kubernetes Security Posture")
    return SecurityEvidence(provider="kubernetes-posture", type="security", layer=SecurityLayer.POSTURE, domain=domain, source="kubernetes-posture", resource=resource, severity=severity, category="misconfiguration", title=title, description=description, recommendation=recommendation, impact=impact, payload=finding)


_INFRA_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease", "calico-system", "tigera-operator", "gpu-operator", "nvidia-device-plugin", "metallb-system", "ingress-nginx", "cert-manager", "longhorn-system", "rook-ceph"}
_INFRA_PREFIXES = ("calico", "cilium", "kube-proxy", "nvidia", "gpu-operator", "metallb", "ingress", "longhorn", "rook", "node-exporter", "flannel", "weave", "multus", "aws-node", "azure-ip-masq-agent")


def _is_expected_infrastructure(meta: dict[str, Any], spec: dict[str, Any]) -> bool:
    ns = str(meta.get("namespace", "default"))
    name = str(meta.get("name", "")).lower()
    owners = meta.get("ownerReferences") or meta.get("owner_references") or []
    owner_kinds = {str(o.get("kind", "")).lower() for o in owners}
    labels = {str(k).lower(): str(v).lower() for k, v in (meta.get("labels") or {}).items()}
    return ns in _INFRA_NAMESPACES or name.startswith(_INFRA_PREFIXES) or (bool(owner_kinds & {"daemonset", "statefulset"}) and ("app.kubernetes.io/component" in labels or "k8s-app" in labels)) or any("operator" in value or "cni" in value for value in labels.values())


def _pod_posture(toolkit: Any, findings: list[SecurityEvidence]) -> None:
    for pod in _items(toolkit.get_resources("pod", None)):
        meta, spec = pod.get("metadata") or {}, pod.get("spec") or {}
        name, ns = meta.get("name", "unknown"), meta.get("namespace", "default")
        resource = f"Pod/{ns}/{name}"
        expected_infra = _is_expected_infrastructure(meta, spec)
        if _field(spec, "hostNetwork", False):
            findings.append(_finding(rule_id="K8S-POSTURE-HOSTNETWORK", title="Pod uses hostNetwork", description=f"{resource} shares the node network namespace.", severity="MEDIUM" if expected_infra else "HIGH", resource=resource, domain=SecurityDomain.NETWORK, recommendation="Keep hostNetwork only when the infrastructure component requires it; otherwise use normal pod networking.", impact="A compromised workload can gain direct access to node-network services and bypass normal pod-network isolation."))
        if _field(spec, "hostPID", False):
            findings.append(_finding(rule_id="K8S-POSTURE-HOSTPID", title="Pod uses hostPID", description=f"{resource} shares the node process namespace.", severity="MEDIUM" if expected_infra else "HIGH", resource=resource, domain=SecurityDomain.RUNTIME, recommendation="Remove hostPID unless explicitly required by the workload.", impact="Process namespace sharing can expose host processes to a compromised workload."))
        for container in spec.get("containers") or []:
            security = _field(container, "securityContext", {}) or {}
            cname = container.get("name", "unknown")
            if _field(security, "privileged", False) is True:
                if expected_infra:
                    findings.append(_finding(rule_id="K8S-POSTURE-PRIVILEGED-EXPECTED", title="Expected elevated privilege on infrastructure workload", description=f"{resource} container {cname!r} is privileged and the workload appears to be a cluster infrastructure component.", severity="LOW", resource=resource, domain=SecurityDomain.WORKLOAD, recommendation="Keep privileged access narrowly scoped and verify it is required by the infrastructure component.", impact="Elevated host access is still powerful, but this use is contextually consistent with common cluster infrastructure components."))
                else:
                    findings.append(_finding(rule_id="K8S-POSTURE-PRIVILEGED", title="Privileged container detected", description=f"{resource} container {cname!r} runs with privileged=true and is not identified as expected infrastructure.", severity="CRITICAL", resource=resource, domain=SecurityDomain.WORKLOAD, recommendation="Remove privileged=true and grant only the Linux capabilities actually required.", impact="A privileged application container can have near-host-level access and substantially increase container escape impact."))
            if _field(security, "runAsNonRoot", None) is False:
                findings.append(_finding(rule_id="K8S-POSTURE-RUNASROOT", title="Container explicitly allows root", description=f"{resource} container {cname!r} sets runAsNonRoot=false.", severity="MEDIUM", resource=resource, domain=SecurityDomain.WORKLOAD, recommendation="Prefer runAsNonRoot=true and a non-zero runAsUser where supported.", impact="Root inside a container increases the impact of application compromise."))
            caps = _field(security, "capabilities", {}) or {}
            dangerous = {str(c).upper() for c in (caps.get("add") or [])} & {"SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "NET_RAW", "SYS_MODULE"}
            if dangerous:
                findings.append(_finding(rule_id="K8S-POSTURE-DANGEROUS-CAPABILITIES", title="Dangerous Linux capabilities added", description=f"{resource} container {cname!r} adds {', '.join(sorted(dangerous))}.", severity="HIGH", resource=resource, domain=SecurityDomain.RUNTIME, recommendation="Drop unnecessary capabilities and add only the exact capability required by the workload.", impact="Powerful Linux capabilities can widen the blast radius of a compromised container."))
        host_paths = [v.get("name") for v in (spec.get("volumes") or []) if isinstance(v.get("hostPath"), dict)]
        if host_paths:
            findings.append(_finding(rule_id="K8S-POSTURE-HOSTPATH", title="Pod mounts hostPath storage", description=f"{resource} mounts hostPath volumes: {', '.join(host_paths)}.", severity="MEDIUM" if expected_infra else "HIGH", resource=resource, domain=SecurityDomain.RUNTIME, recommendation="Avoid hostPath for application workloads; use PVCs or dedicated interfaces where possible.", impact="Host filesystem access can expose node files or writable paths to a compromised workload."))


def _rbac_posture(toolkit: Any, findings: list[SecurityEvidence]) -> None:
    try:
        from backend.kubernetes import toolkit as toolkit_module
        api = toolkit_module.client.RbacAuthorizationV1Api(api_client=toolkit.api_client)
        roles = [toolkit_module.K8sToolkit._serialize(x) for x in (api.list_cluster_role().items or [])]
        bindings = [toolkit_module.K8sToolkit._serialize(x) for x in (api.list_cluster_role_binding().items or [])]
        role_bindings = [toolkit_module.K8sToolkit._serialize(x) for x in (api.list_role_binding_for_all_namespaces().items or [])]
    except Exception:
        return
    for binding in bindings:
        role_ref = binding.get("role_ref") or binding.get("roleRef") or {}
        if role_ref.get("name") != "cluster-admin":
            continue
        for subject in binding.get("subjects") or []:
            kind, name = subject.get("kind", ""), subject.get("name", "")
            if kind == "ServiceAccount" and name.startswith(("system:", "default")):
                continue
            findings.append(_finding(rule_id="K8S-POSTURE-RBAC-CLUSTERADMIN", title="Cluster-admin binding grants broad control", description=f"ClusterRoleBinding {binding.get('metadata', {}).get('name', 'unknown')} grants cluster-admin to {kind}:{name}.", severity="HIGH", resource=f"ClusterRoleBinding/cluster/{binding.get('metadata', {}).get('name', 'unknown')}", domain=SecurityDomain.IDENTITY, recommendation="Replace cluster-admin with a least-privilege role scoped to the required resources and verbs.", impact="A compromised identity with cluster-admin can control workloads, secrets and cluster configuration."))
    for role in roles:
        for rule in role.get("rules") or []:
            if "*" in set(rule.get("verbs") or []) and "*" in set(rule.get("resources") or []) and role.get("metadata", {}).get("name") != "cluster-admin":
                findings.append(_finding(rule_id="K8S-POSTURE-RBAC-WILDCARD", title="RBAC role uses wildcard verbs and resources", description=f"ClusterRole {role.get('metadata', {}).get('name', 'unknown')} grants wildcard verbs over wildcard resources.", severity="HIGH", resource=f"ClusterRole/cluster/{role.get('metadata', {}).get('name', 'unknown')}", domain=SecurityDomain.IDENTITY, recommendation="Replace wildcard permissions with an explicit allow-list of required resources and verbs.", impact="Wildcard RBAC permissions can turn a compromised identity into broad cluster control."))
    for binding in role_bindings:
        role_ref = binding.get("role_ref") or binding.get("roleRef") or {}
        if role_ref.get("name") != "cluster-admin":
            continue
        for subject in binding.get("subjects") or []:
            if subject.get("kind") == "ServiceAccount":
                ns = subject.get("namespace") or binding.get("metadata", {}).get("namespace") or "default"
                name = subject.get("name", "unknown")
                if ns not in _INFRA_NAMESPACES:
                    findings.append(_finding(rule_id="K8S-POSTURE-RBAC-NAMESPACE-CLUSTERADMIN", title="Namespaced service account has cluster-admin", description=f"ServiceAccount {ns}/{name} is bound to cluster-admin.", severity="HIGH", resource=f"ServiceAccount/{ns}/{name}", domain=SecurityDomain.IDENTITY, recommendation="Scope the service account to a namespaced Role with only required permissions.", impact="A compromised application service account can escalate from namespace access to cluster-wide control."))


def _control_plane_posture(toolkit: Any, findings: list[SecurityEvidence]) -> None:
    items = _items(toolkit.get_resources("pod", "kube-system"))
    by_name = {str((p.get("metadata") or {}).get("name", "")): p for p in items}
    apiserver = next((p for n, p in by_name.items() if n.startswith("kube-apiserver")), None)
    etcd = next((p for n, p in by_name.items() if n.startswith("etcd-")), None)
    def args_for(pod: dict[str, Any]) -> list[str]:
        out: list[str] = []
        for c in (pod.get("spec") or {}).get("containers") or []:
            out.extend(c.get("command") or [])
            out.extend(c.get("args") or [])
        return [str(x) for x in out]
    if apiserver:
        args = args_for(apiserver)
        resource = f"Pod/kube-system/{(apiserver.get('metadata') or {}).get('name', 'kube-apiserver')}"
        if not any(a.startswith("--authorization-mode=") and "RBAC" in a for a in args):
            findings.append(_finding(rule_id="K8S-POSTURE-APISERVER-RBAC", title="API server does not advertise RBAC authorization mode", description="The kube-apiserver static pod arguments do not show authorization-mode containing RBAC.", severity="HIGH", resource=resource, domain=SecurityDomain.CONTROL_PLANE, recommendation="Enable RBAC authorization and verify it is enforced alongside any other required authorization modes.", impact="Without RBAC, authorization can be weaker or rely on a less explicit policy model."))
        if any(a == "--anonymous-auth=true" or a.startswith("--anonymous-auth=true") for a in args):
            findings.append(_finding(rule_id="K8S-POSTURE-ANONYMOUS-AUTH", title="API server allows anonymous authentication", description="kube-apiserver explicitly enables anonymous authentication.", severity="HIGH", resource=resource, domain=SecurityDomain.CONTROL_PLANE, recommendation="Disable anonymous authentication unless a documented component requires it.", impact="Anonymous access increases the chance that unauthenticated requests reach API authorization paths."))
        if not any(a.startswith("--encryption-provider-config=") for a in args):
            findings.append(_finding(rule_id="K8S-POSTURE-ETCD-ENCRYPTION", title="API server does not advertise an encryption provider config", description="No --encryption-provider-config argument is visible on kube-apiserver; encryption at rest of API objects in etcd is therefore not evidenced by static pod configuration.", severity="HIGH", resource=resource, domain=SecurityDomain.CONTROL_PLANE, recommendation="Configure encryption at rest with an encryption-provider-config and verify it covers sensitive resources such as Secrets.", impact="Without encryption at rest, sensitive Kubernetes objects stored in etcd may be readable if the datastore is compromised."))
    if etcd:
        args = args_for(etcd)
        resource = f"Pod/kube-system/{(etcd.get('metadata') or {}).get('name', 'etcd')}"
        if not any(a == "--client-cert-auth=true" for a in args):
            findings.append(_finding(rule_id="K8S-POSTURE-ETCD-CLIENT-CERT", title="etcd client certificate authentication is not evidenced", description="The etcd static pod arguments do not show --client-cert-auth=true.", severity="HIGH", resource=resource, domain=SecurityDomain.CONTROL_PLANE, recommendation="Require client certificate authentication for etcd client connections.", impact="Weak etcd client authentication can expose the control-plane datastore to unauthorized access."))
        if not any(a == "--peer-client-cert-auth=true" for a in args):
            findings.append(_finding(rule_id="K8S-POSTURE-ETCD-PEER-CERT", title="etcd peer certificate authentication is not evidenced", description="The etcd static pod arguments do not show --peer-client-cert-auth=true.", severity="MEDIUM", resource=resource, domain=SecurityDomain.CONTROL_PLANE, recommendation="Require peer certificate authentication for etcd cluster communication.", impact="Unauthenticated peer connections weaken the trust boundary between etcd members."))


def _network_posture(toolkit: Any, findings: list[SecurityEvidence]) -> None:
    policy_namespaces = {(p.get("metadata") or {}).get("namespace") for p in _items(toolkit.get_resources("networkpolicy", None))}
    for ns_obj in _items(toolkit.get_resources("namespace", None)):
        ns = (ns_obj.get("metadata") or {}).get("name")
        if ns and ns not in policy_namespaces and ns not in _INFRA_NAMESPACES and ns != "default":
            findings.append(_finding(rule_id="K8S-POSTURE-NETWORKPOLICY-ABSENT", title="Namespace has no NetworkPolicy", description=f"Namespace {ns} has no NetworkPolicy objects.", severity="MEDIUM", resource=f"Namespace/cluster/{ns}", domain=SecurityDomain.NETWORK, recommendation="Define a default-deny NetworkPolicy and explicitly allow required ingress and egress flows.", impact="Without NetworkPolicy, pod-to-pod traffic may be broadly reachable depending on the CNI configuration."))


def evaluate_cluster_posture(toolkit: Any) -> list[SecurityEvidence]:
    """Run deterministic, read-only Kubernetes security checks with context-aware classification."""
    findings: list[SecurityEvidence] = []
    try:
        if not toolkit.get_resources("node", None).get("success"):
            return findings
        _pod_posture(toolkit, findings)
        _rbac_posture(toolkit, findings)
        _control_plane_posture(toolkit, findings)
        _network_posture(toolkit, findings)
    except Exception:
        pass
    return findings
