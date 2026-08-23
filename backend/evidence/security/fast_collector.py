from __future__ import annotations

from collections import defaultdict
from typing import Any

from backend.core.logging import logger
from backend.evidence.security.collector import _recommendation, _severity, _title
from backend.evidence.security.model import SecurityEvidence, SecurityFinding
from backend.kubernetes.toolkit import K8sToolkit

SEVERITY_WEIGHT = {"CRITICAL": 100, "HIGH": 88, "MEDIUM": 68, "LOW": 42, "UNKNOWN": 25}


class FastSecurityEvidenceCollector:
    """Fast, operator-facing security scan.

    It deliberately does not collect SBOMs or persist thousands of scanner rows.
    It checks a small set of high-value native controls and samples only the
    highest-value Trivy findings while preserving aggregate scanner counts.
    """

    def __init__(self, toolkit: K8sToolkit):
        self.toolkit = toolkit
        self.evidence: list[SecurityEvidence] = []
        self.issues: dict[str, dict[str, Any]] = {}
        self.counts = defaultdict(int)
        self.coverage = defaultdict(int)
        self._evidence_limit = 100

    @staticmethod
    def _risk(severity: str, context: int = 0) -> int:
        return min(99, SEVERITY_WEIGHT.get(severity, 25) + context)

    def _add(self, *, title: str, severity: str, category: str, resource: str,
             layer: str, source: str, proof: str, why: str, fix: str,
             verify: str, cve: str | None = None, issue_key: str | None = None,
             context: int = 0) -> None:
        severity = _severity(severity)
        self.counts[(category, severity)] += 1
        key = issue_key or f"{category}|{cve or title}"
        issue = self.issues.get(key)
        if issue is None:
            issue = {
                "id": key,
                "title": title,
                "severity": severity,
                "score": self._risk(severity, context),
                "category": category,
                "layer": layer,
                "source": source,
                "cve": cve,
                "proof": proof,
                "why": why,
                "fix": fix,
                "verify": verify,
                "occurrences": 0,
                "affected_resources": [],
            }
            self.issues[key] = issue
        issue["occurrences"] += 1
        if resource not in issue["affected_resources"]:
            issue["affected_resources"].append(resource)
        issue["score"] = max(issue["score"], self._risk(severity, context))
        self.coverage[layer] += 1

        if len(self.evidence) < self._evidence_limit:
            finding = SecurityFinding(
                category=category,
                resource=resource,
                namespace=resource.split("/")[1] if resource.count("/") >= 2 else None,
                title=title,
                finding=title,
                description=why,
                severity=severity,
                remediation=fix,
                recommendation=fix,
                references=None,
                rule_id=None,
                cve_id=cve,
                confidence=1.0,
            )
            self.evidence.append(SecurityEvidence(
                provider=source,
                resource=resource,
                namespace=finding.namespace,
                category=category,
                title=title,
                description=why,
                severity=severity,
                recommendation=fix,
                references=None,
                confidence=1.0,
                payload=finding,
            ))

    def _scan_native(self) -> None:
        pods = self.toolkit.get_resources("pod").get("data", {}).get("items", [])
        deployments = self.toolkit.get_resources("deployment").get("data", {}).get("items", [])
        services = self.toolkit.get_resources("service").get("data", {}).get("items", [])
        namespaces = self.toolkit.get_resources("namespace").get("data", {}).get("items", [])
        network_policies = self.toolkit.get_resources("networkpolicy").get("data", {}).get("items", [])

        policy_namespaces = {str((p.get("metadata") or {}).get("namespace", "")) for p in network_policies}
        workload_namespaces = set()

        for pod in pods:
            meta = pod.get("metadata") or {}
            spec = pod.get("spec") or {}
            ns = str(meta.get("namespace", "default"))
            name = str(meta.get("name", "unknown"))
            resource = f"Pod/{ns}/{name}"
            workload_namespaces.add(ns)
            containers = (spec.get("containers") or []) + (spec.get("initContainers") or [])

            if spec.get("hostNetwork"):
                self._add(
                    title="Pod uses host network namespace", severity="HIGH", category="native_misconfiguration",
                    resource=resource, layer="WORKLOAD", source="kubernetes-api", context=2,
                    proof=f"spec.hostNetwork=true on {resource}",
                    why="The pod shares the node network namespace, increasing the blast radius of a container compromise.",
                    fix="Set spec.hostNetwork=false unless the workload has a documented host-network requirement.",
                    verify="Re-read the pod spec and confirm hostNetwork is false.", issue_key="host-network",
                )
            if spec.get("hostPID"):
                self._add(
                    title="Pod shares the host PID namespace", severity="CRITICAL", category="native_misconfiguration",
                    resource=resource, layer="WORKLOAD", source="kubernetes-api", context=3,
                    proof=f"spec.hostPID=true on {resource}",
                    why="Processes on the node can become visible to the pod, materially increasing host-compromise risk.",
                    fix="Set hostPID=false and remove the host-level dependency where possible.",
                    verify="Re-read the pod spec and confirm hostPID is false.", issue_key="host-pid",
                )
            if spec.get("hostIPC"):
                self._add(
                    title="Pod shares the host IPC namespace", severity="HIGH", category="native_misconfiguration",
                    resource=resource, layer="WORKLOAD", source="kubernetes-api", context=2,
                    proof=f"spec.hostIPC=true on {resource}",
                    why="Host IPC access can expose node-level shared memory and IPC resources to the container.",
                    fix="Set hostIPC=false unless the workload has an approved host IPC requirement.",
                    verify="Re-read the pod spec and confirm hostIPC is false.", issue_key="host-ipc",
                )

            for container in containers:
                cname = container.get("name", "container")
                sc = container.get("securityContext") or {}
                c_resource = f"{resource} container={cname}"
                if sc.get("privileged") is True:
                    self._add(
                        title="Privileged container can access host-level capabilities", severity="CRITICAL", category="privileged_container",
                        resource=c_resource, layer="WORKLOAD", source="kubernetes-api", context=3,
                        proof=f"securityContext.privileged=true on {c_resource}",
                        why="A privileged container is close to node-level access and can turn a container compromise into a host compromise.",
                        fix="Remove privileged=true; grant only the specific Linux capability or device the workload needs.",
                        verify="Confirm securityContext.privileged is absent/false and restart the workload.", issue_key="privileged-container",
                    )
                if sc.get("allowPrivilegeEscalation") is True:
                    self._add(
                        title="Privilege escalation is explicitly allowed", severity="HIGH", category="native_misconfiguration",
                        resource=c_resource, layer="WORKLOAD", source="kubernetes-api", context=2,
                        proof=f"securityContext.allowPrivilegeEscalation=true on {c_resource}",
                        why="A compromised process can gain additional privileges inside the container.",
                        fix="Set allowPrivilegeEscalation=false and use a non-root security context.",
                        verify="Confirm the rendered pod spec contains allowPrivilegeEscalation=false.", issue_key="privilege-escalation",
                    )
                if sc.get("runAsUser") == 0 or sc.get("runAsNonRoot") is False:
                    self._add(
                        title="Container is configured to run as root", severity="HIGH", category="native_misconfiguration",
                        resource=c_resource, layer="WORKLOAD", source="kubernetes-api", context=1,
                        proof=f"securityContext.runAsUser=0 or runAsNonRoot=false on {c_resource}",
                        why="Root inside a container increases the impact of an application compromise.",
                        fix="Run the process as a dedicated non-root UID and set runAsNonRoot=true.",
                        verify="Check the rendered pod securityContext and confirm a non-root UID is used.", issue_key="root-container",
                    )
                if not sc.get("runAsNonRoot") and sc.get("runAsUser") != 0:
                    self._add(
                        title="Container does not require a non-root user", severity="MEDIUM", category="native_misconfiguration",
                        resource=c_resource, layer="WORKLOAD", source="kubernetes-api",
                        proof=f"runAsNonRoot is not set on {c_resource}",
                        why="The workload leaves the runtime free to run as root, increasing the impact of a container escape or compromise.",
                        fix="Set runAsNonRoot=true and choose an explicit unprivileged UID.",
                        verify="Confirm runAsNonRoot=true in the live pod spec.", issue_key="missing-nonroot",
                    )
                for mount in container.get("volumeMounts") or []:
                    _ = mount
            for volume in spec.get("volumes") or []:
                host_path = volume.get("hostPath")
                if host_path:
                    self._add(
                        title="Pod mounts a host filesystem path", severity="HIGH", category="hostpath_mount",
                        resource=resource, layer="WORKLOAD", source="kubernetes-api", context=2,
                        proof=f"volumes[{volume.get('name', 'unknown')}].hostPath={host_path.get('path', '')}",
                        why="Host filesystem access can expose node credentials, sockets, or configuration to the container.",
                        fix="Replace hostPath with a PVC or remove the mount; never mount the container runtime socket.",
                        verify="Confirm no hostPath volumes remain in the live pod spec.", issue_key="hostpath-mount",
                    )
            if spec.get("automountServiceAccountToken") is not False:
                self._add(
                    title="Service-account token is automatically mounted", severity="MEDIUM", category="identity",
                    resource=resource, layer="WORKLOAD", source="kubernetes-api",
                    proof=f"automountServiceAccountToken is not false on {resource}",
                    why="A compromised pod may obtain a Kubernetes API token it does not need.",
                    fix="Set automountServiceAccountToken=false and mount a narrowly scoped token only where required.",
                    verify="Confirm the rendered pod has automountServiceAccountToken=false.", issue_key="sa-token-auto-mount",
                )

        # Namespace-level network isolation: only flag namespaces that actually run workloads.
        for ns in workload_namespaces:
            if ns in {"kube-system", "kube-public", "kube-node-lease"}:
                continue
            if ns not in policy_namespaces:
                self._add(
                    title="No NetworkPolicy protects this workload namespace", severity="MEDIUM", category="network_isolation",
                    resource=f"Namespace/{ns}", layer="NETWORK", source="kubernetes-api",
                    proof=f"No NetworkPolicy object exists in namespace {ns}",
                    why="Without a NetworkPolicy, compromised workloads may communicate freely with other pods depending on the CNI defaults.",
                    fix="Add a default-deny NetworkPolicy, then explicitly allow required application flows.",
                    verify="kubectl get networkpolicy -n {ns} should show the intended policy set.", issue_key="no-network-policy",
                )

        # Internet-facing services are treated as context, not proof of exploitation.
        for svc in services:
            meta = svc.get("metadata") or {}
            spec = svc.get("spec") or {}
            if spec.get("type") in {"LoadBalancer", "NodePort"}:
                ns = str(meta.get("namespace", "default"))
                name = str(meta.get("name", "unknown"))
                self._add(
                    title=f"{spec.get('type')} service exposes a workload", severity="MEDIUM", category="exposure",
                    resource=f"Service/{ns}/{name}", layer="NETWORK", source="kubernetes-api", context=2,
                    proof=f"spec.type={spec.get('type')} on Service/{ns}/{name}",
                    why="Externally reachable workloads have a larger attack surface and should be hardened before internal-only services.",
                    fix="Use ClusterIP unless external access is required; restrict ingress and enforce TLS/authentication at the edge.",
                    verify="Confirm only intended ports are externally reachable and the service is protected by ingress controls.", issue_key="external-service",
                )

        # Control-plane checks from the live kube-system static pods.
        for pod in pods:
            meta = pod.get("metadata") or {}
            ns = str(meta.get("namespace", ""))
            name = str(meta.get("name", ""))
            if ns != "kube-system":
                continue
            spec = pod.get("spec") or {}
            containers = spec.get("containers") or []
            if not containers:
                continue
            container = containers[0]
            args = [str(x) for x in (container.get("command") or []) + (container.get("args") or [])]
            joined = " ".join(args)
            resource = f"Pod/{ns}/{name}"

            if name.startswith("kube-apiserver"):
                if "--encryption-provider-config=" not in joined:
                    self._add(
                        title="API server has no encryption-provider-config configured", severity="CRITICAL", category="control_plane",
                        resource=resource, layer="CONTROL PLANE", source="kubernetes-api", context=3,
                        proof=f"Live kube-apiserver command line for {resource} does not contain --encryption-provider-config",
                        why="This is a strong configuration signal that Kubernetes Secrets are not configured for envelope encryption at rest.",
                        fix="Configure an encryption provider, supply it with --encryption-provider-config, and rotate existing Secrets after enabling it.",
                        verify="Confirm the live kube-apiserver args contain --encryption-provider-config and validate encryption with the cluster's documented procedure.", issue_key="secret-encryption-at-rest",
                    )
                if "--anonymous-auth=true" in joined or "--anonymous-auth" not in joined:
                    self._add(
                        title="Kubernetes API anonymous authentication is not explicitly disabled", severity="HIGH", category="control_plane",
                        resource=resource, layer="CONTROL PLANE", source="kubernetes-api", context=2,
                        proof=f"Live kube-apiserver args do not show --anonymous-auth=false on {resource}",
                        why="Anonymous API access can expose endpoints to unauthenticated callers when authorization permits it.",
                        fix="Set --anonymous-auth=false on the API server unless an explicit compatibility requirement exists.",
                        verify="Confirm --anonymous-auth=false is present on the running API server.", issue_key="anonymous-api-auth",
                    )
                if any(x.startswith("--insecure-port=") and not x.endswith("=0") for x in args):
                    self._add(
                        title="API server exposes the legacy insecure port", severity="CRITICAL", category="control_plane",
                        resource=resource, layer="CONTROL PLANE", source="kubernetes-api", context=3,
                        proof=f"Live kube-apiserver args contain a non-zero --insecure-port on {resource}",
                        why="The legacy unauthenticated API port can bypass normal TLS and authentication controls.",
                        fix="Set --insecure-port=0 and restart the API server; use the normal authenticated HTTPS endpoint.",
                        verify="Confirm the running API server has --insecure-port=0 or the flag is absent on supported versions.", issue_key="insecure-api-port",
                    )

            if name.startswith("etcd"):
                if "--client-cert-auth=true" not in joined:
                    self._add(
                        title="etcd client certificate authentication is not enabled", severity="HIGH", category="control_plane",
                        resource=resource, layer="DATASTORE", source="kubernetes-api", context=2,
                        proof=f"Live etcd command line does not contain --client-cert-auth=true on {resource}",
                        why="Without client certificate authentication, etcd client connections have weaker identity guarantees.",
                        fix="Enable --client-cert-auth=true and configure the trusted CA/certificate flags for etcd clients.",
                        verify="Confirm the running etcd args contain --client-cert-auth=true.", issue_key="etcd-client-auth",
                    )
                if any(x.startswith("--listen-client-urls=http://") for x in args) or any(x.startswith("--advertise-client-urls=http://") for x in args):
                    self._add(
                        title="etcd client traffic is configured over HTTP", severity="CRITICAL", category="control_plane",
                        resource=resource, layer="DATASTORE", source="kubernetes-api", context=3,
                        proof=f"Live etcd args contain an http:// client URL on {resource}",
                        why="etcd carries highly sensitive cluster state; plaintext client traffic can expose credentials and data on the network.",
                        fix="Use HTTPS client URLs with a trusted CA and client certificates; remove plaintext client endpoints.",
                        verify="Confirm all etcd client URLs are https:// and TLS client authentication is enabled.", issue_key="etcd-plaintext-client",
                    )
                if "--peer-client-cert-auth=true" not in joined:
                    self._add(
                        title="etcd peer certificate authentication is not enabled", severity="HIGH", category="control_plane",
                        resource=resource, layer="DATASTORE", source="kubernetes-api", context=2,
                        proof=f"Live etcd command line does not contain --peer-client-cert-auth=true on {resource}",
                        why="Unauthenticated etcd peer connections weaken protection of the distributed datastore.",
                        fix="Enable peer client certificate authentication and configure peer TLS certificates and a trusted CA.",
                        verify="Confirm --peer-client-cert-auth=true is present on the running etcd process.", issue_key="etcd-peer-auth",
                    )

        # A missing control-plane pod is not automatically a vulnerability; do not invent a finding.
        _ = deployments
        _ = namespaces

    def _scan_trivy(self) -> None:
        # Only the security reports needed for prioritization. SBOM reports are intentionally skipped.
        for plural, category in (
            ("vulnerabilityreports", "vulnerability"),
            ("configauditreports", "misconfiguration"),
            ("exposedsecretreports", "exposed_secret"),
        ):
            result = self.toolkit.get_custom_resources("aquasecurity.github.io", None, plural)
            if not result.get("success"):
                logger.info("Security scanner %s unavailable: %s", plural, result.get("error", {}).get("message"))
                continue
            for report_crd in (result.get("data") or {}).get("items") or []:
                metadata = report_crd.get("metadata") or {}
                labels = metadata.get("labels") or {}
                ns = str(labels.get("trivy-operator.resource.namespace") or metadata.get("namespace") or "cluster")
                kind = str(labels.get("trivy-operator.resource.kind") or "Workload")
                name = str(labels.get("trivy-operator.resource.name") or metadata.get("name") or "unknown")
                resource = f"{kind}/{ns}/{name}"
                report = report_crd.get("report") or {}
                rows = report.get("vulnerabilities") or report.get("checks") or report.get("secrets") or []
                if not rows:
                    summary = report.get("summary") or {}
                    for sev_key, sev in (("criticalCount", "CRITICAL"), ("highCount", "HIGH"), ("mediumCount", "MEDIUM"), ("lowCount", "LOW"), ("unknownCount", "UNKNOWN")):
                        count = int(summary.get(sev_key, 0) or 0)
                        for _ in range(count):
                            self._add(
                                title=f"{sev} {category} reported by Trivy", severity=sev, category=category,
                                resource=resource, layer="SCANNER", source="trivy-operator",
                                proof=f"Trivy Operator {plural} report for {resource} contains {sev} findings",
                                why=f"Trivy reports a {sev.lower()} {category.replace('_', ' ')} on this workload.",
                                fix="Review the Trivy recommendation and upgrade/reconfigure the affected workload.",
                                verify="Re-scan the workload and confirm the reported issue is gone.", issue_key=f"trivy-summary|{category}|{sev}",
                            )
                    continue
                # Inspect every row for aggregate counts, but keep only the top unique issues in memory.
                rows_sorted = sorted(rows, key=lambda x: SEVERITY_WEIGHT.get(_severity(x.get("severity")), 25), reverse=True)
                for row in rows_sorted:
                    sev = _severity(row.get("severity"))
                    title = _title(row)
                    cve = row.get("vulnerabilityID") or row.get("id") or row.get("checkID") or row.get("ruleID")
                    fix = _recommendation(row) or "Apply the scanner recommendation and redeploy the affected workload."
                    key = f"trivy|{category}|{cve or title}"
                    self._add(
                        title=title, severity=sev, category=category, resource=resource, layer="SCANNER", source="trivy-operator",
                        proof=f"Trivy Operator {plural}: {resource} · {cve or 'rule'} · severity {sev}",
                        why=f"Trivy verified this {sev.lower()} {category.replace('_', ' ')} on the workload.",
                        fix=fix, verify="Re-scan the workload and confirm this finding is no longer reported.",
                        cve=cve if category == "vulnerability" else None, issue_key=key,
                    )

    def collect(self) -> dict[str, Any]:
        self._scan_native()
        self._scan_trivy()
        issues = sorted(self.issues.values(), key=lambda x: (-x["score"], -SEVERITY_WEIGHT.get(x["severity"], 25), x["title"]))
        for index, issue in enumerate(issues, 1):
            issue["rank"] = index
            issue["affected_count"] = len(issue["affected_resources"])
            issue["evidence"] = issue.pop("proof")
            issue["fix"] = issue["fix"]
        severities = defaultdict(int)
        for issue in issues:
            if issue["category"] == "vulnerability":
                severities[issue["severity"]] += issue["occurrences"]

        total_misconfigs = sum(v for (category, _), v in self.counts.items() if category in {"misconfiguration", "native_misconfiguration", "privileged_container", "hostpath_mount", "control_plane", "network_isolation", "identity"})
        total_secrets = sum(v for (category, _), v in self.counts.items() if category == "exposed_secret")
        affected_resources = {r for issue in issues for r in issue["affected_resources"]}
        namespaces = {r.split("/")[1] for r in affected_resources if r.count("/") >= 2}
        known_points = severities["CRITICAL"] * 10 + severities["HIGH"] * 4 + severities["MEDIUM"] + total_misconfigs * 2 + total_secrets * 15
        workloads = max(1, len(affected_resources))
        import math
        penalty = min(95.0, 8.0 * math.sqrt(known_points / workloads)) if known_points else 0.0
        score = max(5, round(100 - penalty)) if known_points else 100

        summary = {
            "status": "AVAILABLE",
            "reason": None,
            "cluster_security_score": score,
            "score_basis": "Fast verified posture: native Kubernetes controls plus prioritized Trivy findings. Duplicate scanner findings are aggregated; scores are prioritization, not exploit probability.",
            "scored_vulnerabilities": sum(severities.values()),
            "unscored_unknown_vulnerabilities": severities["UNKNOWN"],
            "total_vulnerabilities": sum(severities.values()),
            "critical_vulnerabilities": severities["CRITICAL"],
            "high_vulnerabilities": severities["HIGH"],
            "medium_vulnerabilities": severities["MEDIUM"],
            "low_vulnerabilities": severities["LOW"],
            "unknown_vulnerabilities": severities["UNKNOWN"],
            "total_misconfigurations": total_misconfigs,
            "total_exposed_secrets": total_secrets,
            "affected_workloads": len(affected_resources),
            "affected_namespaces": len(namespaces),
            "top_10_risks": [],
            "top_recommendations": [i["fix"] for i in issues[:5]],
            "priority_issues": issues[:25],
            "total_unique_issues": len(issues),
            "coverage": dict(self.coverage),
        }
        diagnostics = {
            "mode": "fast-layered",
            "security_evidence_created": len(self.evidence),
            "priority_issues": len(issues),
            "trivy_rows_aggregated": sum(i["occurrences"] for i in issues if i["source"] == "trivy-operator"),
            "mongo_evidence_cap": self._evidence_limit,
        }
        return {"evidence": self.evidence, "summary": summary, "diagnostics": diagnostics}


SecurityEvidenceCollector = FastSecurityEvidenceCollector
