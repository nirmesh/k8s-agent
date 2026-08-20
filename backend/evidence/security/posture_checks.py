from __future__ import annotations

from typing import Any


def _items(result: dict[str, Any]) -> list[dict[str, Any]]:
    return ((result.get("data") or {}).get("items") or []) if result.get("success") else []


def _args_for(pod: dict[str, Any]) -> list[str]:
    args: list[str] = []
    for container in (pod.get("spec") or {}).get("containers") or []:
        args.extend(container.get("command") or [])
        args.extend(container.get("args") or [])
    return [str(value) for value in args]


def _check(check_id: str, title: str, status: str, domain: str, detail: str, severity: str = "INFO", resource: str | None = None, recommendation: str | None = None) -> dict[str, Any]:
    return {
        "id": check_id,
        "title": title,
        "status": status,
        "domain": domain,
        "severity": severity,
        "detail": detail,
        "resource": resource,
        "recommendation": recommendation,
    }


def collect_native_posture_checks(toolkit: Any, posture_findings: list[Any]) -> list[dict[str, Any]]:
    """Return positive/negative control state separately from risk findings.

    Findings answer "what is risky?"; these checks answer "what is configured?".
    This makes a healthy control visible instead of silently omitting it.
    """
    checks: list[dict[str, Any]] = []
    kube_system = _items(toolkit.get_resources("pod", "kube-system"))
    apiserver = next(
        (pod for pod in kube_system if str((pod.get("metadata") or {}).get("name", "")).startswith("kube-apiserver")),
        None,
    )
    etcd = next(
        (pod for pod in kube_system if str((pod.get("metadata") or {}).get("name", "")).startswith("etcd-")),
        None,
    )

    if apiserver:
        api_name = (apiserver.get("metadata") or {}).get("name", "kube-apiserver")
        api_resource = f"Pod/kube-system/{api_name}"
        args = _args_for(apiserver)
        auth_mode = next((a.split("=", 1)[1] for a in args if a.startswith("--authorization-mode=")), "")
        if "RBAC" in {part.strip() for part in auth_mode.split(",")}:
            checks.append(_check("K8S-CONTROL-RBAC", "RBAC authorization", "PASS", "identity", "kube-apiserver advertises RBAC in --authorization-mode.", resource=api_resource))
        else:
            checks.append(_check("K8S-CONTROL-RBAC", "RBAC authorization", "FAIL", "identity", "RBAC is not visible in kube-apiserver --authorization-mode.", "HIGH", api_resource, "Enable RBAC authorization and verify it is enforced."))

        anonymous = next((a.split("=", 1)[1].lower() for a in args if a.startswith("--anonymous-auth=")), None)
        if anonymous == "false":
            checks.append(_check("K8S-CONTROL-ANONYMOUS", "Anonymous authentication", "PASS", "control_plane", "kube-apiserver explicitly disables anonymous authentication.", resource=api_resource))
        elif anonymous == "true":
            checks.append(_check("K8S-CONTROL-ANONYMOUS", "Anonymous authentication", "FAIL", "control_plane", "kube-apiserver explicitly allows anonymous authentication.", "HIGH", api_resource, "Disable anonymous authentication unless a documented component requires it."))
        else:
            checks.append(_check("K8S-CONTROL-ANONYMOUS", "Anonymous authentication", "NOT_VERIFIED", "control_plane", "No explicit --anonymous-auth setting is visible; effective/default behavior is not inferred.", "INFO", api_resource))

        encryption = next((a for a in args if a.startswith("--encryption-provider-config=")), None)
        if encryption:
            checks.append(_check("K8S-DATASTORE-ENCRYPTION", "Secrets encryption at rest", "PASS", "secrets", f"kube-apiserver references {encryption.split('=', 1)[1]} via --encryption-provider-config.", resource=api_resource))
        else:
            checks.append(_check("K8S-DATASTORE-ENCRYPTION", "Secrets encryption at rest", "FAIL", "secrets", "No --encryption-provider-config is visible on kube-apiserver, so encryption at rest is not evidenced by static pod configuration.", "HIGH", api_resource, "Configure encryption at rest and verify sensitive resources such as Secrets use an encryption provider."))
    else:
        checks.extend([
            _check("K8S-CONTROL-RBAC", "RBAC authorization", "NOT_VERIFIED", "identity", "kube-apiserver pod was not visible in kube-system; the control-plane check could not verify its flags."),
            _check("K8S-CONTROL-ANONYMOUS", "Anonymous authentication", "NOT_VERIFIED", "control_plane", "kube-apiserver pod was not visible in kube-system."),
            _check("K8S-DATASTORE-ENCRYPTION", "Secrets encryption at rest", "NOT_VERIFIED", "secrets", "kube-apiserver pod was not visible in kube-system; encryption configuration could not be verified."),
        ])

    if etcd:
        etcd_name = (etcd.get("metadata") or {}).get("name", "etcd")
        etcd_resource = f"Pod/kube-system/{etcd_name}"
        args = _args_for(etcd)
        client_auth = any(a == "--client-cert-auth=true" for a in args)
        peer_auth = any(a == "--peer-client-cert-auth=true" for a in args)
        checks.append(_check(
            "K8S-DATASTORE-CLIENT-TLS", "etcd client certificate authentication", "PASS" if client_auth else "FAIL", "control_plane",
            "etcd requires client certificates." if client_auth else "etcd does not visibly require client certificates.",
            "INFO" if client_auth else "HIGH", etcd_resource,
            None if client_auth else "Enable --client-cert-auth=true and verify the client CA configuration.",
        ))
        checks.append(_check(
            "K8S-DATASTORE-PEER-TLS", "etcd peer certificate authentication", "PASS" if peer_auth else "FAIL", "control_plane",
            "etcd requires peer client certificates." if peer_auth else "etcd does not visibly require peer client certificates.",
            "INFO" if peer_auth else "MEDIUM", etcd_resource,
            None if peer_auth else "Enable --peer-client-cert-auth=true and verify the peer CA configuration.",
        ))
    else:
        checks.extend([
            _check("K8S-DATASTORE-CLIENT-TLS", "etcd client certificate authentication", "NOT_VERIFIED", "control_plane", "etcd pod was not visible in kube-system."),
            _check("K8S-DATASTORE-PEER-TLS", "etcd peer certificate authentication", "NOT_VERIFIED", "control_plane", "etcd pod was not visible in kube-system."),
        ])

    finding_rules = {getattr(getattr(finding, "payload", None), "rule_id", None) for finding in posture_findings}
    if any(rule == "K8S-POSTURE-RBAC-CLUSTERADMIN" or rule == "K8S-POSTURE-RBAC-NAMESPACE-CLUSTERADMIN" for rule in finding_rules):
        checks.append(_check("K8S-RBAC-CLUSTERADMIN", "Excessive cluster-admin exposure", "FAIL", "identity", "One or more identities are granted cluster-admin outside the expected infrastructure context.", "HIGH", recommendation="Review cluster-admin bindings and replace them with least-privilege roles where possible."))
    else:
        checks.append(_check("K8S-RBAC-CLUSTERADMIN", "Excessive cluster-admin exposure", "PASS", "identity", "No non-infrastructure cluster-admin exposure was identified by the native posture rules."))

    return checks
