"""Generic post-remediation verification."""

from backend.kubernetes.toolkit import K8sToolkit


def verify_remediation(target: dict, plan: dict, toolkit: K8sToolkit) -> dict:
    """Verify the actual outcome of a remediation using the success criteria in the plan."""
    kind = (target.get("kind") or "").lower()
    namespace = target.get("namespace")
    name = target.get("name")
    checks = []

    verification = (plan or {}).get("verification") or {}
    vtype = (verification.get("type") or "").lower()
    expected = verification.get("expected", "")

    if vtype == "resource_exists" or not vtype:
        resource = toolkit.get_resource(kind, namespace, name)
        checks.append({
            "name": f"{kind} exists",
            "status": "PASS" if resource.get("success") else "FAIL",
            "detail": expected,
        })
    elif vtype == "resource_ready":
        checks.extend(_verify_resource_ready(kind, namespace, name, toolkit))
    elif vtype == "rollout_status":
        checks.extend(_verify_rollout_status(kind, namespace, name, toolkit))
    elif vtype == "endpoints_ready":
        checks.extend(_verify_endpoints_ready(namespace, name, toolkit))
    elif vtype == "pods_ready":
        checks.extend(_verify_pods_ready(kind, namespace, name, toolkit))
    elif vtype == "pvc_bound":
        checks.extend(_verify_pvc_bound(namespace, name, toolkit))
    elif vtype == "pod_scheduled":
        checks.extend(_verify_pod_scheduled(namespace, name, toolkit))
    elif vtype == "pod_ready":
        checks.extend(_verify_pod_ready(namespace, name, toolkit))
    else:
        checks.append({
            "name": f"Verification '{vtype}'",
            "status": "WARN",
            "detail": f"Unknown verification type. Expected: {expected}",
        })

    status = "RESOLVED"
    if any(c["status"] == "FAIL" for c in checks):
        status = "NOT_RESOLVED"

    return {
        "status": status,
        "checks": checks,
    }


def _verify_resource_ready(kind: str, namespace: str | None, name: str, toolkit: K8sToolkit) -> list[dict]:
    checks = []
    resource = toolkit.get_resource(kind, namespace, name)
    if not resource.get("success"):
        checks.append({"name": "Resource exists", "status": "FAIL"})
        return checks

    data = resource["data"].get("resource", {})
    status = data.get("status", {})

    if kind in ("deployment", "statefulset", "daemonset", "replicaset"):
        desired = data.get("spec", {}).get("replicas")
        ready = status.get("ready_replicas") or status.get("readyReplicas") or 0
        available = status.get("available_replicas") or status.get("availableReplicas") or 0
        passed = (
            desired is not None
            and ready is not None
            and available is not None
            and ready >= desired
            and available >= desired
        )
        checks.append({
            "name": "Replicas ready/available",
            "status": "PASS" if passed else "FAIL",
            "detail": f"desired={desired}, ready={ready}, available={available}",
        })
    elif kind == "pod":
        checks.extend(_pod_ready_checks(data))
    elif kind == "service":
        checks.extend(_verify_endpoints_ready(namespace, name, toolkit))
    elif kind == "persistentvolumeclaim":
        checks.extend(_verify_pvc_bound(namespace, name, toolkit))
    else:
        checks.append({
            "name": "Resource ready",
            "status": "WARN",
            "detail": f"No readiness heuristic for kind {kind}",
        })

    return checks


def _verify_rollout_status(kind: str, namespace: str | None, name: str, toolkit: K8sToolkit) -> list[dict]:
    checks = []
    resource = toolkit.get_resource(kind, namespace, name)
    if not resource.get("success"):
        checks.append({"name": "Resource exists", "status": "FAIL"})
        return checks

    data = resource["data"].get("resource", {})
    generation = data.get("metadata", {}).get("generation", 0)
    observed = (
        data.get("status", {}).get("observed_generation")
        or data.get("status", {}).get("observedGeneration")
        or 0
    )
    if observed and observed == generation:
        checks.append({"name": "Observed generation", "status": "PASS"})
    elif observed:
        checks.append({"name": "Observed generation", "status": "WARN"})
    else:
        checks.append({"name": "Observed generation", "status": "FAIL"})

    rollout = toolkit.get_rollout_status(kind, namespace, name)
    if rollout.get("success"):
        rdata = rollout.get("data", {})
        desired = rdata.get("desired", 0)
        ready = rdata.get("ready", 0)
        updated = rdata.get("updated")
        available = rdata.get("available", 0)
        unavailable = rdata.get("unavailable") or 0
        passed = (
            desired > 0
            and ready == desired
            and available == desired
            and not unavailable
        )
        if updated is not None:
            passed = passed and updated == desired
        checks.append({
            "name": "Rollout status",
            "status": "PASS" if passed else "FAIL",
            "detail": f"desired={desired}, ready={ready}, updated={updated}, available={available}, unavailable={unavailable}",
        })
    else:
        checks.append({"name": "Rollout status", "status": "FAIL"})

    checks.extend(_verify_pods_ready(kind, namespace, name, toolkit))
    return checks


def _verify_pods_ready(kind: str, namespace: str | None, name: str, toolkit: K8sToolkit) -> list[dict]:
    checks = []
    pods = toolkit.get_resources("pod", namespace)
    if not pods.get("success"):
        checks.append({"name": "Pods Ready", "status": "FAIL"})
        return checks

    items = pods["data"].get("items", [])
    owned = [p for p in items if _pod_owned_by_target(p, kind, name, namespace, toolkit)]
    if not owned:
        checks.append({"name": "Pods Ready", "status": "FAIL", "detail": "No owned pods found"})
        return checks

    ready_count = 0
    for pod in owned:
        pod_status = pod.get("status", {})
        phase = pod_status.get("phase", "")
        conditions = pod_status.get("conditions", [])
        ready = any(
            c.get("type") == "Ready" and c.get("status") == "True"
            for c in conditions
        )
        container_statuses = pod_status.get("container_statuses") or pod_status.get("containerStatuses", [])
        containers_ready = all(
            c.get("ready") and c.get("state") is not None and "running" in c.get("state")
            for c in container_statuses
        )
        if phase == "Running" and ready and containers_ready:
            ready_count += 1

    checks.append({
        "name": "Pods Ready",
        "status": "PASS" if ready_count == len(owned) else "FAIL",
        "detail": f"{ready_count}/{len(owned)} owned pods ready",
    })
    return checks


def _pod_owned_by_target(pod: dict, kind: str, name: str, namespace: str | None, toolkit: K8sToolkit) -> bool:
    for ref in pod.get("metadata", {}).get("owner_references") or pod.get("metadata", {}).get("ownerReferences", []):
        ref_kind = ref.get("kind", "").lower()
        ref_name = ref.get("name", "")
        if ref_kind == kind and ref_name == name:
            return True
        if ref_kind == "replicaset" and kind == "deployment":
            owner = toolkit.get_owner("replicaset", namespace, ref_name)
            if owner.get("success"):
                for o in owner.get("data", {}).get("owners", []):
                    o_kind = (o.get("kind") or "").lower()
                    o_name = o.get("metadata", {}).get("name") or o.get("name", "")
                    if o_kind == "deployment" and o_name == name:
                        return True
    return False


def _verify_endpoints_ready(namespace: str | None, name: str, toolkit: K8sToolkit) -> list[dict]:
    checks = []
    endpoints = toolkit.get_resource("endpoints", namespace, name)
    if endpoints.get("success"):
        ep = endpoints["data"].get("resource", {})
        subsets = ep.get("subsets") or []
        has_addresses = any(
            subset.get("addresses")
            for subset in subsets
        )
        checks.append({
            "name": "Endpoints ready",
            "status": "PASS" if has_addresses else "FAIL",
        })
    else:
        checks.append({"name": "Endpoints ready", "status": "FAIL"})
    return checks


def _verify_pvc_bound(namespace: str | None, name: str, toolkit: K8sToolkit) -> list[dict]:
    checks = []
    pvc = toolkit.get_resource("persistentvolumeclaim", namespace, name)
    if pvc.get("success"):
        phase = pvc["data"].get("resource", {}).get("status", {}).get("phase", "")
        checks.append({
            "name": "PVC Bound",
            "status": "PASS" if phase == "Bound" else "FAIL",
            "detail": f"phase={phase}",
        })
    else:
        checks.append({"name": "PVC Bound", "status": "FAIL"})
    return checks


def _verify_pod_scheduled(namespace: str | None, name: str, toolkit: K8sToolkit) -> list[dict]:
    checks = []
    pod = toolkit.get_resource("pod", namespace, name)
    if pod.get("success"):
        spec = pod["data"].get("resource", {}).get("spec", {})
        scheduled = bool(spec.get("nodeName"))
        checks.append({
            "name": "Pod scheduled",
            "status": "PASS" if scheduled else "FAIL",
        })
    else:
        checks.append({"name": "Pod scheduled", "status": "FAIL"})
    return checks


def _verify_pod_ready(namespace: str | None, name: str, toolkit: K8sToolkit) -> list[dict]:
    checks = []
    resource = toolkit.get_resource("pod", namespace, name)
    if not resource.get("success"):
        checks.append({"name": "Pod Ready", "status": "FAIL"})
        return checks

    pod = resource["data"].get("resource", {})
    checks.extend(_pod_ready_checks(pod))
    return checks


def _pod_ready_checks(pod: dict) -> list[dict]:
    checks = []
    pod_status = pod.get("status", {})
    phase = pod_status.get("phase", "")
    conditions = pod_status.get("conditions", [])
    ready = any(
        c.get("type") == "Ready" and c.get("status") == "True"
        for c in conditions
    )
    container_statuses = pod_status.get("container_statuses") or pod_status.get("containerStatuses", [])
    waiting = any(
        ((c.get("state") or {}).get("waiting") or {}).get("reason")
        for c in container_statuses
    )
    checks.append({
        "name": "Pod Ready",
        "status": "PASS" if phase == "Running" and ready and not waiting else "FAIL",
        "detail": f"phase={phase}, ready={ready}, waiting={waiting}",
    })
    return checks
