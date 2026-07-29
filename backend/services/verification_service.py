"""Generic post-remediation verification."""

from backend.kubernetes.toolkit import K8sToolkit

WORKLOAD_KINDS = {"deployment", "statefulset", "daemonset", "replicaset"}


def verify_remediation(target: dict, plan: dict, toolkit: K8sToolkit) -> dict:
    """Verify the actual outcome of a remediation for the target resource."""
    kind = (target.get("kind") or "").lower()
    namespace = target.get("namespace")
    name = target.get("name")
    checks = []

    if kind in WORKLOAD_KINDS:
        checks.extend(_verify_workload(kind, namespace, name, toolkit))
    elif kind == "pod":
        checks.extend(_verify_pod(namespace, name, toolkit))
    elif kind == "service":
        checks.extend(_verify_service(namespace, name, toolkit))
    else:
        resource = toolkit.get_resource(kind, namespace, name)
        checks.append({
            "name": f"{kind} exists",
            "status": "PASS" if resource.get("success") else "FAIL",
        })

    status = "RESOLVED"
    if any(c["status"] == "FAIL" for c in checks):
        status = "NOT_RESOLVED"

    return {
        "status": status,
        "checks": checks,
    }


def _verify_workload(kind: str, namespace: str | None, name: str, toolkit: K8sToolkit) -> list[dict]:
    checks = []

    resource = toolkit.get_resource(kind, namespace, name)
    if resource.get("success"):
        resource_data = resource["data"].get("resource", {})
        generation = resource_data.get("metadata", {}).get("generation", 0)
        observed = resource_data.get("status", {}).get("observed_generation") or resource_data.get("status", {}).get("observedGeneration", 0)
        if observed and observed == generation:
            checks.append({"name": "Observed generation", "status": "PASS"})
        elif observed:
            checks.append({"name": "Observed generation", "status": "WARN"})
        else:
            checks.append({"name": "Observed generation", "status": "FAIL"})
    else:
        checks.append({"name": "Observed generation", "status": "FAIL"})

    rollout = toolkit.get_rollout_status(kind, namespace, name)
    if rollout.get("success"):
        data = rollout.get("data", {})
        desired = data.get("desired", 0)
        ready = data.get("ready", 0)
        updated = data.get("updated")
        available = data.get("available", 0)
        unavailable = data.get("unavailable") or 0
        passed = (
            desired > 0
            and ready == desired
            and available == desired
            and not unavailable
        )
        if updated is not None:
            passed = passed and updated == desired
        checks.append({"name": "Deployment rollout", "status": "PASS" if passed else "FAIL"})
    else:
        checks.append({"name": "Deployment rollout", "status": "FAIL"})

    pods = toolkit.get_resources("pod", namespace)
    if pods.get("success"):
        items = pods["data"].get("items", [])
        def _pod_owned_by_target(pod, kind, name):
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
        owned = [
            pod
            for pod in items
            if _pod_owned_by_target(pod, kind, name)
        ]
        if owned:
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
            })
        else:
            checks.append({"name": "Pods Ready", "status": "FAIL"})
    else:
        checks.append({"name": "Pods Ready", "status": "FAIL"})

    events = toolkit.get_events(namespace, resource_name=name)
    if events.get("success"):
        warning_events = [
            e for e in events["data"].get("items", []) if e.get("type") == "Warning"
        ]
        checks.append({
            "name": "Warning events",
            "status": "PASS" if not warning_events else "WARN",
        })
    else:
        checks.append({"name": "Warning events", "status": "WARN"})

    return checks


def _verify_pod(namespace: str | None, name: str, toolkit: K8sToolkit) -> list[dict]:
    checks = []
    resource = toolkit.get_resource("pod", namespace, name)
    if resource.get("success"):
        pod = resource["data"].get("resource", {})
        phase = pod.get("status", {}).get("phase", "")
        conditions = pod.get("status", {}).get("conditions", [])
        ready = any(
            c.get("type") == "Ready" and c.get("status") == "True"
            for c in conditions
        )
        container_statuses = pod.get("status", {}).get("container_statuses") or pod.get("status", {}).get("containerStatuses", [])
        waiting_bad = any(
            ((c.get("state") or {}).get("waiting") or {}).get("reason")
            in ("ImagePullBackOff", "ErrImagePull", "CrashLoopBackOff")
            for c in container_statuses
        )
        checks.append({
            "name": "Pod Ready",
            "status": "PASS" if phase == "Running" and ready and not waiting_bad else "FAIL",
        })
    else:
        checks.append({"name": "Pod Ready", "status": "FAIL"})

    events = toolkit.get_events(namespace, resource_name=name)
    if events.get("success"):
        warnings = [
            e for e in events["data"].get("items", []) if e.get("type") == "Warning"
        ]
        checks.append({
            "name": "Warning events",
            "status": "PASS" if not warnings else "WARN",
        })
    else:
        checks.append({"name": "Warning events", "status": "WARN"})

    return checks


def _verify_service(namespace: str | None, name: str, toolkit: K8sToolkit) -> list[dict]:
    checks = []
    resource = toolkit.get_resource("service", namespace, name)
    checks.append({
        "name": "Service exists",
        "status": "PASS" if resource.get("success") else "FAIL",
    })

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

    events = toolkit.get_events(namespace, resource_name=name)
    if events.get("success"):
        warnings = [
            e for e in events["data"].get("items", []) if e.get("type") == "Warning"
        ]
        checks.append({
            "name": "Warning events",
            "status": "PASS" if not warnings else "WARN",
        })
    else:
        checks.append({"name": "Warning events", "status": "WARN"})

    return checks
