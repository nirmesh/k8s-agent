from backend.kubernetes.executor import run_kubectl_json
from backend.core.logging import logger


def inspect_network() -> dict:
    """Inspect services and networking for missing endpoints and selector issues."""
    services_data = run_kubectl_json(["get", "svc", "--all-namespaces"])
    endpoints_data = run_kubectl_json(["get", "endpoints", "--all-namespaces"])

    if services_data is None:
        logger.error("Failed to retrieve services")
        return {"total_services": 0, "issues": [], "error": "kubectl failed"}

    services = services_data.get("items", [])
    endpoints = endpoints_data.get("items", []) if endpoints_data is not None else []

    ep_map = {}
    for ep in endpoints:
        metadata = ep.get("metadata", {})
        key = (metadata.get("namespace"), metadata.get("name"))
        ep_map[key] = ep.get("subsets", [])

    issues = []
    for svc in services:
        metadata = svc.get("metadata", {})
        spec = svc.get("spec", {})

        namespace = metadata.get("namespace")
        name = metadata.get("name")
        selector = spec.get("selector") or {}
        svc_type = spec.get("type", "")

        if svc_type == "ExternalName":
            continue

        subsets = ep_map.get((namespace, name), [])
        if not subsets and selector:
            issues.append({
                "name": name,
                "namespace": namespace,
                "type": svc_type,
                "issue": "missing_endpoints",
                "message": "Service has a selector but no matching endpoints",
            })
        elif not selector and not subsets:
            issues.append({
                "name": name,
                "namespace": namespace,
                "type": svc_type,
                "issue": "no_selector_and_no_endpoints",
                "message": "Service has no selector and no endpoints",
            })

    return {
        "total_services": len(services),
        "issues": issues,
    }
