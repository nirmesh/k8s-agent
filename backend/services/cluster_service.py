import os
from typing import Any

import yaml

from backend.core.config import settings
from backend.core.logging import logger


def list_clusters() -> list[dict[str, Any]]:
    """List Kubernetes contexts from the local kubeconfig file."""
    path = os.path.expanduser(os.path.expandvars(settings.kubeconfig_path))

    if not os.path.isfile(path):
        logger.warning(f"kubeconfig not found at {path}")
        return []

    try:
        with open(path, "r") as f:
            config = yaml.safe_load(f)
    except Exception as exc:
        logger.error(f"Failed to parse kubeconfig: {exc}")
        return []

    contexts = config.get("contexts", []) or []
    clusters = {c["name"]: c.get("cluster", {}) for c in config.get("clusters", []) or []}
    current_context = config.get("current-context", "")

    result = []
    for ctx in contexts:
        name = ctx.get("name", "")
        ctx_info = ctx.get("context", {}) or {}
        cluster_name = ctx_info.get("cluster", "")
        cluster = clusters.get(cluster_name, {})
        result.append({
            "name": name,
            "current": name == current_context,
            "server": cluster.get("server", ""),
            "namespace": ctx_info.get("namespace", "default"),
            "cluster_name": cluster_name,
        })

    return result
