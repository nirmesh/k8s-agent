from __future__ import annotations

from typing import Any

from backend.evidence.security.posture import evaluate_cluster_posture
from backend.evidence.security.provider import SecurityProvider


class KubernetesPostureAdapter(SecurityProvider):
    """Built-in read-only Kubernetes security posture checks."""

    def __init__(self, source: Any | None = None):
        self.source = source

    @property
    def name(self) -> str:
        return "kubernetes-posture"

    def collect(self, query: dict[str, Any] | None = None):
        if self.source is None:
            return []
        return evaluate_cluster_posture(self.source)

    def health(self) -> dict[str, Any]:
        return {"healthy": self.source is not None, "mode": "kubernetes-api"}
