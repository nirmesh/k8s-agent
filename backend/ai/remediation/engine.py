from __future__ import annotations

from typing import Any

from backend.ai.remediation.base import Remediation, Remediator
from backend.ai.remediation.remediators import (
    ConfigMapRemediator,
    ContainmentRemediator,
    CrashLoopBackOffRemediator,
    ImagePullBackOffRemediator,
    NodeNotReadyRemediator,
    OOMKilledRemediator,
    PVCPendingRemediator,
    ReadinessProbeRemediator,
    SecretRemediator,
    ServiceSelectorRemediator,
)


DEFAULT_REMEDIATORS: list[Remediator] = [
    ImagePullBackOffRemediator(),
    CrashLoopBackOffRemediator(),
    OOMKilledRemediator(),
    ReadinessProbeRemediator(),
    ServiceSelectorRemediator(),
    PVCPendingRemediator(),
    ConfigMapRemediator(),
    SecretRemediator(),
    NodeNotReadyRemediator(),
    ContainmentRemediator(),
]


class RemediationEngine:
    """Rule-based remediation engine that selects the best corrective action."""

    def __init__(
        self,
        toolkit: Any,
        remediators: list[Remediator] | None = None,
    ):
        self.toolkit = toolkit
        self.remediators = remediators or DEFAULT_REMEDIATORS

    def propose(
        self,
        diagnosis: dict[str, Any],
        resource: dict[str, str],
        manifest: dict[str, Any],
    ) -> Remediation | None:
        """Evaluate all remediators and return the preferred remediation.

        Root-cause fixes are always preferred over containment, and the highest
        confidence candidate wins within each group.
        """
        resource_manifest = (
            manifest.get("resource", manifest)
            if isinstance(manifest, dict) and "resource" in manifest
            else manifest
        )
        candidates: list[Remediation] = []
        for remediator in self.remediators:
            candidate = remediator.propose(diagnosis, resource, resource_manifest, self.toolkit)
            if candidate:
                candidates.append(candidate)

        if not candidates:
            return None

        # Sort: root-cause first (CONTAINMENT goes last), then highest confidence.
        return sorted(
            candidates,
            key=lambda c: (c.remediation_type == "CONTAINMENT", -c.confidence),
        )[0]
