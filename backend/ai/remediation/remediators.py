from __future__ import annotations

import json
from typing import Any

from backend.ai.remediation.base import Remediation, Remediator
from backend.ai.remediation.resolvers import is_known_tag, resolve_safe_tag
from backend.kubernetes.toolkit import SCALABLE_KINDS


def _diagnosis_context(diagnosis: dict[str, Any]) -> str:
    """Flatten the diagnosis and evidence into a lowercase search string."""
    evidence = diagnosis.get("evidence") or []
    parts = [json.dumps(diagnosis, default=str), json.dumps(evidence, default=str)]
    return " ".join(parts).lower()


def _live_event_context(toolkit: Any, namespace: str | None, name: str) -> str:
    """Gather pod/warning events for the workload to improve classification."""
    fragments: list[str] = []
    if not namespace:
        return ""
    try:
        result = toolkit.get_events(namespace=namespace, resource_name=name)
        if result.get("success"):
            for item in result.get("data", {}).get("items") or []:
                msg = " ".join(
                    str(item.get(k, ""))
                    for k in ("message", "reason", "type", "note")
                )
                fragments.append(msg)
    except Exception:
        pass
    return " ".join(fragments).lower()


class ImagePullBackOffRemediator(Remediator):
    """Root-cause remediation for image pull failures."""

    def propose(
        self,
        diagnosis: dict[str, Any],
        resource: dict[str, str],
        manifest: dict[str, Any],
        toolkit: Any,
    ) -> Remediation | None:
        text = _diagnosis_context(diagnosis)
        if not any(k in text for k in ("imagepullbackoff", "errimagepull", "back-off pulling image")):
            return None

        text += " " + _live_event_context(toolkit, resource.get("namespace"), resource.get("name"))

        category = self._classify(text)

        containers = (
            ((manifest.get("spec") or {}).get("template") or {}).get("spec") or {}
        ).get("containers") or []
        if not isinstance(containers, list):
            return None

        # If the text is not conclusive, treat a well-known image with an
        # unrecognised tag as a non-existent tag case.
        if category == "unknown":
            for container in containers:
                current = container.get("image", "")
                if resolve_safe_tag(current) and not is_known_tag(current):
                    category = "image_not_found"
                    break
            if category == "unknown":
                return None

        if category == "image_not_found":
            return self._build_image_patch(resource, manifest, containers)
        if category == "private_registry":
            return self._need_input(
                resource,
                "Private registry authentication required",
                "Attach the correct imagePullSecret to the ServiceAccount for this namespace.",
            )
        if category == "dns_failure":
            return self._need_input(
                resource,
                "DNS resolution failure for image registry",
                "Check DNS/network connectivity; do not change the container image.",
            )
        if category == "registry_timeout":
            return self._need_input(
                resource,
                "Registry timeout while pulling image",
                "Retry the pull and verify registry health; do not change the container image.",
            )
        return None

    def _classify(self, text: str) -> str:
        if any(k in text for k in ("unauthorized", "authentication required", "denied", "401")):
            return "private_registry"
        if any(k in text for k in ("no such host", "lookup", "dns", "resolve", "name resolution")):
            return "dns_failure"
        if any(k in text for k in ("i/o timeout", "timeout", "context deadline exceeded", "net/http")):
            return "registry_timeout"
        if any(
            k in text
            for k in (
                "not found",
                "does not exist",
                "unknown manifest",
                "manifest unknown",
                "manifest not known",
                "no such image",
            )
        ):
            return "image_not_found"
        return "unknown"

    def _build_image_patch(
        self,
        resource: dict[str, str],
        manifest: dict[str, Any],
        containers: list[dict[str, Any]],
    ) -> Remediation | None:
        patches: list[dict[str, str]] = []
        changes: list[dict[str, str]] = []
        first_image = ""
        for i, container in enumerate(containers):
            name = container.get("name")
            current = container.get("image")
            if not name or not current:
                continue
            if not first_image:
                first_image = current
            safe = resolve_safe_tag(current)
            if not safe or safe == current or is_known_tag(current):
                continue
            patches.append({"name": name, "image": safe})
            changes.append(
                {
                    "path": f"spec.template.spec.containers[{i}].image",
                    "before": current,
                    "after": safe,
                }
            )

        if not patches:
            return self._need_input(
                resource,
                "Image tag cannot be verified",
                "Known tags could not be verified for this image. Select an existing tag from the registry.",
            )

        patch = {"spec": {"template": {"spec": {"containers": patches}}}}
        target = f"{resource['kind']}/{resource.get('namespace') or 'default'}/{resource['name']}"
        after = patches[0]["image"]
        set_image_cmds = [
            f"kubectl set image {resource['kind']}/{resource['name']} "
            f"{p['name']}={p['image']} -n {resource.get('namespace') or 'default'}"
            for p in patches
        ]
        return Remediation(
            root_cause=f"Container image {first_image} does not exist." if first_image else "Container image does not exist.",
            confidence=0.98,
            risk="LOW",
            remediation_type="PATCH",
            tool="patch_resource",
            arguments={
                "kind": resource["kind"],
                "namespace": resource.get("namespace"),
                "name": resource["name"],
                "patch": patch,
            },
            target=resource,
            changes=changes,
            reason="Image tag does not exist.",
            verification={"type": "rollout_status", "expected": "deployment rolled out and pods become ready"},
            rollback={"available": True, "strategy": f"kubectl rollout undo {resource['kind']}/{resource['name']} -n {resource.get('namespace') or 'default'}"},
            kubectl_commands=set_image_cmds,
            verification_steps=[
                f"kubectl rollout status {resource['kind']}/{resource['name']} -n {resource.get('namespace') or 'default'}",
                "Verify pods are Ready",
                "Verify Deployment has Available replicas",
                "Verify expected replica count",
                "Check pod events for normal pull progress",
            ],
            rollback_steps=[
                f"kubectl rollout undo {resource['kind']}/{resource['name']} -n {resource.get('namespace') or 'default'}",
            ],
            summary=f"Patch container image to {after}",
        )

    def _need_input(
        self,
        resource: dict[str, str],
        root_cause: str,
        reason: str,
    ) -> Remediation:
        return Remediation(
            root_cause=root_cause,
            confidence=0.85,
            risk="MEDIUM",
            remediation_type="NEED_USER_INPUT",
            tool=None,
            arguments={},
            target=resource,
            changes=[],
            reason=reason,
            verification={"type": "manual", "expected": "User provides a valid value or configuration"},
            rollback={"available": False, "strategy": "N/A"},
            kubectl_commands=[],
            verification_steps=[],
            rollback_steps=[],
            question=reason,
            summary="User input required",
        )


class ContainmentRemediator(Remediator):
    """Emergency containment fallback: scale the workload to zero replicas."""

    SEVERE_SYMPTOMS = (
        "imagepullbackoff",
        "errimagepull",
        "crashloopbackoff",
        "oomkilled",
        "not ready",
        "unhealthy",
        "failing",
        "back-off",
        "failed",
    )

    def propose(
        self,
        diagnosis: dict[str, Any],
        resource: dict[str, str],
        manifest: dict[str, Any],
        toolkit: Any,
    ) -> Remediation | None:
        text = _diagnosis_context(diagnosis)
        if not any(symptom in text for symptom in self.SEVERE_SYMPTOMS):
            return None
        if resource.get("kind", "").lower() not in SCALABLE_KINDS:
            return None

        replicas = (((manifest.get("spec") or {}).get("replicas")) or 1)
        return Remediation(
            root_cause="Unable to safely determine root cause",
            confidence=0.3,
            risk="MEDIUM",
            remediation_type="CONTAINMENT",
            tool="scale_workload",
            arguments={
                "kind": resource["kind"],
                "namespace": resource.get("namespace"),
                "name": resource["name"],
                "replicas": 0,
            },
            target=resource,
            changes=[{"path": "spec.replicas", "before": str(replicas), "after": "0"}],
            reason="Unable to safely determine root cause. Scale to zero as emergency containment.",
            verification={"type": "pods_ready", "expected": "zero pods running"},
            rollback={
                "available": True,
                "strategy": f"Scale {resource['kind']}/{resource['name']} back to {replicas} replicas",
            },
            kubectl_commands=[
                f"kubectl scale {resource['kind']}/{resource['name']} --replicas=0 -n {resource.get('namespace') or 'default'}"
            ],
            verification_steps=[
                f"kubectl get pods -n {resource.get('namespace') or 'default'} -l app={resource['name']}",
                "Confirm zero pods are running",
            ],
            rollback_steps=[
                f"kubectl scale {resource['kind']}/{resource['name']} --replicas={replicas} -n {resource.get('namespace') or 'default'}"
            ],
            summary="Scale workload to zero (containment)",
        )


class CrashLoopBackOffRemediator(Remediator):
    def propose(
        self,
        diagnosis: dict[str, Any],
        resource: dict[str, str],
        manifest: dict[str, Any],
        toolkit: Any,
    ) -> Remediation | None:
        return None


class OOMKilledRemediator(Remediator):
    def propose(
        self,
        diagnosis: dict[str, Any],
        resource: dict[str, str],
        manifest: dict[str, Any],
        toolkit: Any,
    ) -> Remediation | None:
        return None


class ReadinessProbeRemediator(Remediator):
    def propose(
        self,
        diagnosis: dict[str, Any],
        resource: dict[str, str],
        manifest: dict[str, Any],
        toolkit: Any,
    ) -> Remediation | None:
        return None


class ServiceSelectorRemediator(Remediator):
    def propose(
        self,
        diagnosis: dict[str, Any],
        resource: dict[str, str],
        manifest: dict[str, Any],
        toolkit: Any,
    ) -> Remediation | None:
        return None


class PVCPendingRemediator(Remediator):
    def propose(
        self,
        diagnosis: dict[str, Any],
        resource: dict[str, str],
        manifest: dict[str, Any],
        toolkit: Any,
    ) -> Remediation | None:
        return None


class ConfigMapRemediator(Remediator):
    def propose(
        self,
        diagnosis: dict[str, Any],
        resource: dict[str, str],
        manifest: dict[str, Any],
        toolkit: Any,
    ) -> Remediation | None:
        return None


class SecretRemediator(Remediator):
    def propose(
        self,
        diagnosis: dict[str, Any],
        resource: dict[str, str],
        manifest: dict[str, Any],
        toolkit: Any,
    ) -> Remediation | None:
        return None


class NodeNotReadyRemediator(Remediator):
    def propose(
        self,
        diagnosis: dict[str, Any],
        resource: dict[str, str],
        manifest: dict[str, Any],
        toolkit: Any,
    ) -> Remediation | None:
        return None
