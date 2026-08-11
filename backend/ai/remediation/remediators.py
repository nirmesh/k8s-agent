from __future__ import annotations

import json
from typing import Any

from backend.ai.remediation.base import Remediation, Remediator
from backend.ai.remediation.resolvers import is_known_tag, resolve_safe_tag
from backend.kubernetes.toolkit import SCALABLE_KINDS


# Images for which a root HTTP GET ("/") is a safe, well-known health check.
# This is deliberately conservative; for other images we ask the user.
_WELL_KNOWN_ROOT_HEALTH = {"nginx"}


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


def _image_repo(image: str) -> str:
    repo = image.split(":")[0].split("@")[0].split("/")[-1].lower()
    return repo


def _need_input(
    resource: dict[str, str],
    root_cause: str,
    reason: str,
    field_path: str | None = None,
) -> Remediation:
    return Remediation(
        root_cause=root_cause,
        confidence=0.7,
        risk="MEDIUM",
        remediation_type="NEED_USER_INPUT",
        tool=None,
        arguments={},
        target=resource,
        changes=[],
        field_path=field_path,
        reason=reason,
        verification={"type": "manual", "expected": "User provides a valid value or configuration"},
        rollback={"available": False, "strategy": "N/A"},
        kubectl_commands=[],
        verification_steps=[],
        rollback_steps=[],
        question=reason,
        summary="User input required",
    )


class ImagePullBackOffRemediator(Remediator):
    """Root-cause remediation for image pull failures."""

    _IMAGE_PULL_KEYWORDS = (
        "imagepullbackoff",
        "errimagepull",
        "back-off pulling image",
        "failed to pull image",
    )

    _IMAGE_NOT_FOUND_KEYWORDS = (
        "not found",
        "does not exist",
        "unknown manifest",
        "manifest unknown",
        "manifest not known",
        "no such image",
    )

    def propose(
        self,
        diagnosis: dict[str, Any],
        resource: dict[str, str],
        manifest: dict[str, Any],
        toolkit: Any,
    ) -> Remediation | None:
        text = _diagnosis_context(diagnosis)
        live = _live_event_context(toolkit, resource.get("namespace"), resource.get("name"))

        # Evidence-linked activation: the root cause or live events for THIS
        # resource must explicitly indicate an image pull failure.
        root_type = str(diagnosis.get("rootCauseType") or "").lower()
        if root_type != "image_pull_failure" and not any(k in text for k in self._IMAGE_PULL_KEYWORDS):
            return None
        if not any(k in text for k in self._IMAGE_PULL_KEYWORDS):
            if not any(k in live for k in self._IMAGE_PULL_KEYWORDS):
                return None

        text = f"{text} {live}".lower()
        category = self._classify(text)

        containers = (
            (((manifest.get("spec") or {}).get("template") or {}).get("spec") or {})
            .get("containers") or []
        )
        if not isinstance(containers, list):
            return None

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
            return _need_input(
                resource,
                "Private registry authentication required",
                "Attach the correct imagePullSecret to the ServiceAccount for this namespace.",
                field_path="spec.template.spec.containers[].imagePullSecret",
            )
        if category == "dns_failure":
            return _need_input(
                resource,
                "DNS resolution failure for image registry",
                "Check DNS/network connectivity; do not change the container image.",
            )
        if category == "registry_timeout":
            return _need_input(
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
        if any(k in text for k in self._IMAGE_NOT_FOUND_KEYWORDS):
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
            return _need_input(
                resource,
                "Image tag cannot be verified",
                "No automatically validated replacement image is available.",
                field_path="spec.template.spec.containers[].image",
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
            field_path=changes[0]["path"] if changes else None,
            current_value=changes[0]["before"] if changes else None,
            proposed_value=changes[0]["after"] if changes else None,
            reason="Image tag does not exist or is not available.",
            verification={"type": "rollout_status", "expected": "deployment rolled out and pods become ready"},
            rollback={"available": True, "strategy": f"kubectl rollout undo {resource['kind']}/{resource['name']} -n {resource.get('namespace') or 'default'}"},
            kubectl_commands=set_image_cmds,
            verification_steps=[
                f"kubectl rollout status {resource['kind']}/{resource['name']} -n {resource.get('namespace') or 'default'}",
                "Verify pods are no longer ImagePullBackOff/ErrImagePull",
                "Verify image is successfully pulled",
                "Verify Deployment has Available replicas",
                "Verify Pods are Ready",
            ],
            rollback_steps=[
                f"kubectl rollout undo {resource['kind']}/{resource['name']} -n {resource.get('namespace') or 'default'}",
            ],
            summary=f"Patch container image to {after}",
        )


class ReadinessProbeRemediator(Remediator):
    """Root-cause remediation for HTTP readiness probe failures."""

    _READINESS_KEYWORDS = ("readiness probe", "readinessprobe", "unhealthy")

    def propose(
        self,
        diagnosis: dict[str, Any],
        resource: dict[str, str],
        manifest: dict[str, Any],
        toolkit: Any,
    ) -> Remediation | None:
        root_type = str(diagnosis.get("rootCauseType") or "").lower()
        text = _diagnosis_context(diagnosis)

        if root_type != "readiness_probe_failure":
            if not any(k in text for k in self._READINESS_KEYWORDS):
                return None
            # Require an HTTP failure code (e.g. 404) before acting.
            if not any(code in text for code in ("404", "http 404", "status 404")):
                return None

        containers = (
            (((manifest.get("spec") or {}).get("template") or {}).get("spec") or {})
            .get("containers") or []
        )
        if not isinstance(containers, list):
            return None

        for i, container in enumerate(containers):
            probe = container.get("readinessProbe") or {}
            http_get = probe.get("httpGet") or {}
            path = http_get.get("path")
            port = http_get.get("port")
            current_image = container.get("image", "")
            repo = _image_repo(current_image)

            if not path or repo not in _WELL_KNOWN_ROOT_HEALTH:
                continue

            # Propose a root path only for well-known images where "/" is a
            # safe, evidence-backed default. For everything else ask the user.
            if path == "/":
                continue

            container_name = container.get("name") or f"container-{i}"
            patch = {
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                {
                                    "name": container_name,
                                    "readinessProbe": {
                                        "httpGet": {
                                            "path": "/",
                                            "port": port,
                                        }
                                    },
                                }
                            ]
                        }
                    }
                }
            }
            changes = [
                {
                    "path": f"spec.template.spec.containers[{i}].readinessProbe.httpGet.path",
                    "before": path,
                    "after": "/",
                }
            ]
            return Remediation(
                root_cause=f"Readiness probe path {path!r} on {current_image} returns HTTP 404.",
                confidence=0.95,
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
                field_path=changes[0]["path"],
                current_value=changes[0]["before"],
                proposed_value=changes[0]["after"],
                reason="The configured readiness probe path does not exist. For nginx, GET / returns HTTP 200.",
                verification={"type": "rollout_status", "expected": "deployment rolled out, readiness probes succeed, pods become Ready"},
                rollback={"available": True, "strategy": f"kubectl rollout undo {resource['kind']}/{resource['name']} -n {resource.get('namespace') or 'default'}"},
                kubectl_commands=[
                    f"kubectl patch {resource['kind']} {resource['name']} -n {resource.get('namespace') or 'default'} --type=strategic -p '{json.dumps(patch)}'"
                ],
                verification_steps=[
                    f"kubectl get deployment {resource['name']} -n {resource.get('namespace') or 'default'} -o jsonpath='{{.status.availableReplicas}}'",
                    "kubectl get pods -w until Ready condition is True",
                    "kubectl describe pod to confirm readiness probe succeeded",
                    "curl the readiness endpoint from inside the pod and expect HTTP 200",
                ],
                rollback_steps=[
                    f"kubectl rollout undo {resource['kind']}/{resource['name']} -n {resource.get('namespace') or 'default'}",
                ],
                summary=f"Change readiness probe path from {path!r} to /",
            )

        # No safe default endpoint could be derived.
        return _need_input(
            resource,
            "Readiness probe failure",
            "A documented health endpoint for this container could not be determined from the current evidence.",
            field_path="spec.template.spec.containers[].readinessProbe.httpGet.path",
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