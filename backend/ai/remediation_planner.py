import inspect
import json
import re
from typing import Any

from backend.ai.llm_client import generate
from backend.core.logging import logger
from backend.kubernetes.toolkit import K8sToolkit

ALLOWED_TOOLS = [
    "patch_resource",
    "apply_resource",
    "restart_workload",
    "rollback_workload",
    "scale_workload",
]

MAX_PROMPT_CHARS = 12000

_SYSTEM_PROMPT = """You are a Kubernetes remediation planner.

Given an evidence-backed diagnosis, propose the smallest safe change that can resolve the incident.

Do not execute anything.
Only use the provided resource state and evidence.
Never invent:
- image tags
- secret values
- ConfigMap contents
- resource names
- namespaces
- storage classes
- credentials

If a fix requires information that is not known, return NEED_USER_INPUT rather than guessing.
Prefer reversible changes.
Return exactly one primary remediation plan.
Every remediation must contain verification and rollback information.

Allowed remediation tools (do not use any others):
- patch_resource(kind, namespace, name, patch)
- apply_resource(manifest)
- restart_workload(kind, namespace, name)
- rollback_workload(kind, namespace, name)
- scale_workload(kind, namespace, name, replicas)

For ImagePullBackOff caused by an invalid image tag, DO NOT invent a replacement image tag.
If no known-good tag can be derived from deployment history, ReplicaSet history, user input, registry evidence, or another trustworthy source, return:
  status: NEED_USER_INPUT
and ask the user to provide/select the desired image.

Return exactly one JSON object with no markdown or commentary:

{
  "status": "READY | NEED_USER_INPUT | NO_SAFE_REMEDIATION",
  "summary": "<human-readable one-line summary>",
  "risk": "LOW | MEDIUM | HIGH | CRITICAL",
  "tool": "<one of the allowed tool names>",
  "arguments": {<tool-specific keyword arguments>},
  "target": {
    "kind": "<kind>",
    "namespace": "<namespace>",
    "name": "<name>"
  },
  "changes": [
    {
      "path": "<json-path or field>",
      "before": "<current value or 'unknown'>",
      "after": "<proposed value>"
    }
  ],
  "reason": "<why this resolves the incident>",
  "verification": {
    "type": "<how to verify, e.g. 'rollout_status' or 'pod_ready'>",
    "expected": "<what should be true after the change>"
  },
  "rollback": {
    "available": true,
    "strategy": "<how to undo the change, e.g. re-apply previous manifest or scale back>"
  }
}
"""


class RemediationPlanner:
    """Propose, but do not execute, Kubernetes remediation plans."""

    def __init__(
        self,
        context: str | None = None,
        config_path: str | None = None,
        _api_client: Any | None = None,
    ):
        self.toolkit = K8sToolkit(
            context=context,
            config_path=config_path,
            _api_client=_api_client,
        )

    def plan(
        self, diagnosis: dict, user_input: dict | None = None
    ) -> dict:
        affected = self._extract_affected(diagnosis)
        evidence = diagnosis.get("evidence") or []
        if not isinstance(evidence, list):
            evidence = []

        if not affected:
            return _fallback(
                "NO_SAFE_REMEDIATION",
                "No affected resources specified in the diagnosis.",
            )

        resource = self._parse_resource(affected[0], diagnosis)
        if not resource:
            return _fallback(
                "NO_SAFE_REMEDIATION",
                "Could not parse affected resource identifier.",
            )

        # Deterministic image-pull remediation: resolve to the owning workload,
        # request a known-good image if missing, or build the patch directly.
        if _is_image_pull_error(diagnosis):
            image = _get_image_from_user(user_input)
            workload_resource, workload_manifest = self._resolve_image_pull_workload(diagnosis)
            if not image:
                target = None
                if workload_resource:
                    target = {
                        "kind": workload_resource["kind"],
                        "namespace": workload_resource["namespace"],
                        "name": workload_resource["name"],
                    }
                return _need_user_input(
                    "A replacement image is required to fix ImagePullBackOff.",
                    "replacement image",
                    target=target,
                )
            if not workload_resource:
                return _fallback(
                    "NO_SAFE_REMEDIATION",
                    "Could not find a workload that owns the failing pod.",
                )
            image_plan = _build_image_patch_plan(workload_resource, workload_manifest, image)
            return self._validate_plan(image_plan)

        manifest_result = self.toolkit.get_resource(
            resource["kind"], resource["namespace"], resource["name"]
        )
        if not manifest_result.get("success"):
            message = (
                manifest_result.get("error", {}).get("message")
                or "unknown error"
            )
            return _fallback(
                "NO_SAFE_REMEDIATION",
                f"Could not fetch current manifest: {message}",
            )

        manifest = manifest_result.get("data")
        prompt = self._build_prompt(
            diagnosis, evidence, resource, manifest, user_input=user_input
        )
        raw = generate(prompt, system=_SYSTEM_PROMPT)

        try:
            plan = self._parse_json(raw)
        except Exception as exc:
            logger.error(f"Remediation planner invalid JSON: {exc}")
            return _fallback(
                "NO_SAFE_REMEDIATION",
                f"Planner returned invalid JSON: {exc}",
            )

        return self._validate_plan(plan)

    def _extract_affected(self, diagnosis: dict) -> list[str]:
        candidates = diagnosis.get("affectedResources") or diagnosis.get("affected_resources") or []
        if not isinstance(candidates, list):
            return []
        return [c for c in candidates if isinstance(c, str) and c.strip()]

    def _parse_resource(self, value: str, diagnosis: dict) -> dict | None:
        parts = value.split("/")
        if len(parts) == 3:
            return {
                "kind": parts[0].lower(),
                "namespace": parts[1],
                "name": parts[2],
            }
        if len(parts) == 2:
            namespace = diagnosis.get("namespace", "") or "default"
            return {
                "kind": parts[0].lower(),
                "namespace": namespace,
                "name": parts[1],
            }
        return None

    def _resolve_image_pull_workload(self, diagnosis: dict) -> tuple[dict | None, Any]:
        """Find the workload whose current image is the failing one."""
        bad_image = _extract_bad_image(diagnosis)

        # 1. Use an explicit workload affected resource if provided.
        for candidate in self._extract_affected(diagnosis):
            res = self._parse_resource(candidate, diagnosis)
            if res and res["kind"] == "deployment":
                workload = self._fetch_workload(res["kind"], res["namespace"], res["name"])
                if workload[0]:
                    return workload

        # 2. Find a currently failing pod and resolve to its workload.
        pods_result = self.toolkit.get_resources("pod", None)
        if pods_result.get("success"):
            items = pods_result.get("data", {}).get("items", [])
            failing = [p for p in items if self._is_failing_pod(p)]
            ordered = failing
            if bad_image:
                ordered = [p for p in failing if any(
                    bad_image in (c.get("image") or "")
                    for c in p.get("status", {}).get("container_statuses") or p.get("status", {}).get("containerStatuses", [])
                )] + failing
            for pod in ordered:
                workload = self._workload_from_owner_refs(
                    pod.get("metadata", {}).get("owner_references") or [],
                    pod.get("metadata", {}).get("namespace") or "default",
                )
                if workload[0]:
                    return workload

        # 3. Fall back to searching all deployments for the bad image.
        if bad_image:
            workload = self._deployment_for_image(bad_image)
            if workload[0]:
                return workload

        return None, None

    def _deployment_for_image(self, image: str) -> tuple[dict | None, Any]:
        """Return the first deployment whose pod template uses the given image."""
        result = self.toolkit.get_resources("deployment", None)
        if not result.get("success"):
            return None, None
        for dep in result.get("data", {}).get("items", []):
            namespace = dep.get("metadata", {}).get("namespace") or "default"
            name = dep.get("metadata", {}).get("name")
            if not name:
                continue
            containers = (
                dep.get("spec", {})
                .get("template", {})
                .get("spec", {})
                .get("containers", [])
            )
            if not isinstance(containers, list):
                continue
            for c in containers:
                if c.get("image") == image:
                    return self._fetch_workload("deployment", namespace, name)
        return None, None

    def _workload_from_owner_refs(
        self, refs: list, namespace: str
    ) -> tuple[dict | None, Any]:
        """Resolve a pod's ownerReferences to the top workload."""
        for ref in refs:
            kind = (ref.get("kind") or "").lower()
            name = ref.get("name", "")
            if not kind or not name:
                continue
            if kind == "deployment":
                return self._fetch_workload(kind, namespace, name)
        for ref in refs:
            kind = (ref.get("kind") or "").lower()
            name = ref.get("name", "")
            if kind == "replicaset" and name:
                workload = self._deployment_owner(namespace, name)
                if workload[0]:
                    return workload
        return None, None

    def _is_failing_pod(self, pod: dict) -> bool:
        status = pod.get("status", {})
        phase = status.get("phase", "")
        container_statuses = status.get("container_statuses") or status.get("containerStatuses", [])
        waiting = any(
            ((c.get("state") or {}).get("waiting") or {}).get("reason")
            in ("ImagePullBackOff", "ErrImagePull")
            for c in container_statuses
        )
        return phase != "Running" or waiting

    def _deployment_owner(self, namespace: str, name: str) -> tuple[dict | None, Any]:
        owner_result = self.toolkit.get_owner("replicaset", namespace, name)
        if not owner_result.get("success"):
            return None, None
        for owner in owner_result.get("data", {}).get("owners", []):
            kind = (owner.get("kind") or "").lower()
            owner_name = owner.get("metadata", {}).get("name") or owner.get("name", "")
            owner_ns = owner.get("metadata", {}).get("namespace") or namespace
            if kind == "deployment" and owner_name:
                return self._fetch_workload(kind, owner_ns, owner_name)
        return None, None

    def _fetch_workload(self, kind: str, namespace: str | None, name: str) -> tuple[dict | None, Any]:
        result = self.toolkit.get_resource(kind, namespace, name)
        if result.get("success"):
            return (
                {"kind": kind, "namespace": namespace, "name": name},
                result.get("data"),
            )
        return None, None

    def _build_prompt(
        self,
        diagnosis: dict,
        evidence: list,
        resource: dict,
        manifest: Any,
        user_input: dict | None = None,
    ) -> str:
        parts = [
            "Diagnosis:",
            _compact(diagnosis),
            "Evidence:",
            _compact(evidence),
            "Affected resource:",
            _compact(resource),
            "Current manifest:",
            _compact(manifest),
        ]
        if user_input:
            parts.extend(
                ["User provided input:", _compact(user_input)]
            )
        parts.extend([
            "Allowed remediation tools:",
            ", ".join(ALLOWED_TOOLS),
            "Return a single JSON remediation plan. Do not execute anything.",
        ])
        prompt = "\n\n".join(parts)
        if len(prompt) > MAX_PROMPT_CHARS:
            prompt = prompt[:MAX_PROMPT_CHARS] + "\n...[truncated]\n\nReturn a single JSON remediation plan."
        return prompt

    def _parse_json(self, raw: str) -> Any:
        text = raw.strip()
        if text.startswith("```"):
            lines = text.splitlines()
            if lines and lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip().startswith("```"):
                lines = lines[:-1]
            text = "\n".join(lines).strip()
        return json.loads(text)

    def _validate_plan(self, plan: dict) -> dict:
        if not isinstance(plan, dict):
            return _fallback(
                "NO_SAFE_REMEDIATION",
                "Planner did not return a JSON object.",
            )

        status = plan.get("status")

        if status == "NEED_USER_INPUT":
            return plan

        if status == "NO_SAFE_REMEDIATION":
            return plan

        if status == "READY":
            tool = plan.get("tool")
            if tool not in ALLOWED_TOOLS:
                return _fallback(
                    "NO_SAFE_REMEDIATION",
                    f"Tool '{tool}' is not an allowed remediation tool.",
                )

            arguments = plan.get("arguments")
            if not isinstance(arguments, dict):
                return _fallback(
                    "NO_SAFE_REMEDIATION",
                    "arguments must be a JSON object of keyword arguments.",
                )

            method = getattr(self.toolkit, tool, None)
            if method is None:
                return _fallback(
                    "NO_SAFE_REMEDIATION",
                    f"Tool '{tool}' not found on the toolkit.",
                )

            try:
                inspect.signature(method).bind(**arguments)
            except Exception as exc:
                return _fallback(
                    "NO_SAFE_REMEDIATION",
                    f"Invalid arguments for {tool}: {exc}",
                )

            target = plan.get("target")
            if not isinstance(target, dict) or not all(
                k in target for k in ("kind", "namespace", "name")
            ):
                return _fallback(
                    "NO_SAFE_REMEDIATION",
                    "Plan target must be a dict with 'kind', 'namespace', and 'name'.",
                )

            return plan

        return _fallback(
            "NO_SAFE_REMEDIATION",
            f"Unknown plan status '{status}'.",
        )


def _extract_bad_image(diagnosis: dict) -> str:
    text = json.dumps(diagnosis, default=str)
    # Match a docker image reference that includes a colon (tag or digest).
    matches = re.findall(r"[a-z0-9][a-z0-9._/-]*:[a-zA-Z0-9_.-]+", text)
    for m in matches:
        if ":" in m:
            return m
    return ""


def _is_image_pull_error(diagnosis: dict) -> bool:
    text = json.dumps(diagnosis, default=str).lower()
    return any(
        term in text
        for term in (
            "imagepullbackoff",
            "errimagepull",
            "failed to pull image",
            "failed to resolve image",
            "invalid image",
            "non-existent image",
            "nonexistent image",
        )
    )


def _get_image_from_user(user_input: dict | None) -> str | None:
    if not isinstance(user_input, dict):
        return None
    image = user_input.get("image") or user_input.get("container_image") or user_input.get("tag")
    if isinstance(image, str) and image.strip():
        return image.strip()
    return None


def _extract_resource_obj(manifest: Any) -> dict:
    if isinstance(manifest, dict):
        if "resource" in manifest:
            return manifest.get("resource") or {}
        return manifest
    return {}


def _build_image_patch_plan(resource: dict, manifest: Any, image: str) -> dict:
    resource_obj = _extract_resource_obj(manifest)
    containers = (
        resource_obj.get("spec", {})
        .get("template", {})
        .get("spec", {})
        .get("containers", [])
    )
    if not containers:
        return _fallback("NO_SAFE_REMEDIATION", "Workload manifest has no containers to patch.")
    if not isinstance(containers, list):
        return _fallback("NO_SAFE_REMEDIATION", "Workload containers are not in the expected list format.")

    container_name = containers[0].get("name")
    if not container_name:
        return _fallback("NO_SAFE_REMEDIATION", "First container has no name.")

    before = containers[0].get("image", "unknown")
    patch = {
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": container_name,
                            "image": image,
                        }
                    ]
                }
            }
        }
    }
    rollback_strategy = (
        "Roll back to previous Deployment revision"
        if resource.get("kind") == "deployment"
        else "Re-patch image to previous value"
    )
    return {
        "status": "READY",
        "summary": f"Replace container image with {image}",
        "risk": "MEDIUM",
        "tool": "patch_resource",
        "arguments": {
            "kind": resource["kind"],
            "namespace": resource["namespace"],
            "name": resource["name"],
            "patch": patch,
        },
        "target": {
            "kind": resource["kind"],
            "namespace": resource["namespace"],
            "name": resource["name"],
        },
        "changes": [
            {
                "path": "spec.template.spec.containers[0].name",
                "before": container_name,
                "after": container_name,
            },
            {
                "path": "spec.template.spec.containers[0].image",
                "before": before,
                "after": image,
            },
        ],
        "reason": "The current image cannot be pulled. Replacing it with a known-good image resolves ImagePullBackOff.",
        "verification": {
            "type": "rollout_status",
            "expected": "Deployment rollout succeeds and new pods become Ready",
        },
        "rollback": {
            "available": True,
            "strategy": rollback_strategy,
        },
    }


def _compact(value: Any, max_len: int = 4000) -> str:
    text = json.dumps(value, default=str, ensure_ascii=False, indent=None)
    if len(text) > max_len:
        return text[:max_len] + " ...[truncated]"
    return text


def _fallback(status: str, summary: str) -> dict:
    return {
        "status": status,
        "summary": summary,
        "risk": "UNKNOWN",
        "tool": None,
        "arguments": None,
        "target": None,
        "changes": [],
        "reason": summary,
        "verification": {"type": "none", "expected": "none"},
        "rollback": {"available": False, "strategy": "none"},
    }


def _need_user_input(summary: str, question: str, target: dict | None = None) -> dict:
    return {
        "status": "NEED_USER_INPUT",
        "summary": summary,
        "question": question,
        "risk": "UNKNOWN",
        "tool": None,
        "arguments": None,
        "target": target,
        "changes": [],
        "reason": summary,
        "verification": {"type": "none", "expected": "none"},
        "rollback": {"available": False, "strategy": "none"},
    }
