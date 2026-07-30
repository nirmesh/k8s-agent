import inspect
import json
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

_SYSTEM_PROMPT = """You are a generic Kubernetes remediation planner.

Given an evidence-backed diagnosis and the current state of the affected resource, propose the smallest safe change that can resolve the incident.

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

If a fix requires information that is not present in the evidence or the resource manifest, return NEED_USER_INPUT rather than guessing.
Prefer reversible changes.
Return exactly one JSON remediation plan.

Allowed remediation tools (do not use any others):
- patch_resource(kind, namespace, name, patch)
- apply_resource(manifest)
- restart_workload(kind, namespace, name)
- rollback_workload(kind, namespace, name)
- scale_workload(kind, namespace, name, replicas)

The `verification` field must describe observable success criteria using a generic verification type such as:
- resource_exists
- resource_ready
- rollout_status
- endpoints_ready
- pods_ready
- pvc_bound
- pod_scheduled
- pod_ready

Return exactly one JSON object with no markdown or commentary:

{
  "status": "READY | NEED_USER_INPUT | NO_SAFE_REMEDIATION",
  "summary": "<human-readable one-line summary>",
  "question": "<what the user needs to provide; omit for READY/NO_SAFE_REMEDIATION>",
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
    "type": "<generic verification type>",
    "expected": "<what should be true after the change>"
  },
  "rollback": {
    "available": true,
    "strategy": "<how to undo the change>"
  }
}
"""


class RemediationPlanner:
    """Propose, but do not execute, generic Kubernetes remediation plans."""

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
        if diagnosis.get("status") == "NO_ISSUE":
            return _fallback(
                "NO_ISSUE",
                "No active issues detected.",
                target={"kind": "cluster", "namespace": "-", "name": "-"},
            )

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
                target=resource,
            )

        manifest = manifest_result.get("data")
        related = self._collect_related(resource)
        prompt = self._build_prompt(
            diagnosis, evidence, resource, manifest, related, user_input=user_input
        )
        raw = generate(prompt, system=_SYSTEM_PROMPT)

        try:
            plan = self._parse_json(raw)
        except Exception as exc:
            logger.error(f"Remediation planner invalid JSON: {exc}")
            return _fallback(
                "NO_SAFE_REMEDIATION",
                f"Planner returned invalid JSON: {exc}",
                target=resource,
            )

        plan = self._auto_fill(plan, resource, manifest, related)
        return self._validate_plan(plan, resource)

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

    def _collect_related(self, resource: dict) -> dict:
        """Gather a small amount of generic context for the planner prompt."""
        related: dict = {}
        try:
            owner = self.toolkit.get_owner(
                resource["kind"], resource.get("namespace"), resource["name"]
            )
            if owner.get("success"):
                related["owner"] = owner.get("data", {})

            owned = self.toolkit.get_owned_resources(
                resource["kind"], resource.get("namespace"), resource["name"]
            )
            if owned.get("success"):
                related["owned"] = owned.get("data", {})

            if resource.get("namespace"):
                events = self.toolkit.get_events(
                    namespace=resource["namespace"], resource_name=resource["name"]
                )
                if events.get("success"):
                    related["events"] = events.get("data", {})

                pods = self.toolkit.list_resources("pod", namespace=resource["namespace"])
                if pods.get("success"):
                    related["pods"] = pods.get("data", {})
        except Exception:
            logger.exception("failed to collect related resources for planner")
        return related

    def _build_prompt(
        self,
        diagnosis: dict,
        evidence: list,
        resource: dict,
        manifest: Any,
        related: dict,
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
            "Related resources:",
            _compact(related),
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
        start = text.find("{")
        if start == -1:
            raise ValueError("No JSON object found in response")
        obj, _ = json.JSONDecoder().raw_decode(text, start)
        return obj

    def _auto_fill(
        self,
        plan: dict,
        resource: dict,
        manifest: Any,
        related: dict,
    ) -> dict:
        """Resolve missing values that can be inferred from cluster state.

        Currently handles Service selector mismatches by deriving the intended
        selector values from the labels of Pods already running in the namespace.
        """
        if not isinstance(plan, dict) or plan.get("status") != "NEED_USER_INPUT":
            return plan

        try:
            if resource.get("kind") != "service":
                return plan

            res = manifest.get("data", {}).get("resource", manifest.get("resource", {}))
            selectors = res.get("spec", {}).get("selector")
            if not isinstance(selectors, dict):
                return plan

            pods_data = related.get("pods") or {}
            pods = pods_data.get("items") or []
            if not pods:
                return plan

            suggested: dict[str, str] = {}
            for key, current in selectors.items():
                if not isinstance(key, str):
                    continue
                values: dict[str, int] = {}
                for pod in pods:
                    labels = (
                        pod.get("metadata", {}).get("labels")
                        or pod.get("metadata", {}).get("labels_dict")
                        or {}
                    )
                    val = labels.get(key)
                    if val and str(val) != str(current):
                        values[str(val)] = values.get(str(val), 0) + 1
                if values:
                    suggested[key] = max(values.items(), key=lambda kv: kv[1])[0]

            if not suggested:
                return plan

            arguments = plan.get("arguments")
            if not isinstance(arguments, dict):
                arguments = {
                    "kind": "Service",
                    "namespace": resource.get("namespace"),
                    "name": resource.get("name"),
                    "patch": {"spec": {"selector": {}}},
                }
                plan["arguments"] = arguments

            patch = arguments.get("patch") or {}
            if not isinstance(patch, dict):
                patch = {}
                arguments["patch"] = patch
            if "spec" not in patch or not isinstance(patch.get("spec"), dict):
                patch["spec"] = {}
            if not isinstance(patch["spec"].get("selector"), dict):
                patch["spec"]["selector"] = {}

            new_values = dict(patch["spec"]["selector"])
            new_values.update(suggested)
            patch["spec"]["selector"] = new_values

            plan["status"] = "READY"
            plan.pop("question", None)
            plan["summary"] = (
                plan.get("summary", "")
                + f" Inferred selector values {suggested} from pod labels."
            ).strip()
            plan["changes"] = [
                {
                    "path": f"spec.selector.{k}",
                    "before": str(selectors.get(k)),
                    "after": v,
                }
                for k, v in suggested.items()
            ]
            plan.setdefault("verification", {"type": "endpoints_ready", "expected": "Service has at least one ready endpoint"})
            plan.setdefault("rollback", {"available": True, "strategy": "Patch selector back to original values using patch_resource"})
        except Exception:
            logger.exception("auto-fill failed; returning original plan")
        return plan

    def _validate_plan(self, plan: dict, default_target: dict) -> dict:
        if not isinstance(plan, dict):
            return _fallback(
                "NO_SAFE_REMEDIATION",
                "Planner did not return a JSON object.",
                target=default_target,
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
                    target=default_target,
                )

            arguments = plan.get("arguments")
            if not isinstance(arguments, dict):
                return _fallback(
                    "NO_SAFE_REMEDIATION",
                    "arguments must be a JSON object of keyword arguments.",
                    target=default_target,
                )

            method = getattr(self.toolkit, tool, None)
            if method is None:
                return _fallback(
                    "NO_SAFE_REMEDIATION",
                    f"Tool '{tool}' not found on the toolkit.",
                    target=default_target,
                )

            try:
                inspect.signature(method).bind(**arguments)
            except Exception as exc:
                return _fallback(
                    "NO_SAFE_REMEDIATION",
                    f"Invalid arguments for {tool}: {exc}",
                    target=default_target,
                )

            target = plan.get("target")
            if not isinstance(target, dict) or not all(
                k in target for k in ("kind", "namespace", "name")
            ):
                plan["target"] = default_target

            if not isinstance(plan.get("changes"), list):
                plan["changes"] = []

            if not isinstance(plan.get("verification"), dict):
                plan["verification"] = {"type": "resource_exists", "expected": "resource is present"}

            if not isinstance(plan.get("rollback"), dict):
                plan["rollback"] = {"available": False, "strategy": "none"}

            return plan

        return _fallback(
            "NO_SAFE_REMEDIATION",
            f"Unknown plan status '{status}'.",
            target=default_target,
        )


def _compact(value: Any, max_len: int = 4000) -> str:
    text = json.dumps(value, default=str, ensure_ascii=False, indent=None)
    if len(text) > max_len:
        return text[:max_len] + " ...[truncated]"
    return text


def _fallback(status: str, summary: str, target: dict | None = None) -> dict:
    return {
        "status": status,
        "summary": summary,
        "risk": "UNKNOWN",
        "tool": None,
        "arguments": None,
        "target": target,
        "changes": [],
        "reason": summary,
        "verification": {"type": "none", "expected": "none"},
        "rollback": {"available": False, "strategy": "none"},
    }
