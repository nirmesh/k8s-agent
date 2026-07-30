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
Only use values that are explicitly present in the supplied diagnosis/evidence, current manifest, related live resources, or user-provided input.
Never invent or infer a replacement value merely because it seems plausible.

If a fix requires a value that is not explicitly supported by supplied evidence, return NEED_USER_INPUT rather than guessing.
If multiple candidate values/resources are present and the intended one is ambiguous, return NEED_USER_INPUT.
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
  "arguments": {"tool": "specific keyword arguments"},
  "target": {"kind": "<kind>", "namespace": "<namespace>", "name": "<name>"},
  "changes": [{"path": "<json-path or field>", "before": "<current value or unknown>", "after": "<proposed value>"}],
  "reason": "<why this resolves the incident>",
  "verification": {"type": "<generic verification type>", "expected": "<what should be true after the change>"},
  "rollback": {"available": true, "strategy": "<how to undo the change>"}
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

    def plan(self, diagnosis: dict, user_input: dict | None = None) -> dict:
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
            return _fallback("NO_SAFE_REMEDIATION", "No affected resources specified in the diagnosis.")

        resource = self._parse_resource(affected[0], diagnosis)
        if not resource:
            return _fallback("NO_SAFE_REMEDIATION", "Could not parse affected resource identifier.")

        manifest_result = self.toolkit.get_resource(
            resource["kind"], resource["namespace"], resource["name"]
        )
        if not manifest_result.get("success"):
            message = manifest_result.get("error", {}).get("message") or "unknown error"
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

        # Important: do not auto-fill missing remediation values. A previous
        # implementation guessed Service selectors from the most common Pod label
        # in a namespace, which can target an unrelated workload. The model may
        # propose a value, but READY plans must pass the deterministic provenance
        # gate below before they can reach approval/execution.
        grounding = {
            "diagnosis": diagnosis,
            "evidence": evidence,
            "manifest": manifest,
            "related": related,
            "user_input": user_input or {},
        }
        return self._validate_plan(plan, resource, grounding)

    def _extract_affected(self, diagnosis: dict) -> list[str]:
        candidates = diagnosis.get("affectedResources") or diagnosis.get("affected_resources") or []
        if not isinstance(candidates, list):
            return []
        return [c for c in candidates if isinstance(c, str) and c.strip()]

    def _parse_resource(self, value: str, diagnosis: dict) -> dict | None:
        parts = value.split("/")
        if len(parts) == 3:
            return {"kind": parts[0].lower(), "namespace": parts[1], "name": parts[2]}
        if len(parts) == 2:
            namespace = diagnosis.get("namespace", "") or "default"
            return {"kind": parts[0].lower(), "namespace": namespace, "name": parts[1]}
        return None

    def _collect_related(self, resource: dict) -> dict:
        """Gather generic live context; facts only, never a diagnosis or guessed fix."""
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
            "Diagnosis:", _compact(diagnosis),
            "Evidence:", _compact(evidence),
            "Affected resource:", _compact(resource),
            "Current manifest:", _compact(manifest),
            "Related resources:", _compact(related),
        ]
        if user_input:
            parts.extend(["User provided input:", _compact(user_input)])
        parts.extend([
            "Allowed remediation tools:",
            ", ".join(ALLOWED_TOOLS),
            "Every replacement/new scalar value must already appear in the supplied evidence, live resource state, or user input. If not, return NEED_USER_INPUT. Return a single JSON remediation plan. Do not execute anything.",
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

    def _validate_plan(self, plan: dict, default_target: dict, grounding: dict) -> dict:
        if not isinstance(plan, dict):
            return _fallback("NO_SAFE_REMEDIATION", "Planner did not return a JSON object.", target=default_target)

        status = plan.get("status")
        if status in {"NEED_USER_INPUT", "NO_SAFE_REMEDIATION"}:
            return plan

        if status != "READY":
            return _fallback(
                "NO_SAFE_REMEDIATION",
                f"Unknown plan status '{status}'.",
                target=default_target,
            )

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
        if not isinstance(target, dict) or not all(k in target for k in ("kind", "namespace", "name")):
            plan["target"] = default_target
            target = default_target

        if not _same_target(target, default_target):
            return _need_input(
                "Planner proposed a different target than the evidence-backed affected resource.",
                default_target,
                "Confirm the exact Kubernetes resource that should be changed.",
            )

        unsupported = self._unsupported_mutation_values(tool, arguments, plan, grounding)
        if unsupported:
            rendered = ", ".join(f"{path}={value!r}" for path, value in unsupported[:5])
            return _need_input(
                f"Blocked remediation because proposed values are not supported by current investigation evidence: {rendered}",
                default_target,
                "Provide or collect evidence for the intended replacement value before applying a change.",
            )

        if not isinstance(plan.get("changes"), list):
            plan["changes"] = []
        if not isinstance(plan.get("verification"), dict):
            plan["verification"] = {"type": "resource_exists", "expected": "resource is present"}
        if not isinstance(plan.get("rollback"), dict):
            plan["rollback"] = {"available": False, "strategy": "none"}

        plan["evidenceGrounded"] = True
        return plan

    def _unsupported_mutation_values(
        self, tool: str, arguments: dict, plan: dict, grounding: dict
    ) -> list[tuple[str, Any]]:
        """Return new scalar values that have no provenance in current evidence.

        This is deliberately generic. It does not know about ImagePullBackOff,
        Service selector mismatches, PVCs, etc. It only enforces that a READY
        mutation cannot introduce a value the current investigation never observed
        (or the user never supplied).
        """
        candidates: list[tuple[str, Any]] = []

        if tool == "patch_resource":
            patch = arguments.get("patch")
            if isinstance(patch, dict):
                candidates.extend(_leaf_scalars(patch, "patch"))
        elif tool == "apply_resource":
            manifest = arguments.get("manifest")
            if isinstance(manifest, dict):
                candidates.extend(_leaf_scalars(manifest, "manifest"))
        elif tool == "scale_workload":
            if "replicas" in arguments:
                candidates.append(("replicas", arguments.get("replicas")))
        # restart_workload and rollback_workload do not introduce arbitrary
        # configuration values, so target validation is sufficient here.

        # changes.after is also checked because UI/executor code may rely on it.
        for index, change in enumerate(plan.get("changes") or []):
            if isinstance(change, dict) and "after" in change:
                candidates.append((f"changes[{index}].after", change.get("after")))

        unsupported: list[tuple[str, Any]] = []
        for path, value in candidates:
            if value is None or isinstance(value, (dict, list)):
                continue
            if _is_structural_value(path, value):
                continue
            if not _value_observed(value, grounding):
                unsupported.append((path, value))
        return unsupported


def _same_target(candidate: dict, expected: dict) -> bool:
    return (
        str(candidate.get("kind", "")).lower() == str(expected.get("kind", "")).lower()
        and str(candidate.get("namespace", "")) == str(expected.get("namespace", ""))
        and str(candidate.get("name", "")) == str(expected.get("name", ""))
    )


def _leaf_scalars(value: Any, path: str) -> list[tuple[str, Any]]:
    if isinstance(value, dict):
        result: list[tuple[str, Any]] = []
        for key, child in value.items():
            result.extend(_leaf_scalars(child, f"{path}.{key}"))
        return result
    if isinstance(value, list):
        result = []
        for index, child in enumerate(value):
            result.extend(_leaf_scalars(child, f"{path}[{index}]"))
        return result
    return [(path, value)]


def _is_structural_value(path: str, value: Any) -> bool:
    """Values identifying the already-validated target are not mutation payloads."""
    lowered = path.lower()
    return lowered.endswith(".kind") or lowered.endswith(".namespace") or lowered.endswith(".name")


def _value_observed(value: Any, grounding: Any) -> bool:
    """Exact scalar provenance search through current investigation inputs."""
    if isinstance(grounding, dict):
        return any(_value_observed(value, child) for child in grounding.values())
    if isinstance(grounding, list):
        return any(_value_observed(value, child) for child in grounding)
    if grounding is None:
        return value is None
    # Keep types meaningful for numbers/bools while accepting stringified values
    # because Kubernetes serializers and LLM JSON can represent the same scalar
    # differently.
    if type(value) is type(grounding) and value == grounding:
        return True
    return str(value) == str(grounding)


def _compact(value: Any, max_len: int = 4000) -> str:
    text = json.dumps(value, default=str, ensure_ascii=False, indent=None)
    if len(text) > max_len:
        return text[:max_len] + " ...[truncated]"
    return text


def _need_input(summary: str, target: dict, question: str) -> dict:
    result = _fallback("NEED_USER_INPUT", summary, target=target)
    result["question"] = question
    return result


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
