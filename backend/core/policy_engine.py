import os
from typing import Any

import yaml

from backend.core.logging import logger

ALLOWED_WRITE_TOOLS = [
    "patch_resource",
    "apply_resource",
    "restart_workload",
    "rollback_workload",
    "scale_workload",
]

DEFAULT_CONFIG_PATH = os.path.join(
    os.path.dirname(__file__), "..", "config", "remediation-policy.yaml"
)


class PolicyEngine:
    """Deterministic, LLM-independent remediation policy validation."""

    def __init__(self, config_path: str | None = None):
        self.config_path = config_path or DEFAULT_CONFIG_PATH
        self.config = self._load_config()

    def _load_config(self) -> dict:
        with open(self.config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    def validate(
        self,
        plan: dict,
        diagnosis: dict | None = None,
        toolkit: Any | None = None,
    ) -> dict:
        """Validate a remediation plan and return a policy decision."""
        violations = []
        warnings = []

        tool = plan.get("tool")
        arguments = plan.get("arguments") or {}
        target = plan.get("target") or {}
        changes = plan.get("changes") or []

        # Registered operation check
        if not tool:
            violations.append("Plan has no 'tool' field")
        elif tool not in ALLOWED_WRITE_TOOLS:
            violations.append(
                f"Tool '{tool}' is not a registered remediation tool. "
                f"Allowed: {ALLOWED_WRITE_TOOLS}"
            )

        risk = self._assess_risk(plan)
        if risk == "CRITICAL":
            violations.append("Operation is classified as CRITICAL and is blocked")

        target_kind = (target.get("kind") or "").lower()
        target_namespace = target.get("namespace")
        target_name = target.get("name")

        # Existence checks against the live cluster
        if toolkit is not None and tool in ALLOWED_WRITE_TOOLS:
            ns_to_check = target_namespace
            if tool == "apply_resource":
                manifest = arguments.get("manifest") or {}
                manifest_meta = manifest.get("metadata") or {}
                ns_to_check = (
                    ns_to_check
                    or manifest_meta.get("namespace")
                    or "default"
                )

            if ns_to_check:
                ns_result = toolkit.get_resource(
                    "namespace", None, ns_to_check
                )
                if not ns_result.get("success"):
                    violations.append(
                        f"Namespace '{ns_to_check}' does not exist"
                    )

            if tool != "apply_resource" and target_kind and target_name:
                res_result = toolkit.get_resource(
                    target_kind, target_namespace, target_name
                )
                if not res_result.get("success"):
                    violations.append(
                        f"Target resource {target_kind}/"
                        f"{target_namespace or 'cluster'}/{target_name} "
                        "does not exist"
                    )

        # Target must align with the diagnosis affected resources
        if diagnosis is not None:
            affected = self._normalize_affected(
                diagnosis.get("affectedResources")
                or diagnosis.get("affected_resources")
                or [],
                toolkit=toolkit,
            )
            plan_target_id = self._target_id(target)
            if affected and plan_target_id and plan_target_id not in affected:
                violations.append(
                    f"Target {plan_target_id} is not listed in the "
                    "diagnosis affected resources"
                )

        # Patch mutation must be declared in the plan changes
        if tool == "patch_resource":
            patch = arguments.get("patch")
            if not isinstance(patch, dict) or not patch:
                violations.append(
                    "patch_resource requires a non-empty 'patch' object"
                )
            else:
                declared = [c.get("path", "") for c in changes]
                if not declared:
                    warnings.append(
                        "No 'changes' declared for patch_resource"
                    )
                else:
                    patch_paths = [
                        p for p in _flatten_paths(patch) if not _is_merge_key_path(p)
                    ]
                    for path in patch_paths:
                        if not any(
                            self._path_matches(declared_path, path)
                            for declared_path in declared
                        ):
                            violations.append(
                                f"Patch modifies undeclared field: {path}"
                            )

        allowed = len(violations) == 0
        approval_required = allowed and risk in ("LOW", "MEDIUM", "HIGH")

        if not allowed:
            logger.warning(
                "Remediation plan blocked: %s", "; ".join(violations)
            )

        return {
            "allowed": allowed,
            "approvalRequired": approval_required,
            "risk": risk,
            "violations": violations,
            "warnings": warnings,
        }

    def _assess_risk(self, plan: dict) -> str:
        tool = plan.get("tool", "")
        arguments = plan.get("arguments") or {}
        target = plan.get("target") or {}
        manifest = arguments.get("manifest") or {}

        if not tool or tool not in ALLOWED_WRITE_TOOLS:
            return "CRITICAL"

        critical = set(self.config.get("critical", {}).get("actions", []))
        if tool in critical:
            return "CRITICAL"
        if "delete" in tool.lower() or "shell" in tool.lower():
            return "CRITICAL"

        kind = (
            target.get("kind")
            or manifest.get("kind")
            or ""
        ).lower()
        name = (
            target.get("name")
            or manifest.get("metadata", {}).get("name", "")
            or ""
        ).lower()

        if kind == "clusterrole" and name == "cluster-admin":
            return "CRITICAL"

        risk_cfg = self.config.get("risk_levels", {})
        high_cfg = risk_cfg.get("high", {})
        high_tools = set(high_cfg.get("tools", []))
        high_kinds = {k.lower() for k in high_cfg.get("kinds", [])}

        if tool in high_tools and kind in high_kinds:
            return "HIGH"

        low_tools = set(risk_cfg.get("low", {}).get("tools", []))
        if tool in low_tools:
            return "LOW"

        return "MEDIUM"

    def _normalize_affected(
        self, resources: list, toolkit: Any | None = None
    ) -> set[str]:
        result = set()
        for value in resources:
            if not isinstance(value, str):
                continue
            parts = value.lower().split("/")
            if len(parts) == 3:
                result.add(f"{parts[0]}/{parts[1]}/{parts[2]}")
                result.add(f"{parts[0]}/{parts[2]}")
                if parts[0] == "pod" and toolkit is not None:
                    owners = self._get_owner_ids(
                        toolkit, "pod", parts[1], parts[2]
                    )
                    result.update(owners)
            elif len(parts) == 2:
                result.add(f"{parts[0]}/ /{parts[1]}")
                result.add(f"{parts[0]}/{parts[1]}")
        return result

    def _get_owner_ids(
        self, toolkit: Any, kind: str, namespace: str, name: str
    ) -> set[str]:
        result = set()
        owner_result = toolkit.get_owner(kind, namespace, name)
        if not owner_result.get("success"):
            return result
        for owner in owner_result.get("data", {}).get("owners", []):
            owner_kind = (owner.get("kind") or "").lower()
            owner_name = owner.get("metadata", {}).get("name") or owner.get("name", "")
            owner_ns = owner.get("metadata", {}).get("namespace") or namespace
            if owner_kind and owner_name:
                result.add(f"{owner_kind}/{owner_ns}/{owner_name}")
            if owner_kind == "replicaset":
                result.update(
                    self._get_owner_ids(toolkit, "replicaset", owner_ns, owner_name)
                )
        return result

    def _target_id(self, target: dict) -> str | None:
        kind = (target.get("kind") or "").lower()
        namespace = target.get("namespace") or ""
        name = target.get("name")
        if not kind or not name:
            return None
        return f"{kind}/{namespace}/{name}".lower()

    def _path_matches(self, declared: str, actual: str) -> bool:
        declared_parts = (
            declared.lower().strip("/").replace("[", ".").replace("]", "").split(".")
        )
        actual_parts = actual.lower().split(".")
        di = ai = 0
        while di < len(declared_parts):
            if ai >= len(actual_parts):
                return False
            dp = declared_parts[di]
            ap = actual_parts[ai]
            if dp == "*" or dp == ap:
                di += 1
                ai += 1
                continue
            # Declared may omit list indices (e.g., containers.readinessProbe) while
            # the actual flattened patch includes them (containers.0.readinessProbe).
            if ap.isdigit():
                ai += 1
                continue
            return False
        return True


def _is_merge_key_path(path: str) -> bool:
    """Return True for list merge keys such as containers.0.name.

    These keys are not themselves intended mutations; they identify the
    list element being patched.
    """
    parts = path.lower().split(".")
    return len(parts) >= 3 and parts[-1] == "name" and parts[-2].isdigit()


def _flatten_paths(obj: Any, prefix: str = "") -> list[str]:
    paths = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            new_prefix = f"{prefix}.{key}" if prefix else key
            if isinstance(value, (dict, list)):
                paths.extend(_flatten_paths(value, new_prefix))
            else:
                paths.append(new_prefix)
    elif isinstance(obj, list):
        for index, value in enumerate(obj):
            new_prefix = f"{prefix}.{index}" if prefix else str(index)
            if isinstance(value, (dict, list)):
                paths.extend(_flatten_paths(value, new_prefix))
            else:
                paths.append(new_prefix)
    else:
        paths.append(prefix)
    return paths
