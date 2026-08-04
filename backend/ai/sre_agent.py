import json
import time
from collections.abc import Callable
from typing import Any

from backend.ai.llm_client import chat
from backend.core.logging import logger
from backend.evidence.model import Evidence
from backend.kubernetes.toolkit import K8sToolkit
from backend.providers import KubernetesProvider, PrometheusProvider, ProviderRegistry

MAX_ITERATIONS = 10
MAX_OBSERVATION_CHARS = 12000

DEFAULT_INCIDENT = (
    "Investigate the Kubernetes cluster for current incidents, unhealthy resources, "
    "failing workloads, or any other anomalous state. Determine the root cause."
)

_SYSTEM_PROMPT = """You are a generic Kubernetes SRE investigator.

Your job is to determine the root cause of an incident using only evidence gathered from read-only Kubernetes tools.

Do not assume cluster state. Use the available tools to observe, hypothesize, and gather evidence.

On every turn you must return exactly one assistant message. Ollama supports native tool calls, or if no tool is needed, output a single JSON object.

When you need more evidence, use one or more tool_calls. When the evidence is sufficient, return a diagnosis JSON.

Return ONLY one of the following:
1. A tool-call block (Ollama format) using one of the available tools.
2. A single JSON object with action="diagnose" and the diagnosis schema below.

Rules:
- Do not invent resources, namespaces, names, logs, events, image tags, secrets, or configuration values.
- Do not repeat a tool call with the exact same arguments.
- If evidence is insufficient after reasonable investigation, return status NEED_MORE_EVIDENCE and say what evidence is missing.
- If the reported symptom is not observable after directly checking it, return status NO_ISSUE.
- Automatically detected anomaly signals in the incident are leads that MUST be verified before NO_ISSUE is allowed. Do not abandon a signal merely because Pods or Deployments elsewhere are healthy.
- For cluster-wide investigations, investigate detected anomaly signals first and stay scoped to their namespaces/resources; do not tour unrelated namespaces.
- If you find a root cause, return status DIAGNOSED.
- affectedResources must use the exact identifiers returned by tools, with form "Kind/namespace/name" (e.g. "Deployment/sre-lab/broken-nginx").
- Report only the resources that are actually affected. For pod-level symptoms, prefer the owning workload.
- Evidence values must come from tool outputs or the user-provided incident.
- Kubernetes infrastructure health does not imply application health. Running Pods and ready Deployments do not prove Services, storage, routing, or dependencies are healthy.

Available tools:

- list_resources(kind, namespace=None, api_version=None, label_selector=None, field_selector=None)
  List resources of `kind`. Omit namespace for all namespaces. Use label_selector/field_selector to filter.

- get_resource(kind, namespace, name, api_version=None)
  Read one resource. Use namespace=null for cluster-scoped resources.

- get_events(namespace=None, resource_name=None, event_type=None)
  Read Kubernetes events. Provide resource_name to filter by involved object. event_type can be "Warning" or "Normal".

- get_logs(namespace, pod, container=None, previous=False, tail_lines=100)
  Read container logs.

- get_owner(kind, namespace, name)
  Resolve ownerReferences for a resource up to the top-level owner.

- get_owned_resources(kind, namespace, name)
  Find resources owned by the named resource via ownerReferences.

- find_resources_by_labels(labels, namespace=None, kind="pod")
  Find resources of `kind` whose labels match the given label dictionary.

- find_resources_by_selector(selector, namespace=None, kind="pod")
  Find resources of `kind` matching a Kubernetes selector dictionary.

- discover_api_resources()
  Return the resource kinds and API versions the tool layer can query.

- get_resource_usage(namespace=None, kind="pod", name=None)
  Request resource usage metrics (requires metrics-server). Currently a stub.

- collect_security_evidence(resource=None, category=None, severity=None)
  Collect normalized security findings from all registered security scanners. The tool
  never exposes which scanner produced the evidence. Use it when the symptom may be a
  vulnerability, runtime threat, or misconfiguration.

To finish with a diagnosis, return exactly one JSON object:
{
  "action": "diagnose",
  "diagnosis": {
    "status": "DIAGNOSED | NEED_MORE_EVIDENCE | NO_ISSUE",
    "rootCause": "<short root cause sentence>",
    "explanation": "<evidence-based explanation>",
    "confidence": 0.0,
    "affectedResources": ["Kind/namespace/name"],
    "evidence": [
      {
        "source": "tool_name",
        "description": "<what this evidence shows>",
        "value": "<relevant excerpt or fact>"
      }
    ]
  }
}

Do not wrap the diagnosis in markdown. Do not include any commentary outside the JSON.
"""

class SREAgent:
    """Bounded, hypothesis-driven, generic Kubernetes SRE investigator backed by Ollama."""

    def __init__(
        self,
        context: str | None = None,
        config_path: str | None = None,
        max_iterations: int = MAX_ITERATIONS,
        _api_client: Any | None = None,
    ):
        self.context = context
        self.config_path = config_path
        self.max_iterations = max_iterations
        self.toolkit = K8sToolkit(
            context=context,
            config_path=config_path,
            _api_client=_api_client,
        )
        self.registry = ProviderRegistry()
        self.registry.register(KubernetesProvider(toolkit=self.toolkit))
        self.registry.register(PrometheusProvider())
        self._tool_schemas = self.registry.tools()
        self._tool_names = self.registry.tool_names()

    def run(
        self,
        incident_description: str | None = None,
        progress_callback: Callable[[str], None] | None = None,
    ) -> dict:
        self.incident_description = incident_description or DEFAULT_INCIDENT
        self.progress_callback = progress_callback
        self.trace: list[dict] = []
        self.observations: list[str] = []
        self.seen_calls: set[tuple[str, str]] = set()
        self.progress_seen: set[str] = set()
        self.activities: list[str] = []

        self._progress("AI Reasoning")
        messages = [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": f"Incident: {self.incident_description}\n\nInvestigate by calling read tools. When you have enough evidence, return the diagnosis JSON. Start by discovering resources if needed, then follow relationships outward from the reported resource."},
        ]

        for iteration in range(1, self.max_iterations + 1):
            start = time.monotonic()
            message = chat(messages, tools=self._tool_schemas)
            llm_duration = time.monotonic() - start

            tool_calls = message.get("tool_calls") or []
            raw = message.get("content") or ""

            self._trace_llm(iteration, raw, {"tool_calls": [tc.get("function", {}).get("name") for tc in tool_calls]}, None, llm_duration)

            if tool_calls:
                messages.append(message)
                for tc in tool_calls:
                    fn = tc.get("function") or {}
                    tool_name = fn.get("name")
                    arguments = fn.get("arguments") or {}
                    if isinstance(arguments, str):
                        try:
                            arguments = json.loads(arguments)
                        except Exception:
                            arguments = {}

                    self.activities.append(f"Called {tool_name}")
                    t0 = time.monotonic()
                    result = self._execute_tool(tool_name, arguments)
                    tool_duration = time.monotonic() - t0

                    self._trace_tool(iteration, tool_name, arguments, result, tool_duration)
                    self._maybe_progress(tool_name, arguments)
                    observation = self._format_observation(iteration, tool_name, arguments, result)
                    self.observations.append(observation)
                    messages.append({"role": "tool", "name": tool_name, "content": self._compact(result)})
                continue

            parsed, parse_error = self._parse_json(raw)
            self._trace_llm(iteration, raw, parsed, parse_error, llm_duration)

            if parse_error:
                self.observations.append(
                    f"Turn {iteration}: LLM returned invalid JSON ({parse_error}). "
                    "Please return a valid JSON object."
                )
                messages.append({"role": "assistant", "content": raw})
                messages.append({"role": "user", "content": "Return ONLY the structured diagnosis JSON now, or call a tool if more evidence is required."})
                continue

            action = parsed.get("action")

            if action == "diagnose":
                diagnosis = parsed.get("diagnosis")
                if not isinstance(diagnosis, dict):
                    diagnosis = {
                        "status": "UNKNOWN",
                        "rootCause": "Model returned a non-object diagnosis",
                        "explanation": json.dumps(parsed),
                        "confidence": 0.0,
                        "affectedResources": [],
                        "evidence": [],
                    }
                else:
                    diagnosis = self._canonicalize_affected_resources(diagnosis)
                self._progress("Root Cause Found")
                diagnosis["investigationTrace"] = self.trace
                return diagnosis

            if action == "tool_call":
                # Support single tool_call JSON objects as a fallback when native tool_calls not used.
                tool_name = parsed.get("tool")
                arguments = parsed.get("arguments", {})
                self.activities.append(f"Called {tool_name}")
                t0 = time.monotonic()
                result = self._execute_tool(tool_name, arguments)
                tool_duration = time.monotonic() - t0
                self._trace_tool(iteration, tool_name, arguments, result, tool_duration)
                self._maybe_progress(tool_name, arguments)
                observation = self._format_observation(iteration, tool_name, arguments, result)
                self.observations.append(observation)
                messages.append({"role": "assistant", "content": raw})
                messages.append({"role": "user", "content": f"Tool result: {observation}"})
                continue

            self.observations.append(
                f"Turn {iteration}: invalid action '{action}'. "
                "Use 'tool_call' or 'diagnose'."
            )
            messages.append({"role": "assistant", "content": raw})
            messages.append({"role": "user", "content": "Invalid action. Call a tool or return action='diagnose' JSON."})

        # Tool budget exhausted; ask for a final synthesis without tools.
        messages.append({"role": "user", "content": (
            "Tool-call budget is exhausted. Do NOT call tools. Using only the evidence already collected, "
            "return exactly one JSON object with action='diagnose'. If the reported symptom cannot be "
            "confirmed or refuted, use status NEED_MORE_EVIDENCE. If no problem is visible, use NO_ISSUE."
        )})
        final_message = chat(messages, tools=None)
        final_raw = final_message.get("content") or ""
        final_parsed, final_error = self._parse_json(final_raw)
        self._trace_llm(self.max_iterations + 1, final_raw, final_parsed, final_error, 0.0)

        if not final_error and isinstance(final_parsed, dict) and final_parsed.get("action") == "diagnose":
            final_diag = final_parsed.get("diagnosis")
            if isinstance(final_diag, dict):
                self._progress("Root Cause Found")
                final_diag = self._canonicalize_affected_resources(final_diag)
                final_diag["investigationTrace"] = self.trace
                return final_diag

        diagnosis = {
            "status": "UNKNOWN",
            "rootCause": "Investigation reached the maximum number of tool iterations without a structured diagnosis.",
            "explanation": "The agent exhausted the allowed tool-call budget.",
            "confidence": 0.0,
            "affectedResources": [],
            "evidence": [
                {
                    "source": "trace",
                    "description": "Agent trace",
                    "value": json.dumps(self.trace, default=str),
                }
            ],
            "investigationTrace": self.trace,
        }
        self._progress("Root Cause Found")
        return diagnosis

    def _parse_json(self, raw: str) -> tuple[dict | None, str | None]:
        text = raw.strip()
        if text.startswith("```"):
            lines = text.splitlines()
            if lines and lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip().startswith("```"):
                lines = lines[:-1]
            text = "\n".join(lines).strip()
        try:
            start = text.index("{")
            obj, _ = json.JSONDecoder().raw_decode(text, start)
            if isinstance(obj, dict):
                return obj, None
            return None, "Parsed JSON is not a JSON object"
        except Exception as exc:
            return None, f"{exc}"

    def _execute_tool(self, tool_name: Any, arguments: Any) -> Evidence:
        if not isinstance(arguments, dict):
            return Evidence(
                provider="sre_agent",
                type="tool_result",
                resource=str(tool_name),
                payload={
                    "tool": tool_name,
                    "arguments": arguments,
                    "result": {
                        "success": False,
                        "error": {
                            "code": "INVALID_ARGUMENTS",
                            "message": "arguments must be a JSON object of keyword arguments.",
                        },
                    },
                },
            )

        if tool_name not in self._tool_names:
            return Evidence(
                provider="sre_agent",
                type="tool_result",
                resource=str(tool_name),
                payload={
                    "tool": tool_name,
                    "arguments": arguments,
                    "result": {
                        "success": False,
                        "error": {
                            "code": "INVALID_TOOL",
                            "message": f"Tool '{tool_name}' is not available.",
                        },
                    },
                },
            )

        call_key = (tool_name, json.dumps(arguments, sort_keys=True, default=str))
        if call_key in self.seen_calls:
            return Evidence(
                provider="sre_agent",
                type="tool_result",
                resource=str(tool_name),
                payload={
                    "tool": tool_name,
                    "arguments": arguments,
                    "result": {
                        "success": False,
                        "error": {
                            "code": "REPEATED_CALL",
                            "message": "This exact tool call was already made.",
                        },
                    },
                },
            )
        self.seen_calls.add(call_key)

        try:
            return self.registry.execute_tool(tool_name, **arguments)
        except Exception as exc:
            logger.exception("SRE agent tool execution failed")
            return Evidence(
                provider="sre_agent",
                type="tool_result",
                resource=str(tool_name),
                payload={
                    "tool": tool_name,
                    "arguments": arguments,
                    "result": {
                        "success": False,
                        "error": {"code": "TOOL_ERROR", "message": str(exc)},
                    },
                },
            )

    def _format_observation(
        self, iteration: int, tool_name: Any, arguments: Any, result: dict
    ) -> str:
        compact = self._compact(result)
        return (
            f"Turn {iteration}: tool={tool_name} "
            f"arguments={json.dumps(arguments, default=str)} -> {compact}"
        )

    def _compact(self, value: Any) -> str:
        if isinstance(value, Evidence):
            value = value.payload.get("result", value.payload)
        text = json.dumps(value, default=str)
        if len(text) > MAX_OBSERVATION_CHARS:
            return text[:MAX_OBSERVATION_CHARS] + " ... [truncated]"
        return text

    def _result_success(self, result: Any) -> bool:
        if isinstance(result, Evidence):
            result = result.payload.get("result")
        if isinstance(result, dict):
            return result.get("success", False)
        return True

    def _trace_llm(
        self,
        iteration: int,
        raw: str,
        parsed: Any,
        error: str | None,
        duration: float,
    ) -> None:
        entry = {
            "iteration": iteration,
            "type": "llm",
            "duration": duration,
        }
        if error:
            entry["error"] = error
        elif isinstance(parsed, dict):
            entry["action"] = parsed.get("action")
        self.trace.append(entry)
        logger.info(
            f"SRE agent turn {iteration} took {duration:.2f}s, "
            f"action={entry.get('action')}, error={error}"
        )

    def _trace_tool(
        self,
        iteration: int,
        tool_name: Any,
        arguments: Any,
        result: dict,
        duration: float,
    ) -> None:
        entry = {
            "iteration": iteration,
            "type": "tool",
            "tool": tool_name,
            "arguments": arguments,
            "success": self._result_success(result),
            "duration": duration,
        }
        self.trace.append(entry)
        logger.info(
            f"SRE agent tool {tool_name}({arguments}) "
            f"success={entry['success']} duration={duration:.2f}s"
        )

    def _maybe_progress(self, tool_name: Any, arguments: Any) -> None:
        if not self.progress_callback:
            return
        step = self._tool_to_step(tool_name, arguments)
        if step:
            self._progress(step)

    def _tool_to_step(self, tool_name: Any, arguments: Any) -> str | None:
        name = str(tool_name).lower()
        kind = ""
        if isinstance(arguments, dict):
            kind = str(arguments.get("kind", "")).lower()

        if name == "get_logs":
            return "Reading Logs"
        if name == "get_events":
            return "Analyzing Events"

        # Pod-level discovery / inspection.
        if kind == "pod" and name in (
            "list_resources",
            "get_resource",
            "find_resources_by_labels",
            "find_resources_by_selector",
        ):
            return "Checking Pods"

        # Workload-level discovery / inspection.
        if kind in ("deployment", "replicaset", "statefulset", "daemonset") and name in (
            "list_resources",
            "get_resource",
            "find_resources_by_labels",
            "find_resources_by_selector",
        ):
            return "Inspecting Deployments"

        # Networking-level discovery / inspection.
        if kind in ("service", "endpoints", "endpointslice", "ingress", "networkpolicy") and name in (
            "list_resources",
            "get_resource",
            "find_resources_by_labels",
            "find_resources_by_selector",
        ):
            return "Checking Networking"

        return None

    def _canonicalize_affected_resources(self, diagnosis: dict) -> dict:
        """Normalize affectedResources and drop empty/unknown placeholders."""
        affected = diagnosis.get("affectedResources") or []
        if not isinstance(affected, list):
            affected = []
        cleaned = []
        for item in affected:
            if not isinstance(item, str):
                continue
            item = item.strip()
            if not item or "unknown" in item.lower():
                continue
            parts = item.split("/")
            if len(parts) == 3:
                cleaned.append(f"{parts[0].capitalize()}/{parts[1]}/{parts[2]}")
            elif len(parts) == 2:
                ns = diagnosis.get("namespace") or "default"
                cleaned.append(f"{parts[0].capitalize()}/{ns}/{parts[1]}")
        diagnosis["affectedResources"] = cleaned
        return diagnosis

    def _progress(self, step: str) -> None:
        if not self.progress_callback or step in self.progress_seen:
            return
        self.progress_seen.add(step)
        try:
            self.progress_callback(step)
        except Exception:
            logger.exception("progress callback failed")


def normalize_diagnosis(diagnosis: dict) -> dict:
    """Convert the camelCase LLM diagnosis into snake_case storage fields."""
    return {
        "root_cause": diagnosis.get("rootCause") or diagnosis.get("root_cause", ""),
        "incident_type": diagnosis.get("incidentType") or diagnosis.get("incident_type", ""),
        "explanation": diagnosis.get("explanation", ""),
        "confidence": float(diagnosis.get("confidence", 0) or 0),
        "status": diagnosis.get("status", "UNKNOWN"),
        "affected_resources": diagnosis.get("affectedResources")
        or diagnosis.get("affected_resources", []),
        "evidence": diagnosis.get("evidence", []),
        "investigation_trace": diagnosis.get("investigationTrace") or [],
    }
