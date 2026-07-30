import inspect
import json
import time
from collections.abc import Callable
from typing import Any

from backend.ai.llm_client import chat
from backend.core.logging import logger
from backend.kubernetes.toolkit import K8sToolkit

MAX_ITERATIONS = 10
MAX_OBSERVATION_CHARS = 12000

DEFAULT_INCIDENT = (
    "Investigate the Kubernetes cluster for current incidents, unhealthy resources, "
    "failing workloads, or any other anomalous state. Determine the root cause."
)

READ_TOOLS = [
    "list_resources",
    "get_resource",
    "get_events",
    "get_logs",
    "get_owner",
    "get_owned_resources",
    "find_resources_by_labels",
    "find_resources_by_selector",
    "discover_api_resources",
    "get_resource_usage",
]

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

OLLAMA_TOOLS = [
    {"type": "function", "function": {"name": "list_resources", "description": "List Kubernetes resources of a kind, optionally filtered by namespace, label selector, or field selector.", "parameters": {"type": "object", "properties": {"kind": {"type": "string"}, "namespace": {"type": ["string", "null"]}, "api_version": {"type": ["string", "null"]}, "label_selector": {"type": ["string", "null"]}, "field_selector": {"type": ["string", "null"]}}, "required": ["kind"]}}},
    {"type": "function", "function": {"name": "get_resource", "description": "Read a single Kubernetes resource by kind, namespace, and name.", "parameters": {"type": "object", "properties": {"kind": {"type": "string"}, "namespace": {"type": ["string", "null"]}, "name": {"type": "string"}, "api_version": {"type": ["string", "null"]}}, "required": ["kind", "name"]}}},
    {"type": "function", "function": {"name": "get_events", "description": "Read Kubernetes events, optionally scoped to a namespace or resource name.", "parameters": {"type": "object", "properties": {"namespace": {"type": ["string", "null"]}, "resource_name": {"type": ["string", "null"]}, "event_type": {"type": ["string", "null"]}}, "required": []}}},
    {"type": "function", "function": {"name": "get_logs", "description": "Read container logs for a pod.", "parameters": {"type": "object", "properties": {"namespace": {"type": "string"}, "pod": {"type": "string"}, "container": {"type": ["string", "null"]}, "previous": {"type": "boolean"}, "tail_lines": {"type": "integer"}}, "required": ["namespace", "pod"]}}},
    {"type": "function", "function": {"name": "get_owner", "description": "Resolve the ownerReferences of a resource up to the top-level owner.", "parameters": {"type": "object", "properties": {"kind": {"type": "string"}, "namespace": {"type": ["string", "null"]}, "name": {"type": "string"}}, "required": ["kind", "name"]}}},
    {"type": "function", "function": {"name": "get_owned_resources", "description": "Find all resources in the same namespace that have ownerReferences pointing to the named resource.", "parameters": {"type": "object", "properties": {"kind": {"type": "string"}, "namespace": {"type": ["string", "null"]}, "name": {"type": "string"}}, "required": ["kind", "name"]}}},
    {"type": "function", "function": {"name": "find_resources_by_labels", "description": "Find resources of a given kind whose labels match the provided label dictionary.", "parameters": {"type": "object", "properties": {"labels": {"type": "object"}, "namespace": {"type": ["string", "null"]}, "kind": {"type": "string"}}, "required": ["labels"]}}},
    {"type": "function", "function": {"name": "find_resources_by_selector", "description": "Find resources of a given kind matching a Kubernetes selector dictionary.", "parameters": {"type": "object", "properties": {"selector": {"type": "object"}, "namespace": {"type": ["string", "null"]}, "kind": {"type": "string"}}, "required": ["selector"]}}},
    {"type": "function", "function": {"name": "discover_api_resources", "description": "Return the read-safe resource kinds the tool layer supports.", "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "get_resource_usage", "description": "Request resource usage metrics if metrics-server is available.", "parameters": {"type": "object", "properties": {"namespace": {"type": ["string", "null"]}, "kind": {"type": "string"}, "name": {"type": ["string", "null"]}}, "required": []}}},
]


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
            message = chat(messages, tools=OLLAMA_TOOLS)
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

    def _execute_tool(self, tool_name: Any, arguments: Any) -> dict:
        if tool_name not in READ_TOOLS:
            return {
                "success": False,
                "error": {
                    "code": "INVALID_TOOL",
                    "message": f"Tool '{tool_name}' is not available. Use one of {READ_TOOLS}.",
                },
            }

        if not isinstance(arguments, dict):
            return {
                "success": False,
                "error": {
                    "code": "INVALID_ARGUMENTS",
                    "message": "arguments must be a JSON object of keyword arguments.",
                },
            }

        tool = getattr(self.toolkit, tool_name)
        try:
            bound = inspect.signature(tool).bind(**arguments)
            bound.apply_defaults()
            arguments = bound.arguments
        except Exception as exc:
            return {
                "success": False,
                "error": {
                    "code": "INVALID_ARGUMENTS",
                    "message": str(exc),
                },
            }

        call_key = (tool_name, json.dumps(arguments, sort_keys=True, default=str))
        if call_key in self.seen_calls:
            return {
                "success": False,
                "error": {
                    "code": "REPEATED_CALL",
                    "message": "This exact tool call was already made.",
                },
            }
        self.seen_calls.add(call_key)

        try:
            return tool(**arguments)
        except Exception as exc:
            logger.exception("SRE agent tool execution failed")
            return {
                "success": False,
                "error": {
                    "code": "TOOL_ERROR",
                    "message": str(exc),
                },
            }

    def _format_observation(
        self, iteration: int, tool_name: Any, arguments: Any, result: dict
    ) -> str:
        compact = self._compact(result)
        return (
            f"Turn {iteration}: tool={tool_name} "
            f"arguments={json.dumps(arguments, default=str)} -> {compact}"
        )

    def _compact(self, value: Any) -> str:
        text = json.dumps(value, default=str)
        if len(text) > MAX_OBSERVATION_CHARS:
            return text[:MAX_OBSERVATION_CHARS] + " ... [truncated]"
        return text

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
            "success": result.get("success") if isinstance(result, dict) else False,
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

        if name == "list_resources":
            return f"Listing {kind or 'resources'}" if kind else "Listing resources"
        if name == "get_resource" and kind:
            return f"Inspecting {kind}"
        if name in ("get_owner", "get_owned_resources"):
            return "Inspecting ownership"
        if name in ("find_resources_by_labels", "find_resources_by_selector"):
            return "Searching related resources"
        if name == "get_events":
            return "Analyzing events"
        if name == "get_logs":
            return "Reading logs"
        if name == "discover_api_resources":
            return "Discovering APIs"
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
