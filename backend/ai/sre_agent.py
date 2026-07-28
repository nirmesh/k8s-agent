import inspect
import json
import time
from collections.abc import Callable
from typing import Any

from backend.ai.llm_client import generate
from backend.core.logging import logger
from backend.kubernetes.toolkit import K8sToolkit

MAX_ITERATIONS = 10
MAX_OBSERVATION_CHARS = 4000

DEFAULT_INCIDENT = (
    "Investigate the Kubernetes cluster for current incidents, unhealthy resources, "
    "failing workloads, or any other anomalous state. Determine the root cause."
)

READ_TOOLS = [
    "get_resources",
    "get_resource",
    "get_events",
    "get_logs",
    "get_owner",
    "get_rollout_status",
]

_SYSTEM_PROMPT = """You are a Kubernetes SRE investigator.

Your job is to determine the root cause of Kubernetes incidents using evidence.

Do not assume cluster state. Use available tools to gather evidence.

Prefer this investigation sequence when applicable:
1. Resource status (get_resources / get_resource)
2. Kubernetes events (get_events)
3. Owner/workload (get_owner)
4. Workload manifest (get_resource)
5. Relevant logs (get_logs)

Do not keep calling tools after sufficient evidence exists.
Do not invent resources, logs, events, image tags, namespaces, or configuration.
If evidence is insufficient, explicitly state what evidence is missing.
When the root cause is established, return a structured diagnosis.
You cannot modify the Kubernetes cluster.

The `affectedResources` list must use the exact resource identifiers from your tool output, with the form:
"kind/namespace/name" (for example, "Deployment/sre-lab/broken-nginx" or "Pod/sre-lab/broken-nginx-759c68c44c-n26w8").
For pod-level symptoms such as ImagePullBackOff, identify the owning Deployment/ReplicaSet and use that workload as the affected resource that the remediation should modify.

Available tools (JSON mode):

- get_resources(kind: string, namespace?: string)
  Returns a list of resources. Use namespace to scope, omit for all namespaces.

- get_resource(kind: string, namespace: string | null, name: string)
  Returns a single resource. Use namespace=null for cluster-scoped resources.

- get_events(namespace?: string, resource_name?: string)
  Returns Kubernetes events. Provide resource_name to filter by involved object.

- get_logs(namespace: string, pod: string, container?: string, tail_lines?: int)
  Returns container logs. Default tail_lines is 100.

- get_owner(kind: string, namespace: string | null, name: string)
  Reads a resource and resolves its ownerReferences to the owning resources.

- get_rollout_status(kind: string, namespace: string | null, name: string)
  Returns readiness for Deployment, StatefulSet, DaemonSet, or ReplicaSet.

On every turn you must return exactly one JSON object. No markdown, no explanation outside the JSON.

To call a tool:
{
  "action": "tool_call",
  "tool": "get_resource",
  "arguments": {
    "kind": "pod",
    "namespace": "default",
    "name": "my-pod"
  }
}

To finish with a diagnosis:
{
  "action": "diagnose",
  "diagnosis": {
    "status": "DIAGNOSED | NEED_MORE_EVIDENCE | UNKNOWN",
    "incidentType": "...",
    "rootCause": "...",
    "explanation": "...",
    "confidence": 0.0,
    "affectedResources": ["kind/name"],
    "evidence": [
      {
        "source": "event|log|resource|manifest",
        "description": "...",
        "value": "..."
      }
    ]
  }
}

Use status NEED_MORE_EVIDENCE only when you have exhausted useful tool calls.
Do not repeat a tool call with the exact same arguments.
"""


class SREAgent:
    """Bounded tool-using SRE agent backed by Ollama."""

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

        for iteration in range(1, self.max_iterations + 1):
            raw, llm_duration = self._call_ollama()
            parsed, parse_error = self._parse_json(raw)
            self._trace_llm(iteration, raw, parsed, parse_error, llm_duration)

            if parse_error:
                self.observations.append(
                    f"Turn {iteration}: LLM returned invalid JSON ({parse_error}). "
                    "Please return a valid JSON object."
                )
                continue

            action = parsed.get("action")

            if action == "diagnose":
                diagnosis = parsed.get("diagnosis")
                if not isinstance(diagnosis, dict):
                    diagnosis = {
                        "status": "UNKNOWN",
                        "incidentType": "unknown",
                        "rootCause": "Model returned a non-object diagnosis",
                        "explanation": json.dumps(parsed),
                        "confidence": 0.0,
                        "affectedResources": [],
                        "evidence": [],
                    }
                self._progress("Root Cause Found")
                return diagnosis

            if action == "tool_call":
                tool_name = parsed.get("tool")
                arguments = parsed.get("arguments", {})
                self.activities.append(f"Called {tool_name}")

                t0 = time.monotonic()
                result = self._execute_tool(tool_name, arguments)
                tool_duration = time.monotonic() - t0

                self._trace_tool(iteration, tool_name, arguments, result, tool_duration)
                self._maybe_progress(tool_name, arguments)
                self.observations.append(
                    self._format_observation(iteration, tool_name, arguments, result)
                )
                continue

            self.observations.append(
                f"Turn {iteration}: invalid action '{action}'. "
                "Use 'tool_call' or 'diagnose'."
            )

        # Exceeded iteration budget without a diagnosis.
        self._progress("Root Cause Found")
        return {
            "status": "UNKNOWN",
            "incidentType": "unknown",
            "rootCause": (
                "Investigation reached the maximum number of tool iterations "
                "without a structured diagnosis."
            ),
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
        }

    def _call_ollama(self) -> tuple[str, float]:
        prompt = self._build_prompt()
        start = time.monotonic()
        raw = generate(prompt, system=_SYSTEM_PROMPT)
        duration = time.monotonic() - start
        return raw, duration

    def _build_prompt(self) -> str:
        parts = [
            f"Incident: {self.incident_description}",
            "Available tool names: " + ", ".join(READ_TOOLS),
            "Observation history:",
            "\n\n".join(self.observations) if self.observations else "No observations yet.",
            "Return a single JSON object for your next turn. Do not wrap it in markdown.",
        ]
        return "\n\n".join(parts)

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
            return json.loads(text), None
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
            inspect.signature(tool).bind(**arguments)
        except Exception as exc:
            return {
                "success": False,
                "error": {
                    "code": "INVALID_ARGUMENTS",
                    "message": str(exc),
                },
            }

        call_key = (tool_name, json.dumps(arguments, sort_keys=True))
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
        parsed: dict | None,
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
        if parsed:
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
        kind = str(arguments.get("kind", "")).lower() if isinstance(arguments, dict) else ""

        if name == "get_resources" and kind == "pod":
            return "Checking Pods"
        if name == "get_logs":
            return "Reading Logs"
        if name == "get_events":
            return "Analyzing Events"
        if name in ("get_owner", "get_rollout_status"):
            return "Inspecting Deployments"
        if name == "get_resource" and kind in (
            "deployment",
            "statefulset",
            "daemonset",
            "replicaset",
        ):
            return "Inspecting Deployments"
        if name == "get_resource" and kind in ("service", "ingress", "networkpolicy"):
            return "Checking Networking"
        return None

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
    }
