from typing import Any

from backend.core.logging import logger
from backend.evidence.model import Evidence
from backend.kubernetes.toolkit import K8sToolkit
from backend.providers.base import EvidenceProvider


_READ_TOOLS_SCHEMA = [
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


class KubernetesProvider(EvidenceProvider):
    """Provider that wraps the existing K8sToolkit for Kubernetes evidence and tools."""

    def __init__(
        self,
        toolkit: K8sToolkit | None = None,
        context: str | None = None,
        config_path: str | None = None,
    ):
        self._toolkit = toolkit
        self.context = context
        self.config_path = config_path

    @property
    def name(self) -> str:
        return "kubernetes"

    def _get_toolkit(self) -> K8sToolkit:
        # Lazily initialize K8sToolkit to avoid side effects during import.
        if self._toolkit is None:
            self._toolkit = K8sToolkit(context=self.context, config_path=self.config_path)
        return self._toolkit

    def health(self) -> dict[str, Any]:
        try:
            self._get_toolkit().discover_api_resources()
            return {"healthy": True}
        except Exception as exc:
            logger.warning(f"Kubernetes provider health check failed: {exc}")
            return {"healthy": False, "error": str(exc)}

    def capabilities(self) -> list[str]:
        return ["kubernetes", "logs", "events", "resources"]

    def tools(self) -> list[dict[str, Any]]:
        return _READ_TOOLS_SCHEMA

    def execute(self, tool: str, **kwargs) -> Evidence:
        toolkit = self._get_toolkit()
        method = getattr(toolkit, tool, None)
        if method is None:
            raise NotImplementedError(f"Tool '{tool}' is not available on the Kubernetes provider")

        resource_id = f"{kwargs.get('kind', 'cluster')}/{kwargs.get('namespace') or 'default'}/{kwargs.get('name') or '-'}"
        result = method(**kwargs)
        return Evidence(
            provider=self.name,
            type="tool_result",
            resource=resource_id,
            payload={"tool": tool, "arguments": kwargs, "result": result},
        )

    def collect(self, query: dict[str, Any] | None = None) -> list[Evidence]:
        """Collect cluster-wide evidence. For now, delegates to signal collection if available."""
        if query:
            # Targeted collection by a single tool call.
            tool = query.get("tool")
            if tool and hasattr(self, "execute"):
                return [self.execute(tool, **{k: v for k, v in query.items() if k != "tool"})]
        return []
