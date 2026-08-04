from __future__ import annotations

from typing import Any

from backend.core.logging import logger
from backend.evidence.model import Evidence
from backend.providers.base import EvidenceProvider


class ProviderRegistry:
    """Registry for evidence providers. Investigators use this to discover and
    call tools without knowing which provider supplies them."""

    def __init__(self):
        self._providers: dict[str, EvidenceProvider] = {}
        self._tool_map: dict[str, str] = {}

    def register(self, provider: EvidenceProvider) -> "ProviderRegistry":
        self._providers[provider.name] = provider
        for tool in provider.tools() or []:
            fn = tool.get("function") or tool.get("tool")
            if isinstance(fn, dict) and fn.get("name"):
                tool_name = str(fn["name"])
                self._tool_map[tool_name] = provider.name
        return self

    def get(self, name: str) -> EvidenceProvider:
        if name not in self._providers:
            raise KeyError(f"Provider '{name}' is not registered")
        return self._providers[name]

    def list(self) -> list[str]:
        return list(self._providers.keys())

    def collect_all(self, query: dict[str, Any] | None = None) -> list[Evidence]:
        evidence: list[Evidence] = []
        for provider in self._providers.values():
            try:
                evidence.extend(provider.collect(query))
            except Exception as exc:
                logger.warning(f"Provider '{provider.name}' collection failed: {exc}")
        return evidence

    def tools(self) -> list[dict[str, Any]]:
        tools: list[dict[str, Any]] = []
        for provider in self._providers.values():
            tools.extend(provider.tools() or [])
        return tools

    def execute_tool(self, tool: str, **kwargs) -> Evidence:
        provider_name = self._tool_map.get(tool)
        if provider_name is None:
            raise NotImplementedError(f"Tool '{tool}' is not provided by any registered provider")
        provider = self._providers[provider_name]
        return provider.execute(tool, **kwargs)

    def tool_names(self) -> list[str]:
        return list(self._tool_map.keys())

    def health(self) -> dict[str, Any]:
        return {name: provider.health() for name, provider in self._providers.items()}


_DEFAULT_REGISTRY: ProviderRegistry | None = None


def get_registry(context: str | None = None, config_path: str | None = None) -> ProviderRegistry:
    """Return the default global registry, lazily initializing it."""
    global _DEFAULT_REGISTRY
    if _DEFAULT_REGISTRY is None:
        from backend.providers.kubernetes_provider import KubernetesProvider
        from backend.providers.security_provider import SecurityEvidenceProvider

        _DEFAULT_REGISTRY = ProviderRegistry()
        _DEFAULT_REGISTRY.register(KubernetesProvider(context=context, config_path=config_path))
        _DEFAULT_REGISTRY.register(SecurityEvidenceProvider())
    return _DEFAULT_REGISTRY
