from __future__ import annotations

from collections import defaultdict
from typing import Any

from backend.evidence.model import Evidence


class EvidenceGraph:
    """Simple in-memory evidence graph. Nodes are Evidence objects and edges
    represent shared resources or explicit relationships."""

    def __init__(self):
        self._nodes: list[Evidence] = []
        self._by_resource: dict[str, list[Evidence]] = defaultdict(list)
        self._edges: list[tuple[str, str]] = []

    def add(self, evidence: Evidence | list[Evidence]) -> "EvidenceGraph":
        items = evidence if isinstance(evidence, list) else [evidence]
        for item in items:
            self._nodes.append(item)
            self._by_resource[item.resource].append(item)
        self._rebuild_edges()
        return self

    def _rebuild_edges(self) -> None:
        self._edges = []
        for resource, nodes in self._by_resource.items():
            if len(nodes) > 1:
                first = nodes[0].resource
                for node in nodes[1:]:
                    self._edges.append((first, node.resource))

    @property
    def nodes(self) -> list[Evidence]:
        return list(self._nodes)

    @property
    def edges(self) -> list[tuple[str, str]]:
        return list(self._edges)

    def for_resource(self, resource: str) -> list[Evidence]:
        return list(self._by_resource.get(resource, []))

    def related(self, resource: str, max_hops: int = 1) -> list[Evidence]:
        """Return all evidence within max_hops of a resource (shared resource hop)."""
        if max_hops < 1:
            return self.for_resource(resource)
        related: set[str] = {resource}
        for _ in range(max_hops):
            next_layer: set[str] = set()
            for res in list(related):
                for edge in self._edges:
                    if res in edge:
                        next_layer.update(edge)
            related.update(next_layer)
        results: list[Evidence] = []
        for res in related:
            results.extend(self._by_resource.get(res, []))
        return results

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [n.model_dump(mode="json") for n in self._nodes],
            "edges": self._edges,
        }
