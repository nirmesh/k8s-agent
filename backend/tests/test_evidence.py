from backend.evidence.graph import EvidenceGraph
from backend.evidence.model import Evidence


def test_evidence_creation():
    e = Evidence(provider="kubernetes", type="event", resource="Pod/default/nginx", payload={"message": "oom"})
    assert e.provider == "kubernetes"
    assert e.type == "event"
    assert e.resource == "Pod/default/nginx"


def test_evidence_graph_adds_nodes_and_edges():
    graph = EvidenceGraph()
    e1 = Evidence(provider="kubernetes", type="event", resource="Pod/default/nginx", payload={})
    e2 = Evidence(provider="kubernetes", type="log", resource="Pod/default/nginx", payload={})
    e3 = Evidence(provider="prometheus", type="metric", resource="Pod/default/app", payload={})
    graph.add([e1, e2, e3])

    assert len(graph.nodes) == 3
    assert len(graph.edges) == 1
    assert graph.for_resource("Pod/default/nginx") == [e1, e2]


def test_evidence_graph_related():
    graph = EvidenceGraph()
    e1 = Evidence(provider="kubernetes", type="event", resource="Pod/default/nginx", payload={})
    e2 = Evidence(provider="kubernetes", type="log", resource="Pod/default/nginx", payload={})
    graph.add([e1, e2])

    related = graph.related("Pod/default/nginx")
    assert len(related) == 2
