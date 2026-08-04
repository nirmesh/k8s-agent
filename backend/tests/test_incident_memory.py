import pytest

from backend.memory.incident_memory import IncidentMemory


class FakeCollection:
    def __init__(self):
        self._docs: list[dict] = []
        self._next_id = 1

    def insert_one(self, doc):
        doc["_id"] = self._next_id
        self._next_id += 1
        self._docs.append(doc)
        return type("Result", (), {"inserted_id": doc["_id"]})()

    def find_one(self, filter):
        for d in self._docs:
            match = True
            for k, v in filter.items():
                if k == "_id" and d.get("_id") == v:
                    continue
                if d.get(k) != v:
                    match = False
                    break
            if match:
                return d
        return None

    def find(self):
        return iter(self._docs)


class FakeDB:
    def __init__(self):
        self.incident_memory = FakeCollection()

    def __getitem__(self, name):
        return getattr(self, name)


def test_store_and_retrieve_incident():
    mem = IncidentMemory(db=FakeDB())
    mid = mem.store(
        symptoms=["pod crashloopbackoff", " readiness probe failing"],
        evidence=[{"provider": "kubernetes", "type": "event"}],
        diagnosis={"root_cause": "readiness probe path wrong"},
        remediation={"tool": "patch_resource"},
        verification={"status": "RESOLVED"},
        confidence=0.9,
    )
    doc = mem.get(mid)
    assert doc is not None
    assert doc["confidence"] == 0.9
    assert "readiness" in doc["tokens"]


def test_search_similar_incidents():
    mem = IncidentMemory(db=FakeDB())
    mem.store(
        symptoms=["pod not ready", "readiness probe 404"],
        evidence=[],
        diagnosis={"root_cause": "readiness probe path is wrong"},
        remediation={},
        verification={},
        confidence=0.8,
    )
    mem.store(
        symptoms=["node disk pressure", "pod evicted"],
        evidence=[],
        diagnosis={"root_cause": "disk full"},
        remediation={},
        verification={},
        confidence=0.6,
    )
    results = mem.search_similar_incidents("readiness probe failing")
    assert len(results) >= 1
    assert results[0]["diagnosis"]["root_cause"] == "readiness probe path is wrong"
    assert results[0]["similarity_score"] > 0


def test_search_returns_empty_for_no_match():
    mem = IncidentMemory(db=FakeDB())
    mem.store(
        symptoms=["disk pressure"],
        evidence=[],
        diagnosis={"root_cause": "disk full"},
        remediation={},
        verification={},
        confidence=0.5,
    )
    assert mem.search_similar_incidents("network policy blocking traffic") == []
