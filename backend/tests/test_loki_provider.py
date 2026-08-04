import pytest

from backend.providers.loki_provider import LokiClient, LokiProvider


class FakeResponse:
    def __init__(self, status_code, json_data):
        self.status_code = status_code
        self._json = json_data
        self.text = str(json_data)

    def json(self):
        return self._json


class FakeLokiClient:
    def __init__(self, data):
        self._data = data

    def query_range(self, query, start=None, end=None, limit=100):
        return self._data

    def health(self):
        return {"healthy": True}


def test_normalize_loki_response():
    data = {
        "data": {
            "result": [
                {
                    "stream": {"namespace": "sre-lab", "pod": "nginx-abc", "container": "nginx"},
                    "values": [
                        ["1720000000000000000", "GET /health 200"],
                        ["1720000001000000000", "GET /ready 500"],
                    ],
                }
            ]
        }
    }
    provider = LokiProvider(client=FakeLokiClient(data))
    evidence = provider.collect(query={"query": '{namespace="sre-lab"}'})
    assert len(evidence) == 2
    assert evidence[0].resource == "Pod/sre-lab/nginx-abc/nginx"
    assert evidence[0].payload["line"] == "GET /health 200"


def test_collect_returns_empty_on_missing_data():
    provider = LokiProvider(client=FakeLokiClient(None))
    assert provider.collect() == []


def test_execute_returns_evidence():
    data = {"data": {"result": []}}
    provider = LokiProvider(client=FakeLokiClient(data))
    ev = provider.execute("query_logs", query='{namespace="sre-lab"}')
    assert ev.provider == "loki"
    assert ev.type == "logs"
    assert ev.payload["arguments"]["query"] == '{namespace="sre-lab"}'
