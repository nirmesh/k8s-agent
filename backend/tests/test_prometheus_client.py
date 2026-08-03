from unittest.mock import MagicMock

from backend.observability.prometheus_client import PrometheusClient


def test_query_success(monkeypatch):
    mock_response = MagicMock()
    mock_response.json.return_value = {"status": "success", "data": {"resultType": "vector", "result": []}}
    mock_response.raise_for_status = MagicMock()
    mock_get = MagicMock(return_value=mock_response)
    monkeypatch.setattr("httpx.get", mock_get)

    client = PrometheusClient(base_url="http://test-prometheus")
    result = client.query("up")

    assert result["status"] == "success"
    mock_get.assert_called_once()
