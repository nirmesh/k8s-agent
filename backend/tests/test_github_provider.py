import pytest

from backend.providers.github_provider import GitHubProvider


class FakeResponse:
    def __init__(self, status_code, json_data):
        self.status_code = status_code
        self._json = json_data
        self.text = str(json_data)

    def json(self):
        return self._json


class FakeClient:
    def __init__(self, responses):
        self.responses = responses
        self.headers = {}

    def get(self, path, params=None):
        for p, data in self.responses:
            if path.startswith(p):
                return FakeResponse(200, data)
        return FakeResponse(404, {})


def test_get_commits_normalizes_evidence(monkeypatch):
    commits = [
        {
            "sha": "abc123",
            "commit": {
                "message": "Fix readiness probe",
                "author": {"name": "alice", "date": "2026-08-01T12:00:00Z"},
            },
            "html_url": "https://github.com/o/r/commit/abc123",
        }
    ]
    provider = GitHubProvider()
    monkeypatch.setattr(provider, "_client", FakeClient([("/repos/o/r/commits", commits)]))
    result = provider.get_commits("o", "r")
    assert result == commits
    ev = provider._commit_evidence("o", "r", commits[0])
    assert ev.type == "github_commit"
    assert ev.payload["message"] == "Fix readiness probe"


def test_get_manifest_decodes_base64(monkeypatch):
    import base64

    encoded = base64.b64encode(b"apiVersion: v1\nkind: Pod").decode("utf-8")
    manifest = {"name": "deployment.yaml", "content": encoded}
    provider = GitHubProvider()
    monkeypatch.setattr(provider, "_client", FakeClient([("/repos/o/r/contents/deployments", [manifest])]))
    result = provider.get_manifest("o", "r")
    assert isinstance(result, list)
    assert result[0]["decoded_content"] == "apiVersion: v1\nkind: Pod"


def test_execute_returns_evidence(monkeypatch):
    prs = [{"number": 42, "title": "Fix probe", "state": "open", "html_url": "url"}]
    provider = GitHubProvider()
    monkeypatch.setattr(provider, "_client", FakeClient([("/repos/o/r/pulls", prs)]))
    ev = provider.execute("get_pull_requests", owner="o", repo="r")
    assert ev.provider == "github"
    assert ev.type == "github"
    assert ev.payload["result"] == prs
