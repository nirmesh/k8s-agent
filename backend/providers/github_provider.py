import base64
from datetime import datetime, timezone
from typing import Any

import httpx

from backend.core.logging import logger
from backend.evidence.model import Evidence
from backend.providers.base import EvidenceProvider


_GITHUB_TOOLS_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "get_commits",
            "description": "Fetch recent commits for a GitHub repository.",
            "parameters": {
                "type": "object",
                "properties": {
                    "owner": {"type": "string"},
                    "repo": {"type": "string"},
                    "branch": {"type": ["string", "null"], "default": None},
                    "per_page": {"type": "integer", "default": 10},
                },
                "required": ["owner", "repo"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_pull_requests",
            "description": "Fetch pull requests for a GitHub repository.",
            "parameters": {
                "type": "object",
                "properties": {
                    "owner": {"type": "string"},
                    "repo": {"type": "string"},
                    "state": {"type": "string", "default": "open"},
                    "per_page": {"type": "integer", "default": 10},
                },
                "required": ["owner", "repo"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_releases",
            "description": "Fetch recent releases for a GitHub repository.",
            "parameters": {
                "type": "object",
                "properties": {
                    "owner": {"type": "string"},
                    "repo": {"type": "string"},
                    "per_page": {"type": "integer", "default": 10},
                },
                "required": ["owner", "repo"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_manifest",
            "description": "Fetch a deployment manifest file (or directory listing) from a GitHub repository.",
            "parameters": {
                "type": "object",
                "properties": {
                    "owner": {"type": "string"},
                    "repo": {"type": "string"},
                    "path": {"type": "string", "default": "deployments"},
                    "ref": {"type": ["string", "null"], "default": None},
                },
                "required": ["owner", "repo"],
            },
        },
    },
]


class GitHubProvider(EvidenceProvider):
    """Provider that surfaces GitHub commits, PRs, releases and manifests as evidence."""

    def __init__(
        self,
        token: str | None = None,
        owner: str | None = None,
        repo: str | None = None,
    ):
        self._token = token
        self._owner = owner
        self._repo = repo
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.Client(
            base_url="https://api.github.com",
            headers=headers,
            timeout=20.0,
        )

    @property
    def name(self) -> str:
        return "github"

    def health(self) -> dict[str, Any]:
        try:
            resp = self._client.get("/rate_limit")
            return {"healthy": resp.status_code == 200, "status": resp.status_code}
        except Exception as exc:
            logger.warning(f"GitHub provider health check failed: {exc}")
            return {"healthy": False, "error": str(exc)}

    def capabilities(self) -> list[str]:
        return ["github", "commits", "pull_requests", "releases", "manifests"]

    def tools(self) -> list[dict[str, Any]]:
        return _GITHUB_TOOLS_SCHEMA

    def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        try:
            resp = self._client.get(path, params=params)
            if resp.status_code == 200:
                return resp.json()
            logger.warning(f"GitHub API {path} returned {resp.status_code}: {resp.text[:200]}")
        except Exception as exc:
            logger.warning(f"GitHub API request {path} failed: {exc}")
        return None

    def execute(self, tool: str, **kwargs) -> Evidence:
        owner = kwargs.get("owner") or self._owner
        repo = kwargs.get("repo") or self._repo
        if not owner or not repo:
            raise ValueError("GitHub provider requires owner and repo")
        if tool == "get_commits":
            payload = self.get_commits(owner, repo, kwargs.get("branch"), kwargs.get("per_page", 10))
        elif tool == "get_pull_requests":
            payload = self.get_pull_requests(owner, repo, kwargs.get("state", "open"), kwargs.get("per_page", 10))
        elif tool == "get_releases":
            payload = self.get_releases(owner, repo, kwargs.get("per_page", 10))
        elif tool == "get_manifest":
            payload = self.get_manifest(owner, repo, kwargs.get("path", "deployments"), kwargs.get("ref"))
        else:
            raise NotImplementedError(f"Tool '{tool}' is not supported by the GitHub provider")
        return Evidence(
            provider=self.name,
            type="github",
            resource=f"{tool}/{owner}/{repo}",
            payload={"tool": tool, "arguments": kwargs, "result": payload},
        )

    def collect(self, query: dict[str, Any] | None = None) -> list[Evidence]:
        query = query or {}
        owner = query.get("owner") or self._owner
        repo = query.get("repo") or self._repo
        if not owner or not repo:
            return []
        evidence: list[Evidence] = []
        kind = query.get("kind") or "commits"
        if kind in ("commits", "all"):
            for commit in self.get_commits(owner, repo) or []:
                evidence.append(self._commit_evidence(owner, repo, commit))
        if kind in ("pull_requests", "pulls", "all"):
            for pr in self.get_pull_requests(owner, repo) or []:
                evidence.append(self._pr_evidence(owner, repo, pr))
        if kind in ("releases", "all"):
            for release in self.get_releases(owner, repo) or []:
                evidence.append(self._release_evidence(owner, repo, release))
        if kind in ("manifests", "all"):
            path = query.get("path", "deployments")
            manifest = self.get_manifest(owner, repo, path)
            if manifest:
                evidence.append(self._manifest_evidence(owner, repo, path, manifest))
        return evidence

    def get_commits(
        self, owner: str, repo: str, branch: str | None = None, per_page: int = 10
    ) -> list[dict[str, Any]] | None:
        params: dict[str, Any] = {"per_page": per_page}
        if branch:
            params["sha"] = branch
        return self._get(f"/repos/{owner}/{repo}/commits", params=params)

    def get_pull_requests(
        self, owner: str, repo: str, state: str = "open", per_page: int = 10
    ) -> list[dict[str, Any]] | None:
        return self._get(
            f"/repos/{owner}/{repo}/pulls",
            params={"state": state, "per_page": per_page},
        )

    def get_releases(self, owner: str, repo: str, per_page: int = 10) -> list[dict[str, Any]] | None:
        return self._get(f"/repos/{owner}/{repo}/releases", params={"per_page": per_page})

    def get_manifest(
        self, owner: str, repo: str, path: str = "deployments", ref: str | None = None
    ) -> dict[str, Any] | list[dict[str, Any]] | None:
        params: dict[str, Any] = {}
        if ref:
            params["ref"] = ref
        data = self._get(f"/repos/{owner}/{repo}/contents/{path}", params=params)
        if data is None:
            return None
        if isinstance(data, list):
            return [self._decode_file(item) for item in data]
        return self._decode_file(data)

    def _decode_file(self, item: dict[str, Any]) -> dict[str, Any]:
        content = item.get("content")
        if content:
            try:
                item["decoded_content"] = base64.b64decode(content).decode("utf-8")
            except Exception:
                item["decoded_content"] = None
        return item

    def _commit_evidence(self, owner: str, repo: str, commit: dict[str, Any]) -> Evidence:
        sha = commit.get("sha", "unknown")
        commit_data = commit.get("commit", {})
        message = commit_data.get("message", "")
        author = commit_data.get("author", {})
        return Evidence(
            provider=self.name,
            type="github_commit",
            resource=f"Commit/{owner}/{repo}/{sha}",
            timestamp=_parse_gh_ts(author.get("date")),
            payload={
                "sha": sha,
                "message": message,
                "author": author.get("name"),
                "url": commit.get("html_url"),
            },
        )

    def _pr_evidence(self, owner: str, repo: str, pr: dict[str, Any]) -> Evidence:
        number = pr.get("number", "unknown")
        return Evidence(
            provider=self.name,
            type="github_pull_request",
            resource=f"PR/{owner}/{repo}/{number}",
            payload={
                "number": number,
                "title": pr.get("title"),
                "state": pr.get("state"),
                "user": pr.get("user", {}).get("login"),
                "body": pr.get("body"),
                "url": pr.get("html_url"),
            },
        )

    def _release_evidence(self, owner: str, repo: str, release: dict[str, Any]) -> Evidence:
        tag = release.get("tag_name", "unknown")
        return Evidence(
            provider=self.name,
            type="github_release",
            resource=f"Release/{owner}/{repo}/{tag}",
            timestamp=_parse_gh_ts(release.get("published_at")),
            payload={
                "tag": tag,
                "name": release.get("name"),
                "body": release.get("body"),
                "url": release.get("html_url"),
            },
        )

    def _manifest_evidence(
        self, owner: str, repo: str, path: str, manifest: Any
    ) -> Evidence:
        return Evidence(
            provider=self.name,
            type="github_manifest",
            resource=f"Manifest/{owner}/{repo}/{path}",
            payload={"path": path, "content": manifest},
        )


def _parse_gh_ts(ts: str | None) -> Any:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None
