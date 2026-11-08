# SPDX-License-Identifier: AGPL-3.0-only
"""GitHub REST reads and narrow writes. The token stays on this object."""

import json
import urllib.error
import urllib.request
from urllib.parse import quote, urlsplit

from free_claude_code.assignments.errors import Forbidden, MergeRejected, TimedOut
from free_claude_code.assignments.models import IssueSnapshot, PublicationPlan
from free_claude_code.assignments.redact import redact

_MERGE_PATHS = ("/merge", "/merges")


class GitHubHttpClient:
    """Talk to one configured API origin. Redirects are refused."""

    def __init__(self, base_url: str, token: str, *, timeout: float = 10.0) -> None:
        parsed = urlsplit(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise Forbidden("github API base must be an absolute http(s) URL")
        self.base_url = base_url.rstrip("/")
        self._token = token
        self.timeout = timeout
        self._opener = urllib.request.build_opener(_NoRedirect())

    def __repr__(self) -> str:
        return f"GitHubHttpClient(base={self.base_url})"

    def fetch_issue(
        self, owner: str, repo: str, number: int, *, timeout: float
    ) -> IssueSnapshot:
        payload = self._json(
            "GET", f"/repos/{_seg(owner)}/{_seg(repo)}/issues/{number}", timeout=timeout
        )
        return IssueSnapshot(
            owner=owner,
            repo=repo,
            number=number,
            title=str(payload.get("title", "")),
            body=str(payload.get("body") or ""),
            state=str(payload.get("state", "")),
            updated_at=str(payload.get("updated_at", "")),
            node_id=str(payload.get("node_id", "")),
        )

    def fetch_branch_sha(
        self, owner: str, repo: str, branch: str, *, timeout: float
    ) -> str:
        payload = self._json(
            "GET",
            f"/repos/{_seg(owner)}/{_seg(repo)}/branches/{_seg(branch)}",
            timeout=timeout,
        )
        commit = payload.get("commit")
        if not isinstance(commit, dict) or not isinstance(commit.get("sha"), str):
            raise Forbidden("branch response did not include a commit SHA")
        return commit["sha"]

    def fetch_diff(self, owner: str, repo: str, base: str, head: str, *, timeout: float) -> str:
        path = f"/repos/{_seg(owner)}/{_seg(repo)}/compare/{_seg(base)}...{_seg(head)}"
        return self._bytes(
            "GET", path, timeout=timeout, accept="application/vnd.github.diff"
        ).decode("utf-8", errors="replace")

    def fetch_check_runs(self, owner: str, repo: str, sha: str, *, timeout: float) -> list[dict]:
        payload = self._json(
            "GET",
            f"/repos/{_seg(owner)}/{_seg(repo)}/commits/{_seg(sha)}/check-runs",
            timeout=timeout,
        )
        runs = payload.get("check_runs")
        if not isinstance(runs, list):
            raise Forbidden("check-runs response was not a list")
        return [run for run in runs if isinstance(run, dict)]

    def fetch_job_log(self, owner: str, repo: str, job_id: int, *, timeout: float) -> str:
        path = f"/repos/{_seg(owner)}/{_seg(repo)}/actions/jobs/{job_id}/logs"
        return self._bytes("GET", path, timeout=timeout, accept="text/plain").decode(
            "utf-8", errors="replace"
        )

    def rerun_job(self, owner: str, repo: str, job_id: int, *, timeout: float) -> None:
        path = f"/repos/{_seg(owner)}/{_seg(repo)}/actions/jobs/{job_id}/rerun"
        self._bytes("POST", path, timeout=timeout, body=b"")

    def create_pull_request_for(
        self, owner: str, repo: str, plan: PublicationPlan, *, timeout: float = 10.0
    ) -> str:
        if plan.auto_merge or plan.direct_push:
            raise MergeRejected("publication cannot merge or push the default branch")
        payload = self._json(
            "POST",
            f"/repos/{_seg(owner)}/{_seg(repo)}/pulls",
            timeout=timeout,
            body={
                "title": plan.title,
                "body": plan.body,
                "head": plan.head_branch,
                "base": plan.base_branch,
                "maintainer_can_modify": False,
            },
        )
        url = payload.get("html_url")
        if not isinstance(url, str) or not url:
            raise Forbidden("pull request response did not include a url")
        return url

    def _json(self, method: str, path: str, *, timeout: float, body: dict | None = None) -> dict:
        raw = self._bytes(
            method,
            path,
            timeout=timeout,
            body=None if body is None else json.dumps(body).encode("utf-8"),
            content_type="application/json" if body is not None else None,
        )
        if not raw:
            return {}
        loaded = json.loads(raw.decode("utf-8"))
        if not isinstance(loaded, dict):
            raise Forbidden("github response was not an object")
        return loaded

    def _bytes(
        self,
        method: str,
        path: str,
        *,
        timeout: float,
        accept: str = "application/json",
        body: bytes | None = None,
        content_type: str | None = None,
    ) -> bytes:
        lowered = path.lower()
        if any(marker in lowered for marker in _MERGE_PATHS):
            raise MergeRejected("merge endpoints are not available")
        url = self.base_url + path
        self._same_origin(url)
        request = urllib.request.Request(url, data=body, method=method)
        request.add_header("Authorization", f"Bearer {self._token}")
        request.add_header("Accept", accept)
        if content_type:
            request.add_header("Content-Type", content_type)
        try:
            with self._opener.open(request, timeout=timeout) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            detail = redact(exc.read().decode("utf-8", errors="replace")[:500])
            raise Forbidden(f"github http {exc.code}: {detail}") from None
        except TimeoutError as exc:
            raise TimedOut("github http timed out") from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, TimeoutError):
                raise TimedOut("github http timed out") from exc
            raise Forbidden(f"github http failed: {redact(str(exc.reason))}") from None

    def _same_origin(self, url: str) -> None:
        target = urlsplit(url)
        base = urlsplit(self.base_url)
        if (target.scheme, target.hostname, target.port) != (
            base.scheme,
            base.hostname,
            base.port,
        ):
            raise Forbidden("refusing a request outside the configured API base")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> urllib.request.Request | None:
        raise Forbidden("refusing an API redirect")


def _seg(value: str) -> str:
    if "/" in value or value in {"", ".", ".."}:
        raise Forbidden("refusing an unsafe github path segment")
    return quote(value, safe="")
