# SPDX-License-Identifier: AGPL-3.0-only
"""Separate publisher process. Disabled until a caller sets enabled.

The publish token is read from the private secret file inside this process.
Git receives it through GIT_ASKPASS, not through argv. Model and test
environments never import this module's token.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

from free_claude_code.assignments.errors import Disabled, Forbidden, MergeRejected
from free_claude_code.assignments.execution import resolve_program, scrub_env
from free_claude_code.assignments.private_io import write_private_bytes
from free_claude_code.assignments.github_http import GitHubHttpClient
from free_claude_code.assignments.models import PublicationPlan
from free_claude_code.assignments.secrets import load_secret_file

_PREFIX = re.compile(r"claude[1-9][0-9]*\Z")


def pinned_origin(owner: str, repo: str) -> str:
    if not owner or not repo or "/" in owner or "/" in repo or owner.startswith("-") or repo.startswith("-"):
        raise Forbidden("publisher repository is not configured")
    return f"https://github.com/{owner}/{repo}.git"


def assert_pinned_origin(origin: str, owner: str, repo: str) -> str:
    """The only push URL is https://github.com/<owner>/<repo> from config."""

    pinned = pinned_origin(owner, repo)
    allowed = {pinned, pinned.removesuffix(".git")}
    if origin.rstrip("/") not in allowed:
        raise Forbidden("publisher origin must be https://github.com/<owner>/<repo>")
    return pinned


def feature_branch(task_id: str, branch_prefix: str) -> str:
    prefix = branch_prefix.strip().strip("/")
    if not _PREFIX.fullmatch(prefix):
        raise Forbidden("branch prefix must be the worker bare name")
    lowered = task_id.strip().lower()
    if not lowered or lowered != task_id.lower() or "/" in lowered or lowered.startswith("-"):
        raise Forbidden("task id must be a lowercase slug")
    if lowered in {"main", "master"}:
        raise MergeRejected("refusing a protected branch")
    return f"{prefix}/{lowered}"


def refuse_push_ref(ref: str, *, force: bool = False, tags: bool = False) -> None:
    """Reject protected branches, tags, and force pushes before git runs."""

    if force or tags:
        raise MergeRejected("force pushes and tags are refused")
    bare = ref.removeprefix("refs/heads/").removeprefix("refs/tags/")
    if ref.startswith("refs/tags/") or bare in {"main", "master"}:
        raise MergeRejected("refusing a protected branch")


def publish_feature(
    *,
    enabled: bool,
    secrets_file: Path,
    workspace: Path,
    task_id: str,
    origin: str,
    api_base: str,
    owner: str,
    repo: str,
    base_branch: str,
    title: str,
    body: str,
    head_sha: str,
    author_id: str,
    reviewer_id: str,
    manifest_id: str,
    branch_prefix: str,
    comment_signature: str,
    timeout: float = 10.0,
    force: bool = False,
    tags: bool = False,
    ca_file: Path | None = None,
) -> str:
    """Push one feature branch and open a pull request. Merge is not available.

    One manager attestation is recorded by the caller as both the execute and
    publish approval. This process does not mint a second signature.
    """

    if not enabled:
        raise Disabled("publisher is disabled")
    branch = feature_branch(task_id, branch_prefix)
    refuse_push_ref(f"refs/heads/{branch}", force=force, tags=tags)
    pinned = assert_pinned_origin(origin, owner, repo)
    if not comment_signature.startswith("— "):
        raise Forbidden("comment signature must name the worker")
    token = load_secret_file(secrets_file).get("github_publish")
    token_path = _token_file(secrets_file.parent, token)
    try:
        askpass = _askpass_helper(secrets_file.parent)
        env = scrub_env(os.environ)
        env.update(
            {
                "GIT_ASKPASS": str(askpass),
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "FCC_ASKPASS_FILE": str(token_path),
            }
        )
        if ca_file is not None:
            env["GIT_SSL_CAINFO"] = str(ca_file)
        if token in " ".join(env.get("GIT_ASKPASS", "")):
            raise Forbidden("publish token must not be placed on argv")
        command = (
            resolve_program("git"),
            "-c",
            "credential.helper=",
            "-c",
            "http.sslVerify=true",
            "push",
            pinned,
            f"HEAD:refs/heads/{branch}",
        )
        if any(part in {"--force", "--force-with-lease", "-f"} for part in command):
            raise MergeRejected("force pushes and tags are refused")
        if token in pinned or token in " ".join(command):
            raise Forbidden("publish token must not be placed on argv")
        workspace_dir = Path(workspace).expanduser().resolve(strict=False)
        if not workspace_dir.is_dir():
            raise Forbidden("publisher workspace is not a directory")
        completed = subprocess.run(
            command,
            cwd=str(workspace_dir),
            env=env,
            shell=False,
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            raise Forbidden("feature push failed")
        plan = PublicationPlan(
            manifest_id=manifest_id,
            base_branch=base_branch,
            head_branch=branch,
            title=title,
            body=body + f"\nResolved head: {head_sha}\n{comment_signature}\n",
            patch_sha256=head_sha,
            reviewer_id=reviewer_id,
            author_id=author_id,
        )
        client = GitHubHttpClient(api_base, token, timeout=timeout)
        return client.create_pull_request_for(owner, repo, plan, timeout=timeout)
    finally:
        try:
            os.unlink(token_path)
        except OSError:
            pass


def _token_file(directory: Path, token: str) -> Path:
    path = directory / "askpass-token"
    write_private_bytes(path, token.encode("utf-8"))
    return path


def _askpass_helper(directory: Path) -> Path:
    script = directory / "askpass.py"
    body = (
        "import os\n"
        "import pathlib\n"
        "import sys\n"
        "prompt = sys.argv[1] if len(sys.argv) > 1 else ''\n"
        "token = pathlib.Path(os.environ['FCC_ASKPASS_FILE']).read_text(encoding='utf-8').strip()\n"
        "if 'username' in prompt.lower():\n"
        "    print('x-access-token')\n"
        "else:\n"
        "    print(token)\n"
    )
    if os.name == "nt":
        write_private_bytes(script, body.encode("utf-8"))
        launcher = directory / "askpass.cmd"
        write_private_bytes(
            launcher,
            f'@echo off\r\n"{sys.executable}" "%~dp0askpass.py" %*\r\n'.encode("utf-8"),
        )
        return launcher
    write_private_bytes(script, ("#!/usr/bin/env python3\n" + body).encode("utf-8"))
    script.chmod(0o700)
    return script


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2 or args[0] != "--config":
        print('{"ok": false, "error": "disabled", "exit_code": 2}')
        return 2
    raw = json.loads(Path(args[1]).read_text(encoding="utf-8"))
    try:
        url = publish_feature(
            enabled=bool(raw.get("enabled", False)),
            secrets_file=Path(raw["secrets_file"]),
            workspace=Path(raw["workspace"]),
            task_id=str(raw["task_id"]),
            origin=str(raw["origin"]),
            api_base=str(raw["api_base"]),
            owner=str(raw["owner"]),
            repo=str(raw["repo"]),
            base_branch=str(raw["base_branch"]),
            title=str(raw["title"]),
            body=str(raw["body"]),
            head_sha=str(raw["head_sha"]),
            author_id=str(raw["author_id"]),
            reviewer_id=str(raw["reviewer_id"]),
            manifest_id=str(raw["manifest_id"]),
            branch_prefix=str(raw["branch_prefix"]),
            comment_signature=str(raw["comment_signature"]),
            ca_file=Path(raw["ca_file"]) if raw.get("ca_file") else None,
            force=bool(raw.get("force", False)),
            tags=bool(raw.get("tags", False)),
        )
    except (Disabled, Forbidden, MergeRejected) as exc:
        print(json.dumps({"ok": False, "error": exc.code, "exit_code": 2}))
        return 2
    print(json.dumps({"ok": True, "url": url, "exit_code": 0}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
