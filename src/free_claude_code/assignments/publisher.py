# SPDX-License-Identifier: AGPL-3.0-only
"""Separate publisher process. Disabled until a caller sets enabled.

The publish token is read from the private secret file inside this process.
Git receives it through GIT_ASKPASS, not through argv. Model and test
environments never import this module's token.
"""

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

from free_claude_code.assignments.errors import Disabled, Forbidden, MergeRejected
from free_claude_code.assignments.execution import scrub_env
from free_claude_code.assignments.github_http import GitHubHttpClient
from free_claude_code.assignments.models import PublicationPlan
from free_claude_code.assignments.secrets import load_secret_file, refuse_symlink_or_reparse

ACTOR_BRANCH_PREFIX = "claude1/"


def feature_branch(task_id: str) -> str:
    lowered = task_id.strip().lower()
    if not lowered or lowered != task_id.lower() or "/" in lowered or lowered.startswith("-"):
        raise Forbidden("task id must be a lowercase slug")
    if lowered in {"main", "master"}:
        raise MergeRejected("refusing a protected branch")
    return f"{ACTOR_BRANCH_PREFIX}{lowered}"


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
    timeout: float = 10.0,
    force: bool = False,
    tags: bool = False,
    ca_file: Path | None = None,
) -> str:
    """Push one feature branch and open a pull request. Merge is not available."""

    if not enabled:
        raise Disabled("publisher is disabled")
    branch = feature_branch(task_id)
    refuse_push_ref(f"refs/heads/{branch}", force=force, tags=tags)
    if not origin.startswith("https://"):
        raise Forbidden("publisher origin must be one configured https url")
    token = load_secret_file(secrets_file).get("github_publish")
    askpass = _askpass_helper(secrets_file.parent)
    env = scrub_env(os.environ)
    env.update(
        {
            "GIT_ASKPASS": str(askpass),
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "FCC_ASKPASS_FILE": str(_token_file(secrets_file.parent, token)),
        }
    )
    if ca_file is not None:
        env["GIT_SSL_CAINFO"] = str(ca_file)
    if token in " ".join(env.get("GIT_ASKPASS", "")):
        raise Forbidden("publish token must not be placed on argv")
    command = (
        "git",
        "-c",
        "credential.helper=",
        "-c",
        "http.sslVerify=true",
        "push",
        origin,
        f"HEAD:refs/heads/{branch}",
    )
    if any(part in {"--force", "--force-with-lease", "-f"} for part in command):
        raise MergeRejected("force pushes and tags are refused")
    if token in origin or token in " ".join(command):
        raise Forbidden("publish token must not be placed on argv")
    completed = subprocess.run(
        command,
        cwd=workspace,
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
        body=body + f"\nResolved head: {head_sha}\n— dev:claude1\n",
        patch_sha256=head_sha,
        reviewer_id=reviewer_id,
        author_id=author_id,
    )
    client = GitHubHttpClient(api_base, token, timeout=timeout)
    return client.create_pull_request_for(owner, repo, plan, timeout=timeout)


def _token_file(directory: Path, token: str) -> Path:
    path = directory / "askpass-token"
    refuse_symlink_or_reparse(is_symlink=path.is_symlink(), reparse=False)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, token.encode("utf-8"))
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)
    return path


def _askpass_helper(directory: Path) -> Path:
    path = directory / "askpass.py"
    path.write_text(
        "#!/usr/bin/env python3\n"
        "import os\n"
        "import pathlib\n"
        "import sys\n"
        "prompt = sys.argv[1] if len(sys.argv) > 1 else ''\n"
        "token = pathlib.Path(os.environ['FCC_ASKPASS_FILE']).read_text(encoding='utf-8').strip()\n"
        "if 'username' in prompt.lower():\n"
        "    print('x-access-token')\n"
        "else:\n"
        "    print(token)\n",
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


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
