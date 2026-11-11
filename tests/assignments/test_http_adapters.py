# SPDX-License-Identifier: AGPL-3.0-only
"""Real HTTP and process adapters against local fixtures. No live GitHub or NVIDIA."""

import json
import os
import stat
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from free_claude_code.assignments.cli import main
from free_claude_code.assignments.errors import ApprovalInvalid, Forbidden, MergeRejected
from free_claude_code.assignments.execution import COMMAND_ALLOWLIST_IS_A_SANDBOX
from free_claude_code.assignments.github_http import GitHubHttpClient
from free_claude_code.assignments.grants import ModelGrant, sign_grant, verify_grant
from free_claude_code.assignments.models import IssueSnapshot
from free_claude_code.assignments.secrets import load_secret_file, write_secret_file

PUBLISH = "publish-token-value"
CI_TOKEN = "ci-token-value"
READ = "read-token-value"
PROXY = "proxy-token-value"
GRANT_KEY = "grant-key-value"


class Api(threading.Thread):
    def __init__(self, sha: str) -> None:
        super().__init__(daemon=True)
        self.sha = sha
        self.seen: list[tuple[str, str, str]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                self._record("GET")
                if self.path.endswith("/issues/7"):
                    self._json(
                        {
                            "number": 7,
                            "title": "Fix add",
                            "body": "data only",
                            "state": "open",
                            "updated_at": "2026-11-08T00:00:00Z",
                            "node_id": "NODE1",
                        }
                    )
                    return
                if self.path.endswith("/branches/dev"):
                    self._json({"commit": {"sha": outer.sha}})
                    return
                if "/check-runs" in self.path:
                    self._json(
                        {
                            "check_runs": [
                                {
                                    "id": 9,
                                    "name": "unit",
                                    "status": "completed",
                                    "conclusion": "failure",
                                    "head_sha": outer.sha,
                                }
                            ]
                        }
                    )
                    return
                if self.path.endswith("/actions/jobs/9/logs"):
                    self._text("unit failed on add\n")
                    return
                if "/compare/" in self.path:
                    self._text("diff --git a/src/widget.py b/src/widget.py\n")
                    return
                self.send_error(404)

            def do_POST(self) -> None:  # noqa: N802
                self._record("POST")
                if self.path.endswith("/merge") or "/merges" in self.path:
                    self.send_error(403)
                    return
                if self.path.endswith("/actions/jobs/9/rerun"):
                    self._json({})
                    return
                if self.path.endswith("/pulls"):
                    self._json({"html_url": "http://fixture.local/pull/1"})
                    return
                self.send_error(404)

            def _record(self, method: str) -> None:
                auth = self.headers.get("Authorization", "")
                outer.seen.append((method, self.path, auth))

            def _json(self, payload: dict) -> None:
                raw = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _text(self, text: str) -> None:
                raw = text.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, fmt: str, *args: object) -> None:
                return

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)

    def run(self) -> None:
        self.httpd.serve_forever()

    def start_url(self) -> str:
        self.start()
        host, port = self.httpd.server_address[:2]
        return f"http://{host}:{port}"

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def _origin(tmp: Path) -> str:
    origin = tmp / "origin"
    (origin / "src").mkdir(parents=True)
    (origin / "src" / "widget.py").write_text("def add(left, right):\n    return 0\n", encoding="utf-8")
    (origin / "src" / "test_widget.py").write_text(
        "import unittest\nfrom widget import add\n\n"
        "class T(unittest.TestCase):\n"
        "    def test_add(self):\n"
        "        self.assertEqual(add(1, 1), 2)\n\n"
        "if __name__ == '__main__':\n"
        "    unittest.main()\n",
        encoding="utf-8",
    )
    env = dict(os.environ)
    env.update(
        {
            "GIT_AUTHOR_NAME": "fixture",
            "GIT_AUTHOR_EMAIL": "fixture@localhost",
            "GIT_COMMITTER_NAME": "fixture",
            "GIT_COMMITTER_EMAIL": "fixture@localhost",
        }
    )
    for args in (
        ("init", "-b", "dev"),
        ("add", "src"),
        ("commit", "-m", "failing add"),
    ):
        subprocess.run(("git", *args), cwd=origin, env=env, check=True, capture_output=True)
    return subprocess.check_output(("git", "rev-parse", "HEAD"), cwd=origin, text=True).strip()


def _layout(tmp: Path, sha: str, api: str, claude: Path) -> Path:
    secrets_dir = tmp / "secrets"
    write_secret_file(
        secrets_dir / "secrets",
        {
            "github_read": READ,
            "github_ci": CI_TOKEN,
            "github_publish": PUBLISH,
            "grant_key": GRANT_KEY,
            "proxy_auth": PROXY,
        },
    )
    state = tmp / "state"
    config = tmp / "config.json"
    test_argv = [sys.executable, "-m", "unittest", "test_widget"]
    config.write_text(
        json.dumps(
            {
                "enabled": True,
                "github_api_base": api,
                "secrets_file": str(secrets_dir / "secrets"),
                "state_dir": str(state),
                "proxy_base_url": "http://127.0.0.1:8082",
                "claude_bin": str(claude),
                "source_repo": str(tmp / "origin"),
                "operators": ["author", "reviewer"],
                "allowed_path_prefixes": ["src"],
                "allowed_commands": [test_argv],
                "allowlist": [
                    {
                        "owner": "cwall5640",
                        "repo": "fixture",
                        "issue_number": 7,
                        "base_branch": "dev",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return config


def _claude(tmp: Path) -> Path:
    path = tmp / "fake-claude.py"
    path.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os\n"
        "from pathlib import Path\n"
        "Path('model-env.json').write_text(json.dumps({\n"
        "    'GITHUB_TOKEN': 'GITHUB_TOKEN' in os.environ,\n"
        "    'publish': 'publish-token-value' in os.environ.values(),\n"
        "    'proxy': os.environ.get('ANTHROPIC_AUTH_TOKEN') == 'proxy-token-value',\n"
        "    'bypass': '--dangerously-skip-permissions' in os.sys.argv,\n"
        "}))\n"
        "Path('src/widget.py').write_text('def add(left, right):\\n    return left + right\\n')\n",
        encoding="utf-8",
    )
    path.chmod(0o700)
    return path


def _launch_fixture_claude(config: Path) -> None:
    """Run the fixture with the interpreter. Production argv stays one executable.

    Windows CreateProcess does not run a .py file as argv[0]. This helper is
    test-only. It does not add a claude_args config field.
    """

    from free_claude_code.assignments.cli import (
        _grant_from_file,
        _load_manifest,
        load_operator_file,
    )
    from free_claude_code.assignments.execution import NvidiaClaudeLauncher
    from free_claude_code.assignments.grants import load_revocations
    from free_claude_code.assignments.secrets import load_secret_file

    operator = load_operator_file(config)
    manifest = _load_manifest(operator)
    secrets = load_secret_file(operator.secrets_file)
    grant = _grant_from_file(operator.state_dir / "grants" / f"{manifest.manifest_id}.json")
    # The snapshot the fixture API serves for issue 7; its revision is the
    # one the loaded manifest was approved for.
    issue = IssueSnapshot(
        owner="cwall5640",
        repo="fixture",
        number=7,
        title="Fix add",
        body="data only",
        state="open",
        updated_at="2026-11-08T00:00:00Z",
        node_id="NODE1",
    )
    script = Path(operator.claude_bin)
    launcher = NvidiaClaudeLauncher(str(script), operator.proxy_base_url, secrets.get("proxy_auth"))

    def spawn(argv: tuple[str, ...], env: dict[str, str], cwd: Path) -> None:
        assert argv[0] == str(script)
        assert "--dangerously-skip-permissions" not in argv
        assert "claude_args" not in argv
        subprocess.run(
            [sys.executable, argv[0], *argv[1:]],
            cwd=cwd,
            env=env,
            shell=False,
            check=True,
        )

    launcher.run(
        manifest,
        operator.state_dir / "workspace",
        grant,
        issue=issue,
        grant_key=secrets.get("grant_key"),
        now=10,
        revocations=load_revocations(operator.state_dir / "revocations.txt"),
        spawn=spawn,
    )


def test_allowlist_is_not_a_sandbox() -> None:
    assert COMMAND_ALLOWLIST_IS_A_SANDBOX is False


def test_secret_file_permissions(tmp_path: Path) -> None:
    from free_claude_code.assignments.secrets import posix_mode_is_private
    from free_claude_code.assignments.windows_acl import acl_is_current_user_only

    assert posix_mode_is_private(0o600, directory=False)
    assert not posix_mode_is_private(0o666, directory=False)
    assert acl_is_current_user_only(
        dacl_present=True,
        dacl_protected=True,
        allow_sids=("S-1-5-21-1",),
        other_ace_count=0,
        user_sid="S-1-5-21-1",
    )
    assert not acl_is_current_user_only(
        dacl_present=True,
        dacl_protected=False,
        allow_sids=("S-1-5-21-1",),
        other_ace_count=0,
        user_sid="S-1-5-21-1",
    )
    assert not acl_is_current_user_only(
        dacl_present=True,
        dacl_protected=True,
        allow_sids=("S-1-5-21-1", "S-1-1-0"),
        other_ace_count=0,
        user_sid="S-1-5-21-1",
    )
    path = tmp_path / "vault" / "secrets"
    write_secret_file(path, {"github_read": READ, "grant_key": GRANT_KEY})
    loaded = load_secret_file(path)
    assert loaded.get("github_read") == READ
    assert "redacted" in repr(loaded)
    if os.name == "nt":
        from free_claude_code.assignments.windows_acl import file_is_current_user_only

        assert file_is_current_user_only(path)
        assert file_is_current_user_only(path.parent)
    else:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert path.stat().st_uid == os.getuid()
    loose_dir = tmp_path / "loose"
    loose_dir.mkdir()
    loose = loose_dir / "secrets"
    loose.write_text("github_read=dummy\n", encoding="utf-8")
    if os.name != "nt":
        os.chmod(loose_dir, 0o755)
        os.chmod(loose, 0o644)
    with pytest.raises(Forbidden):
        load_secret_file(loose)
    from tests.assignments.run_windows_secret_tests import attempt_symlink_rejection

    link = path.parent / "link"
    symlink_result = attempt_symlink_rejection(link, path)
    assert symlink_result != "FAILED_LINK_WAS_READ"
    assert symlink_result != "FAILED_POLICY"
    if os.name != "nt":
        assert symlink_result == "VALIDATED"


def test_grant_rejects_stale_and_revoked() -> None:
    from free_claude_code.assignments.models import ModelProvenance, Scope, TaskManifest

    manifest = TaskManifest(
        task_key="cwall5640/fixture#7",
        owner="cwall5640",
        repo="fixture",
        issue_number=7,
        issue_revision="abc",
        title_redacted="t",
        base_branch="dev",
        base_sha="sha",
        scope=Scope(("src",), 1000),
        model=ModelProvenance(),
    )
    grant = sign_grant(
        GRANT_KEY,
        ModelGrant(manifest.manifest_id, "cwall5640/fixture", "sha", "abc", 50, ("implement",), ""),
    )
    verify_grant(GRANT_KEY, grant, manifest, now=10, action="implement", revocations=set())
    with pytest.raises(ApprovalInvalid):
        verify_grant(GRANT_KEY, grant, manifest, now=51, action="implement", revocations=set())
    with pytest.raises(ApprovalInvalid):
        verify_grant(
            GRANT_KEY,
            grant,
            manifest,
            now=10,
            action="implement",
            revocations={manifest.manifest_id},
        )
    tampered = ModelGrant(
        grant.manifest_id,
        grant.repo,
        "different",
        grant.issue_revision,
        grant.expires_at,
        grant.actions,
        grant.signature,
    )
    with pytest.raises(ApprovalInvalid):
        verify_grant(GRANT_KEY, tampered, manifest, now=10, action="implement", revocations=set())


def test_http_client_reads_and_refuses_merge(tmp_path: Path) -> None:
    sha = _origin(tmp_path)
    api = Api(sha)
    try:
        base = api.start_url()
        client = GitHubHttpClient(base, READ, timeout=5)
        issue = client.fetch_issue("cwall5640", "fixture", 7, timeout=5)
        assert isinstance(issue, IssueSnapshot)
        assert client.fetch_branch_sha("cwall5640", "fixture", "dev", timeout=5) == sha
        diff = client.fetch_diff("cwall5640", "fixture", sha, sha, timeout=5)
        assert "widget.py" in diff
        runs = client.fetch_check_runs("cwall5640", "fixture", sha, timeout=5)
        assert runs[0]["name"] == "unit"
        log = client.fetch_job_log("cwall5640", "fixture", 9, timeout=5)
        assert "unit failed" in log
        with pytest.raises(MergeRejected):
            client._bytes("POST", "/repos/cwall5640/fixture/pulls/1/merge", timeout=5, body=b"")
    finally:
        api.stop()


def _run(config: Path, *args: str, capsys: pytest.CaptureFixture[str]) -> dict:
    code = main(["--config", str(config), *args])
    out = capsys.readouterr().out.strip().splitlines()[-1]
    payload = json.loads(out)
    assert code == 0, payload
    assert PUBLISH not in out
    return payload


def test_cli_fail_fix_pass_against_local_api(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    sha = _origin(tmp_path)
    api = Api(sha)
    try:
        base = api.start_url()
        config = _layout(tmp_path, sha, base, _claude(tmp_path))
        fetched = _run(config, "fetch", "--owner", "cwall5640", "--repo", "fixture", "--number", "7", capsys=capsys)
        assert fetched["status"] == "fetched"
        _run(config, "approve", "--phase", "execute", "--operator", "author", capsys=capsys)
        checked = _run(config, "checkout", capsys=capsys)
        assert checked["head_sha"] == sha
        first = _run(config, "test", "--operator", "author", capsys=capsys)
        assert first["local_tests"] == "HOLD"
        assert first["failed"] == 1
        _run(config, "grant", "--operator", "author", "--expires-at", "9999999999", capsys=capsys)
        _launch_fixture_claude(config)
        env_report = json.loads((tmp_path / "state" / "workspace" / "model-env.json").read_text())
        assert env_report["GITHUB_TOKEN"] is False
        assert env_report["publish"] is False
        assert env_report["proxy"] is True
        assert env_report["bypass"] is False
        second = _run(config, "test", "--operator", "author", capsys=capsys)
        assert second["local_tests"] == "PASS"
        assert second["passed"] == 1
        read = _run(config, "ci-read", "--sha", sha, capsys=capsys)
        assert read["action"] == "read"
        assert read["checks"] == 1
        denied = main(["--config", str(config), "ci-rerun", "--job", "9"])
        assert denied == 2
        assert "/rerun" not in {path for _method, path, _auth in api.seen}
        _run(config, "approve", "--phase", "ci_rerun", "--operator", "author", capsys=capsys)
        _run(config, "ci-rerun", "--job", "9", capsys=capsys)
        _run(config, "approve", "--phase", "publish", "--operator", "author", capsys=capsys)
        published = _run(config, "publish", "--reviewer", "reviewer", capsys=capsys)
        assert published["url"] == "http://fixture.local/pull/1"
        methods = {(method, path) for method, path, _auth in api.seen}
        assert ("POST", "/repos/cwall5640/fixture/pulls") in {(m, p.split("?")[0]) for m, p in methods}
        assert not any("merge" in path for _method, path, _auth in api.seen)
        rerun_auth = [auth for method, path, auth in api.seen if path.endswith("/rerun")]
        publish_auth = [auth for method, path, auth in api.seen if path.endswith("/pulls")]
        assert rerun_auth == [f"Bearer {CI_TOKEN}"]
        assert publish_auth == [f"Bearer {PUBLISH}"]
        assert CI_TOKEN != PUBLISH
    finally:
        api.stop()
