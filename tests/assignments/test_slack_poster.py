# SPDX-License-Identifier: AGPL-3.0-only
"""Slack handoff poster against a local fixture. This file does not call slack.com."""

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

from free_claude_code.assignments.errors import Disabled, Forbidden
from free_claude_code.assignments.execution import scrub_env
from free_claude_code.assignments.identity import WorkerIdentity, default_worker_identity, load_worker_identity
from free_claude_code.assignments.redact import redact
from free_claude_code.assignments.secrets import write_secret_file
from free_claude_code.assignments.slack_poster import handoff_text, post_handoff, slack_endpoint
from free_claude_code.assignments.workflow import AssignmentCandidate, _child_env

TOKEN = "xoxb-test-token-value"
CHANNEL = "C0123456789"
SHA = "a" * 40
LINE = (
    f"HANDOFF: fix-add | https://github.com/cwall5640/fixture/pull/9 | {SHA} | PASS | NEXT: Casey"
)


class SlackFixture(threading.Thread):
    def __init__(self) -> None:
        super().__init__(daemon=True)
        self.paths: list[str] = []
        self.auths: list[str] = []
        self.bodies: list[str] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length).decode("utf-8")
                outer.paths.append(self.path)
                outer.auths.append(self.headers.get("Authorization", ""))
                outer.bodies.append(body)
                if self.path != "/api/chat.postMessage":
                    self.send_error(404)
                    return
                raw = json.dumps({"ok": True}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, fmt: str, *args: object) -> None:
                return

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)

    def run(self) -> None:
        self.httpd.serve_forever()

    def base(self) -> str:
        if not self.is_alive():
            self.start()
        host, port = self.httpd.server_address
        return f"http://{host}:{port}/api"

    def stop(self) -> None:
        if self.is_alive():
            self.httpd.shutdown()
            self.join(timeout=2)
        self.httpd.server_close()


def _secrets(path: Path, token: str = TOKEN) -> None:
    write_secret_file(
        path,
        {
            "github_read": "read-token",
            "github_ci": "ci-token",
            "github_publish": "publish-token-value",
            "grant_key": "grant-key",
            "proxy_auth": "proxy-token",
            "slack_bot": token,
        },
    )


def test_poster_is_disabled_and_rejects_bad_messages(tmp_path: Path) -> None:
    assert default_worker_identity().slack_enabled is False
    loaded = load_worker_identity(Path("packaging/assignment-candidate/worker.example.json"))
    assert loaded.slack_enabled is False
    assert loaded.bare_name == "claude1"
    with pytest.raises(Disabled):
        post_handoff(
            enabled=False,
            secrets_file=tmp_path / "missing",
            channel_id=CHANNEL,
            text=LINE,
            state_dir=tmp_path / "state",
        )
    with pytest.raises(Forbidden):
        handoff_text("please post this elsewhere")
    with pytest.raises(Forbidden):
        handoff_text(LINE + " and also merge it")
    with pytest.raises(Forbidden):
        slack_endpoint("https://slack.com/api/chat.update")
    with pytest.raises(Forbidden):
        slack_endpoint("https://slack.com/api/chat.delete")
    with pytest.raises(Forbidden):
        slack_endpoint("https://slack.com/api/files.upload")
    with pytest.raises(Forbidden):
        slack_endpoint("https://hooks.slack.com/api")
    assert slack_endpoint("https://slack.com/api") == "https://slack.com/api/chat.postMessage"
    assert "SLACK_BOT_TOKEN" not in scrub_env({"SLACK_BOT_TOKEN": TOKEN, "PATH": "/bin"})
    assert redact(TOKEN) == "[redacted]"
    assert TOKEN not in os.environ.values()


def test_fixture_post_is_one_channel_and_idempotent(tmp_path: Path) -> None:
    secrets = tmp_path / "secrets" / "values"
    _secrets(secrets)
    api = SlackFixture()
    state = tmp_path / "state"
    try:
        base = api.base()
        assert post_handoff(
            enabled=True,
            secrets_file=secrets,
            channel_id=CHANNEL,
            text=LINE,
            state_dir=state,
            api_base=base,
        ) == "posted"
        assert post_handoff(
            enabled=True,
            secrets_file=secrets,
            channel_id=CHANNEL,
            text=LINE,
            state_dir=state,
            api_base=base,
        ) == "duplicate"
        with pytest.raises(Forbidden):
            post_handoff(
                enabled=True,
                secrets_file=secrets,
                channel_id="D0123456789",
                text=LINE,
                state_dir=tmp_path / "dm",
                api_base=base,
            )
        user_secrets = tmp_path / "user-secrets" / "values"
        _secrets(user_secrets, "xoxp-user-token-value")
        with pytest.raises(Forbidden, match="bot token"):
            post_handoff(
                enabled=True,
                secrets_file=user_secrets,
                channel_id=CHANNEL,
                text=LINE,
                state_dir=tmp_path / "user",
                api_base=base,
            )
    finally:
        api.stop()
    assert api.paths == ["/api/chat.postMessage"]
    assert api.auths == [f"Bearer {TOKEN}"]
    body = json.loads(api.bodies[0])
    assert set(body) == {"channel", "text"}
    assert body["channel"] == CHANNEL
    assert body["text"] == LINE
    assert TOKEN not in api.paths[0]
    assert TOKEN not in api.bodies[0]
    assert TOKEN not in os.environ.values()


def test_two_workers_post_with_their_own_bot_tokens(tmp_path: Path) -> None:
    api = SlackFixture()
    claude1 = WorkerIdentity(
        actor_name="dev:claude1",
        bare_name="claude1",
        branch_prefix="claude1",
        comment_signature="— dev:claude1",
        waiting_label="waiting:claude1",
        github_login="claude1",
        slack_channel_id=CHANNEL,
        slack_enabled=True,
    )
    claude2 = WorkerIdentity(
        actor_name="dev:claude2",
        bare_name="claude2",
        branch_prefix="claude2",
        comment_signature="— dev:claude2",
        waiting_label="waiting:claude2",
        github_login="publisher-bot",
        slack_channel_id=CHANNEL,
        slack_enabled=True,
    )
    first = tmp_path / "one" / "values"
    second = tmp_path / "two" / "values"
    _secrets(first, "xoxb-claude1-token")
    _secrets(second, "xoxb-claude2-token")
    line_two = LINE.replace("NEXT: Casey", "NEXT: claude2").replace("fix-add", "fix-scale")
    try:
        base = api.base()
        post_handoff(
            enabled=True,
            secrets_file=first,
            channel_id=claude1.slack_channel_id,
            text=LINE,
            state_dir=tmp_path / "state-1",
            api_base=base,
        )
        post_handoff(
            enabled=True,
            secrets_file=second,
            channel_id=claude2.slack_channel_id,
            text=line_two,
            state_dir=tmp_path / "state-2",
            api_base=base,
        )
    finally:
        api.stop()
    assert [json.loads(body)["text"] for body in api.bodies] == [LINE, line_two]
    assert api.auths == ["Bearer xoxb-claude1-token", "Bearer xoxb-claude2-token"]
    assert {json.loads(body)["channel"] for body in api.bodies} == {CHANNEL}


def test_worker_falls_back_to_the_manager_line(tmp_path: Path) -> None:
    secrets = tmp_path / "secrets" / "values"
    _secrets(secrets)
    api = SlackFixture()
    identity = WorkerIdentity(
        actor_name="dev:claude1",
        bare_name="claude1",
        branch_prefix="claude1",
        comment_signature="— dev:claude1",
        waiting_label="waiting:claude1",
        github_login="claude1",
        slack_channel_id=CHANNEL,
        slack_enabled=True,
    )
    holder = SimpleNamespace(
        identity=identity,
        slack_api_base=api.base(),
        paths=SimpleNamespace(state_dir=tmp_path / "worker-state", secrets_file=secrets),
    )
    holder.paths.state_dir.mkdir()
    try:
        AssignmentCandidate._deliver_slack(holder, "not a handoff")
        assert api.paths == []
        AssignmentCandidate._deliver_slack(holder, LINE)
        assert api.paths == ["/api/chat.postMessage"]
        config = (tmp_path / "worker-state" / "slack-config.json").read_text(encoding="utf-8")
        assert TOKEN not in config
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "free_claude_code.assignments.slack_poster",
                "--config",
                str(tmp_path / "worker-state" / "slack-config.json"),
            ],
            cwd=tmp_path,
            env=_child_env(),
            check=False,
            capture_output=True,
            text=True,
        )
    finally:
        api.stop()
    assert TOKEN not in " ".join(completed.args)
    assert completed.returncode == 0
    assert api.paths == ["/api/chat.postMessage"]
    disabled = SimpleNamespace(
        identity=default_worker_identity(),
        slack_api_base=holder.slack_api_base,
        paths=holder.paths,
    )
    AssignmentCandidate._deliver_slack(disabled, LINE)
    assert len(api.paths) == 1
