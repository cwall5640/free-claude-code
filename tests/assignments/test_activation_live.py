# SPDX-License-Identifier: AGPL-3.0-only
"""Live switch against a fake GitHub. Slack stays off unless the identity says so."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from free_claude_code.assignments.activation import activate, is_activated
from free_claude_code.assignments.candidate import main as candidate_main
from free_claude_code.assignments.errors import MergeRejected
from free_claude_code.assignments.publisher import refuse_push_ref
from free_claude_code.assignments.secrets import write_secret_file
from tests.assignments.test_automatic_workflow import (
    PINNED_ORIGIN,
    PUBLISH,
    VIBE_PUBLIC,
    FixtureApi,
    GitHttps,
    _attestation,
    _origin,
    _ok_script,
    _posted_texts,
    _redirect_pinned_push,
    _write_inbox,
)

pytest.importorskip("cryptography")


def test_activate_records_the_approver_and_deactivate_flips_it(tmp_path: Path) -> None:
    root = tmp_path / "state"
    assert candidate_main(["activate", "--root", str(root)]) == 2
    assert candidate_main(["run-once", "--root", str(root), "--config", str(tmp_path / "config")]) == 2
    assert is_activated(root) is False
    assert candidate_main(
        ["activate", "--root", str(root), "--approved-by", "Casey", "--approval-reference", "casey-activation"]
    ) == 0
    record = json.loads((root / "activation-rollback.json").read_text(encoding="utf-8"))
    assert record["executed"] is True
    assert record["approved_by"] == "Casey"
    assert record["approval_reference"] == "casey-activation"
    assert record["approved_at"]
    assert candidate_main(["deactivate", "--root", str(root), "--approved-by", "Casey"]) == 0
    assert is_activated(root) is False
    again = json.loads((root / "activation-rollback.json").read_text(encoding="utf-8"))
    assert again["deactivated_by"] == "Casey"


def test_disabled_logon_does_not_call_github(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("proxy started while disabled")

    monkeypatch.setattr("free_claude_code.assignments.live.ensure_fcc_proxy", boom)
    config = tmp_path / "config"
    config.mkdir()
    (config / "worker.json").write_text(json.dumps(_worker(enabled=False)), encoding="utf-8")
    state = tmp_path / "state"
    assert candidate_main(["logon", "--root", str(state), "--config", str(config)]) == 0
    assert "logon idle" in (state / "logon.log").read_text(encoding="utf-8")
    assert candidate_main(["run-once", "--root", str(state), "--config", str(config)]) == 2


def test_enabled_loop_publishes_without_slack_or_merge(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(MergeRejected):
        refuse_push_ref("refs/heads/main")
    monkeypatch.setattr("free_claude_code.assignments.live.ensure_fcc_proxy", lambda **_kwargs: "healthy")
    commands: list[object] = []
    real_run = subprocess.run

    def record(command, **kwargs):
        commands.append(command)
        return real_run(command, **kwargs)

    monkeypatch.setattr(subprocess, "run", record)
    origin, sha = _origin(tmp_path)
    api = FixtureApi(sha)
    api.has_pull = False
    git_remote = GitHttps(tmp_path / "git-remote", PUBLISH)
    config = tmp_path / "config"
    state = tmp_path / "run" / "state"
    try:
        _arm(config, state, api, sha, git_remote, origin, tmp_path)
        with _redirect_pinned_push(git_remote):
            code = candidate_main(["run-once", "--root", str(state), "--config", str(config)])
        assert code == 0
        assert any(path.endswith("/pulls") for path, _auth in api.posts)
        posted = _posted_texts(api)
        assert any(body.rstrip().endswith("— dev:claude1") for body in posted)
        assert any("NEXT:" in body for body in posted)
        assert all("slack_poster" not in " ".join(map(str, command)) for command in commands)
        with pytest.raises(MergeRejected):
            refuse_push_ref("refs/heads/main", force=True)
        with _redirect_pinned_push(git_remote):
            replay = candidate_main(["run-once", "--root", str(state), "--config", str(config)])
        assert replay == 2
        assert "fail closed" in (state / "logon.log").read_text(encoding="utf-8")
    finally:
        api.stop()
        git_remote.stop()


def test_bad_signature_and_wrong_label_do_not_publish(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("free_claude_code.assignments.live.ensure_fcc_proxy", lambda **_kwargs: "healthy")
    origin, sha = _origin(tmp_path)
    api = FixtureApi(sha)
    api.has_pull = False
    config = tmp_path / "config"
    state = tmp_path / "run" / "state"
    try:
        _arm(config, state, api, sha, None, origin, tmp_path, publish=False)
        inbox = state / "inbox" / "9.json"
        raw = json.loads(inbox.read_text(encoding="utf-8"))
        raw["signature"] = "0" * 128
        inbox.write_text(json.dumps(raw), encoding="utf-8")
        assert candidate_main(["run-once", "--root", str(state), "--config", str(config)]) == 2
        assert not any(path.endswith("/pulls") for path, _auth in api.posts)
        api.labels = ["waiting:casey"]
        _write_inbox(state / "inbox", _attestation(sha, expires=2_000_000_000, nonce="label"))
        assert candidate_main(["run-once", "--root", str(state), "--config", str(config)]) == 0
        assert not any(path.endswith("/pulls") for path, _auth in api.posts)
    finally:
        api.stop()


def test_kill_switch_stops_before_github(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(**_kwargs: object) -> str:
        raise AssertionError("proxy started after the kill switch")

    monkeypatch.setattr("free_claude_code.assignments.live.ensure_fcc_proxy", boom)
    config = tmp_path / "config"
    state = tmp_path / "state"
    config.mkdir()
    state.mkdir()
    (config / "worker.json").write_text(json.dumps(_worker(enabled=True)), encoding="utf-8")
    activate(state, "Casey", "casey-activation")
    (state / "KILL").write_text("stop\n", encoding="utf-8")
    assert candidate_main(["run-once", "--root", str(state), "--config", str(config)]) == 0
    assert "kill switch" in (state / "logon.log").read_text(encoding="utf-8")


def _worker(*, enabled: bool) -> dict[str, object]:
    return {
        "actor_name": "dev:claude1",
        "bare_name": "claude1",
        "branch_prefix": "claude1",
        "comment_signature": "— dev:claude1",
        "waiting_label": "waiting:claude1",
        "github_login": "claude1",
        "enabled": enabled,
        "slack_enabled": False,
        "slack_channel_id": "",
        "fcc_launcher": "",
    }


def _arm(
    config: Path,
    state: Path,
    api: FixtureApi,
    sha: str,
    git_remote: GitHttps | None,
    origin: Path,
    tmp: Path,
    *,
    publish: bool = True,
) -> None:
    config.mkdir(parents=True, exist_ok=True)
    os.chmod(config, 0o700)
    state.mkdir(parents=True, exist_ok=True)
    for name in ("power", "session", "network"):
        (state / name).write_text("1\n", encoding="utf-8")
    (config / "worker.json").write_text(json.dumps(_worker(enabled=True)), encoding="utf-8")
    (config / "managers.json").write_text(
        json.dumps(
            {
                "managers": [
                    {
                        "principal_id": "vibe-1",
                        "role": "vibe",
                        "display_name": "Vibe Coder",
                        "github_login": "VibeCoder",
                        "handoff_actor": "Casey",
                        "public_key_hex": VIBE_PUBLIC.hex(),
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    write_secret_file(
        config / "secrets",
        {
            "github_read": "read-token",
            "github_ci": "ci-token",
            "github_publish": PUBLISH,
            "grant_key": "grant-key",
            "proxy_auth": "proxy-token",
        },
    )
    runtime = {
        "allowed_command": [sys.executable, str(_ok_script(tmp))],
        "audience": "worker-1",
        "command_cwd": "src",
        "github_api_base": api.start_url(),
        "managers_file": "managers.json",
        "operator_id": "operator",
        "owner": "cwall5640",
        "poll_interval_seconds": 0,
        "poll_limit": 1,
        "repo": "fixture",
        "reviewer_id": "reviewer",
        "secrets_file": "secrets",
        "source_repo": str(origin),
    }
    if publish and git_remote is not None:
        runtime["publish_origin"] = PINNED_ORIGIN
        runtime["ca_file"] = str(git_remote.cert)
        git_remote.origin()
    (config / "runtime.json").write_text(json.dumps(runtime), encoding="utf-8")
    activate(state, "Casey", "casey-activation")
    _write_inbox(state / "inbox", _attestation(sha, expires=2_000_000_000))
