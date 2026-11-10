import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from free_claude_code.assignments import live
from free_claude_code.assignments.errors import Forbidden
from free_claude_code.assignments.secrets import SecretFile


def _worker_file(config_dir: Path, runtime: dict[str, object]) -> Path:
    config_dir.mkdir(parents=True, exist_ok=True)
    (config_dir / "worker.json").write_text("{}", encoding="utf-8")
    (config_dir / "runtime.json").write_text(json.dumps(runtime), encoding="utf-8")
    return config_dir


def _runtime_dict(**overrides: object) -> dict[str, object]:
    runtime: dict[str, object] = {
        "owner": "owner",
        "repo": "game",
        "operator_id": "operator",
        "reviewer_id": "reviewer",
        "allowed_command": ["python", "check.py"],
    }
    runtime.update(overrides)
    return runtime


def test_setup_command_defaults_to_none(tmp_path):
    result = live._runtime(_worker_file(tmp_path / "cfg", _runtime_dict()))
    assert result["setup_command"] is None


def test_setup_command_parsed_when_present(tmp_path):
    result = live._runtime(
        _worker_file(tmp_path / "cfg", _runtime_dict(setup_command=["npm.cmd", "ci"]))
    )
    assert result["setup_command"] == ("npm.cmd", "ci")


@pytest.mark.parametrize(
    "bad",
    [
        "npm ci",
        [],
        ["npm", ""],
        ["npm", 3],
        42,
        None,
    ],
)
def test_setup_command_malformed_fails_closed(tmp_path, bad):
    with pytest.raises(Forbidden):
        live._runtime(_worker_file(tmp_path / "cfg", _runtime_dict(setup_command=bad)))


def _patch_live(monkeypatch):
    monkeypatch.setattr(live, "load_worker_identity", lambda *_: SimpleNamespace(enabled=True))
    monkeypatch.setattr(
        live, "load_manager_config", lambda *_: [SimpleNamespace(principal_id="manager")]
    )
    monkeypatch.setattr(
        live, "load_secret_file", lambda *_: SecretFile({"github_read": "test"})
    )
    monkeypatch.setattr(live, "GitHubHttpClient", lambda *args, **kwargs: None)
    monkeypatch.setattr(live, "_verifier", lambda *args: None)


def _runtime_for_candidate(tmp_path: Path, **overrides: object) -> dict[str, object]:
    source = tmp_path / "source"
    source.mkdir(exist_ok=True)
    runtime: dict[str, object] = {
        "managers_file": "managers.json",
        "secrets_file": "secrets",
        "source_repo": str(source),
        "audience": "worker",
        "owner": "owner",
        "repo": "game",
        "github_api_base": "https://api.github.test",
        "operator_id": "operator",
        "reviewer_id": "reviewer",
        "allowed_command": ("python", "check.py"),
        "command_cwd": "src",
        "allowed_path_prefixes": ("src",),
        "command_timeout_seconds": 10.0,
        "publish_origin": "",
        "ca_file": "",
        "setup_command": None,
        "grants_dir": None,
    }
    runtime.update(overrides)
    return runtime


def test_setup_command_reaches_candidate(tmp_path, monkeypatch):
    captured: dict[str, object] = {}

    def capture(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(**kwargs)

    _patch_live(monkeypatch)
    monkeypatch.setattr(live, "AssignmentCandidate", capture)
    live._candidate(
        tmp_path / "state",
        tmp_path,
        _runtime_for_candidate(tmp_path, setup_command=("npm.cmd", "ci")),
    )
    assert captured["setup_command"] == ("npm.cmd", "ci")


def test_setup_command_absent_reaches_candidate_as_none(tmp_path, monkeypatch):
    captured: dict[str, object] = {}

    def capture(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(**kwargs)

    _patch_live(monkeypatch)
    monkeypatch.setattr(live, "AssignmentCandidate", capture)
    live._candidate(tmp_path / "state", tmp_path, _runtime_for_candidate(tmp_path))
    assert captured["setup_command"] is None


def test_scope_fingerprint_binds_the_setup_command():
    from free_claude_code.assignments.models import Scope

    base = Scope(("src",), 1_000)
    with_setup = Scope(("src",), 1_000, ("npm.cmd", "ci"))
    other_setup = Scope(("src",), 1_000, ("npm.cmd", "install"))
    assert base.fingerprint() != with_setup.fingerprint()
    assert with_setup.fingerprint() != other_setup.fingerprint()


def test_service_manifest_carries_the_configured_setup(tmp_path):
    from free_claude_code.assignments.models import (
        AllowlistEntry,
        AssignmentConfig,
        IssueSnapshot,
    )
    from free_claude_code.assignments.service import AssignmentService
    from free_claude_code.assignments.store import StateStore

    issue = IssueSnapshot(
        owner="o",
        repo="r",
        number=7,
        title="t",
        body="b",
        state="open",
        updated_at="2026-01-01T00:00:00Z",
        node_id="NODE7",
    )
    entry = AllowlistEntry("o", "r", 7, "main")
    plain = AssignmentService(
        AssignmentConfig(enabled=True, operators=("op",)), StateStore(tmp_path / "a")
    )._manifest(issue, entry, "base")
    bound = AssignmentService(
        AssignmentConfig(
            enabled=True, operators=("op",), setup_command=("npm.cmd", "ci")
        ),
        StateStore(tmp_path / "b"),
    )._manifest(issue, entry, "base")
    assert plain.scope.setup_command == ()
    assert bound.scope.setup_command == ("npm.cmd", "ci")
    assert plain.manifest_id != bound.manifest_id
