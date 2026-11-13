import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from free_claude_code.assignments import live
from free_claude_code.assignments.secrets import SecretFile
from free_claude_code.assignments.errors import Forbidden


def _config(tmp_path: Path, **extra: object) -> Path:
    raw = {
        "allowed_command": ["python", "check.py"],
        "owner": "owner",
        "repo": "game",
        "operator_id": "operator",
        "reviewer_id": "reviewer",
        "audience": "worker",
        "source_repo": str(tmp_path),
        **extra,
    }
    (tmp_path / "runtime.json").write_text(json.dumps(raw), encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize("timeout,expected", [(1800, 1800.0), (60, 60.0), (10, 10.0), (3600, 3600.0), (7200, 7200.0)])
def test_runtime_timeout_reaches_candidate(tmp_path, monkeypatch, timeout, expected):
    config = _config(tmp_path, command_timeout_seconds=timeout)
    monkeypatch.setattr(live, "load_worker_identity", lambda *_: SimpleNamespace(enabled=True))
    monkeypatch.setattr(live, "load_manager_config", lambda *_: [SimpleNamespace(principal_id="manager")])
    monkeypatch.setattr(live, "load_secret_file", lambda *_: SecretFile({"github_read": "test"}))
    monkeypatch.setattr(live, "GitHubHttpClient", lambda *args, **kwargs: None)
    monkeypatch.setattr(live, "_verifier", lambda *args: None)
    monkeypatch.setattr(live, "AssignmentCandidate", lambda **kwargs: SimpleNamespace(**kwargs))
    candidate = live._candidate(tmp_path / "state", config, live._runtime(config))
    assert candidate.command_timeout_seconds == expected


def test_runtime_timeout_default(tmp_path):
    assert live._runtime(_config(tmp_path))["command_timeout_seconds"] == 10.0


@pytest.mark.parametrize(
    "timeout",
    [None, "1800", True, False, 0, 9.9, 7201, -5,
     float("nan"), float("inf"), float("-inf"), [1800], {}],
)
def test_runtime_rejects_malformed_or_out_of_bounds_timeouts(tmp_path, timeout):
    with pytest.raises(Forbidden):
        live._runtime(_config(tmp_path, command_timeout_seconds=timeout))
