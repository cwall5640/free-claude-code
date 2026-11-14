import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from free_claude_code.assignments import live
from free_claude_code.assignments.errors import Forbidden
from free_claude_code.assignments.secrets import SecretFile

# AWAKE-01: AssignmentCandidate.awake_seconds defaulted to 30.0 and
# live._candidate never overrode it, so bounded_awake raised
# "awake window elapsed" on exit for any run over 30s and masked
# run_once's result summary (found in claude1 run #18, 2026-11-11).
# The awake budget is now a runtime config value, wired through
# live.py like command_timeout_seconds, with a default well above
# the longest expected run and bounds that keep the guard meaningful.


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


def _candidate_kwargs(tmp_path, monkeypatch, config):
    monkeypatch.setattr(live, "load_worker_identity", lambda *_: SimpleNamespace(enabled=True))
    monkeypatch.setattr(live, "load_manager_config", lambda *_: [SimpleNamespace(principal_id="manager")])
    monkeypatch.setattr(live, "load_secret_file", lambda *_: SecretFile({"github_read": "test"}))
    monkeypatch.setattr(live, "GitHubHttpClient", lambda *args, **kwargs: None)
    monkeypatch.setattr(live, "_verifier", lambda *args: None)
    monkeypatch.setattr(live, "AssignmentCandidate", lambda **kwargs: SimpleNamespace(**kwargs))
    return live._candidate(tmp_path / "state", config, live._runtime(config))


def test_awake_default_is_above_the_longest_expected_run(tmp_path):
    awake = live._runtime(_config(tmp_path))["awake_seconds"]
    assert awake == live.AWAKE_SECONDS_DEFAULT
    # The check stage alone may run 10800s (TIMEOUT-02 cap); a whole run must fit.
    assert awake > 10800.0


def test_awake_default_reaches_candidate(tmp_path, monkeypatch):
    candidate = _candidate_kwargs(tmp_path, monkeypatch, _config(tmp_path))
    assert candidate.awake_seconds == live.AWAKE_SECONDS_DEFAULT


@pytest.mark.parametrize("value,expected", [(5400, 5400.0), (60, 60.0), (14400, 14400.0)])
def test_awake_value_reaches_candidate(tmp_path, monkeypatch, value, expected):
    candidate = _candidate_kwargs(tmp_path, monkeypatch, _config(tmp_path, awake_seconds=value))
    assert candidate.awake_seconds == expected


@pytest.mark.parametrize(
    "value",
    [None, "7200", True, False, 0, 30, 59.9, 14401, -5,
     float("nan"), float("inf"), float("-inf"), [7200], {}],
)
def test_runtime_rejects_malformed_or_out_of_bounds_awake(tmp_path, value):
    with pytest.raises(Forbidden):
        live._runtime(_config(tmp_path, awake_seconds=value))
